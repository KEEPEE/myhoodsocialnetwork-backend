//! Integrné testy B5 (MYHSN-7): **skutočný server na ephemeral porti** a
//! skutoční WS klienti (tokio-tungstenite), framing z `core::wire` (D-24).
//!
//! Kritériá zo zadania, každé má svoj test:
//! - (a) klient A appendne post → klient B dostane push do 2 s,
//! - (b) B offline, A appendne záznamy, B sa pripojí s watermarkom →
//!   dostane **presne chýbajúce** (range dobehnutie, D-29),
//! - (c) duplicitný append rovnakého hashu → idempotentný `Ack` bez
//!   duplikátu,
//! - (d) `Hello` so zlou verziou → `Reject` s kódom,
//! - (e) naväzujúce na B4: podpis **revokovaným** device kľúčom sa pri
//!   append odmietne (`Reject` s kódom), neznámy kľúč taktiež.

use futures::{SinkExt, StreamExt};
use myhsn_core::channel::ChannelKind;
use myhsn_core::identity::{public_from_seed, DevicePublicKey};
use myhsn_core::record::{Envelope, NodeStamp, Payload};
use myhsn_core::seq::ChannelId;
use myhsn_core::storage::RecordStore;
use myhsn_core::wire::{
    self, Ack, Hello, HelloWatermark, MsgType, Header, REJECT_RECORD, REJECT_VERSION,
    WIRE_VERSION,
};
use node::api::SharedStore;
use node::store::Store;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

/// Push musí prísť do 2 s (kritérium a) — s rezervou pre CI.
const RECV_TIMEOUT: Duration = Duration::from_secs(2);

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Spustí skutočný axum server (`node::build_router`) na ephemeral port.
async fn spawn_server() -> (SocketAddr, SharedStore) {
    let store: SharedStore = Arc::new(Mutex::new(Store::open_in_memory().unwrap()));
    // WS test médiá nepoužíva — adresár je len povinný parameter build_router.
    let media_rt = node::media::MediaRuntime::with_dir(std::env::temp_dir().join("myhsn-ws-test-media"));
    let app = node::build_router(store.clone(), media_rt);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, store)
}

/// Fiktívny PHC retestec — WS cesta heslo neoveruje (autituje podpis v
/// obálke, D-26), takže Argon2 v príprave testu netreba platiť.
const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2ExMg$c2lnbmlnLXNpZ25pZ2wtc2lnbmlnbC1zaWduaWdsLXNpZ25pZ2w";

/// Pripraví kanál + účet so zariadeniami (seed → verejný kľúč) priamo v
/// úložni; REST vrstvu kryjú unit testy v `api.rs`.
fn setup(
    store: &SharedStore,
    username: &str,
    seeds: &[&[u8; 32]],
) -> (ChannelId, Vec<i64>) {
    let mut s = store.lock().unwrap_or_else(|p| p.into_inner());
    let ch = s.create_channel("nastienka", ChannelKind::Wall).unwrap();
    let acc = s.create_account(username, DUMMY_PHC, 1_000).unwrap();
    let mut device_ids = Vec::new();
    for (i, seed) in seeds.iter().enumerate() {
        let dk = s
            .attest_device_key(
                &acc.id,
                &DevicePublicKey::from_seed(seed),
                &format!("zariadenie-{i}"),
                1_000,
            )
            .unwrap();
        device_ids.push(dk.id);
    }
    (ch.id, device_ids)
}

/// Obálka tak, ako ju posiela klient: poradie nepozná (epocha/seq 0,
/// `stamp_sig = None`), uzol doplní a podpíše (D-25).
fn client_envelope(author_seed: &[u8; 32], channel: ChannelId, text: &str) -> Vec<u8> {
    Envelope::build(
        author_seed,
        &Payload::Post {
            text: text.to_string(),
            media_ref: None,
        },
        NodeStamp::new(channel, 0, 0, [0u8; 32]),
        b"",
        None,
    )
    .encode()
}

/// Jeden WS klient: split na sink/stream + asistované čítanie frame.
struct Client {
    sink: futures::stream::SplitSink<WsStream, Message>,
    stream: futures::stream::SplitStream<WsStream>,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Self {
        let (ws, _resp) = connect_async(format!("ws://{addr}/ws")).await.unwrap();
        let (sink, stream) = ws.split();
        Self { sink, stream }
    }

    async fn send(&mut self, msg_type: MsgType, payload: &[u8]) {
        let header = Header {
            version: WIRE_VERSION,
            msg_type: msg_type as u8,
            channel: 0,
            len: payload.len() as u32,
        };
        self.sink
            .send(Message::Binary(wire::encode_frame(&header, payload).into()))
            .await
            .unwrap();
    }

    /// Ďalší frame s timeoutom; protocol-level Ping/Pong preskočí.
    async fn frame(&mut self) -> (u8, Vec<u8>) {
        loop {
            let msg = tokio::time::timeout(RECV_TIMEOUT, self.stream.next())
                .await
                .expect("timeout: sprava nedosla v casovom okne")
                .expect("stream sa zavrel predcasne")
                .expect("chyba WebSocket");
            match msg {
                Message::Binary(bytes) => {
                    let (hdr, payload) = wire::decode_frame(&bytes).expect("platny frame");
                    return (hdr.msg_type, payload.to_vec());
                }
                Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                other => panic!("neocekavana sprava: {other:?}"),
            }
        }
    }

    /// Pošle `Hello` a vráti `HelloAck` (verzia, caps, epochy).
    async fn hello(&mut self, watermarks: Vec<HelloWatermark>) -> myhsn_core::wire::HelloAck {
        self.send(
            MsgType::Hello,
            &wire::encode_hello(&Hello {
                proto_min: 0,
                proto_max: 0,
                caps: vec!["sync".to_string()],
                watermarks,
                session: None,
            }),
        )
        .await;
        let (msg_type, payload) = self.frame().await;
        assert_eq!(msg_type, MsgType::HelloAck as u8, "na Hello cakame HelloAck");
        wire::decode_hello_ack(&payload).unwrap()
    }

    /// Počúva na `Ack` (vlastné push Record správy medzitým preskočí —
    /// uzol pushuje aj odosielateľovi, D-29 to ruší idempotenciou).
    async fn expect_ack(&mut self) -> Ack {
        loop {
            let (msg_type, payload) = self.frame().await;
            match MsgType::from_u8(msg_type) {
                Some(MsgType::Record) => continue,
                Some(MsgType::Ack) => return wire::decode_ack(&payload).unwrap(),
                other => panic!("cakany Ack, prisiel typ {other:?}"),
            }
        }
    }

    /// Počúva na `Record` push (Ack vlastného appendu preskočí).
    async fn expect_record(&mut self) -> Envelope {
        loop {
            let (msg_type, payload) = self.frame().await;
            match MsgType::from_u8(msg_type) {
                Some(MsgType::Ack) => continue,
                Some(MsgType::Record) => {
                    return Envelope::decode(&payload).expect("pushnuta obalka ide dekódovať")
                }
                other => panic!("cakany Record, prisiel typ {other:?}"),
            }
        }
    }

    /// Počúva na `Reject` a vráti jeho kód.
    async fn expect_reject(&mut self) -> u16 {
        loop {
            let (msg_type, payload) = self.frame().await;
            match MsgType::from_u8(msg_type) {
                Some(MsgType::Ack) | Some(MsgType::Record) => continue,
                Some(MsgType::Reject) => {
                    return wire::decode_reject(&payload).unwrap().code
                }
                other => panic!("cakany Reject, prisiel typ {other:?}"),
            }
        }
    }

    /// Žiadna ďalšia správa nesmie prísť (test „presne toľko, koľko má“).
    async fn expect_quiet(&mut self) {
        let extra = tokio::time::timeout(RECV_TIMEOUT, self.stream.next()).await;
        match extra {
            Err(_) => {} // timeout = ticho, čo očakávame
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => {}
            Ok(other) => panic!("cakane ticho, prislo: {other:?}"),
        }
    }
}

/// **(a)** klient A appendne post → klient B dostane push do 2 s a obaja
/// sa pozerajú na ten istý finálny hash + poradie uzla.
#[tokio::test]
async fn a_appends_b_gets_push_within_2s() {
    let (addr, store) = spawn_server().await;
    let seed_a = [0xa1u8; 32];
    let (channel, _devices) = setup(&store, "klient-a", &[&seed_a]);

    let mut a = Client::connect(addr).await;
    let ack_info = a.hello(vec![]).await;
    assert_eq!(ack_info.version, myhsn_core::PROTO_VERSION);
    assert!(ack_info.caps.iter().any(|c| c == "sync"), "caps musia obsahovat sync");
    assert!(
        ack_info.epochs.iter().any(|e| e.channel == channel && e.node_epoch == 0),
        "HelloAck musí oznámiť epochu kanála (D-25)"
    );

    let mut b = Client::connect(addr).await;
    b.hello(vec![]).await;

    // A appendne
    a.send(MsgType::Record, &client_envelope(&seed_a, channel, "ahoj susedia")).await;
    let ack = a.expect_ack().await;
    assert_eq!(ack.channel, channel);
    assert_eq!((ack.node_epoch, ack.node_seq), (0, 1), "prvy zaznam ma poradie 1");

    // B dostane push do 2 s (RECV_TIMEOUT = 2 s)
    let pushed = b.expect_record().await;
    assert_eq!(pushed.hash(), myhsn_core::record::RecordHash(ack.hash));
    assert_eq!((pushed.stamp.node_epoch, pushed.stamp.node_seq), (0, 1));
    pushed.validate().expect("pushnuta obalka je platna");

    // pečiatka uzla sedí s node_id (D-27: operačný kľúč = node_id)
    let node_pub = store
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .node_pub()
        .unwrap();
    assert_eq!(pushed.stamp.signed_by_node, node_pub);
    assert!(pushed.verify_stamp_sig(), "stamp_sig overitelny voči node_id");
}

/// **(b)** B je offline, A appendne 4 záznamy; B sa pripojí s
/// watermarkom `(epoch 0, seq 1)` → dostane **presne chýbajúce 3**
/// (seq 2, 3, 4) a potom je ticho.
#[tokio::test]
async fn offline_client_catches_up_exactly_missing_records() {
    let (addr, store) = spawn_server().await;
    let seed = [0xb2u8; 32];
    let (channel, _) = setup(&store, "klient-b", &[&seed]);

    let mut a = Client::connect(addr).await;
    a.hello(vec![]).await;
    for i in 1..=4 {
        a.send(MsgType::Record, &client_envelope(&seed, channel, &format!("post {i}")))
            .await;
        let ack = a.expect_ack().await;
        assert_eq!(ack.node_seq, i);
    }

    // B: watermark (0, 1) = má aplikovaný seq 1 → chýbajú 2, 3, 4
    let mut b = Client::connect(addr).await;
    b.hello(vec![HelloWatermark {
        channel,
        node_epoch: 0,
        node_seq: 1,
    }])
    .await;

    let mut seqs = Vec::new();
    for _ in 0..3 {
        let rec = b.expect_record().await;
        assert_eq!(rec.stamp.channel, channel);
        seqs.push(rec.stamp.node_seq);
    }
    assert_eq!(seqs, vec![2, 3, 4], "range dobehnutie presne chýbajúce");
    b.expect_quiet().await;

    // kontrola na druhej strane: watermark (0, 0) = nový klient → všetky 4
    let mut c = Client::connect(addr).await;
    c.hello(vec![HelloWatermark {
        channel,
        node_epoch: 0,
        node_seq: 0,
    }])
    .await;
    for expected in 1..=4 {
        let rec = c.expect_record().await;
        assert_eq!(rec.stamp.node_seq, expected);
    }
    c.expect_quiet().await;
}

/// **(c)** duplicitný append rovnakého hashu: druhý `Ack` je zhodný s
/// prvým (rovnaký finálny hash aj poradie) a v logu je jeden záznam.
#[tokio::test]
async fn duplicate_append_is_idempotent() {
    let (addr, store) = spawn_server().await;
    let seed = [0xc3u8; 32];
    let (channel, _) = setup(&store, "klient-c", &[&seed]);

    let mut a = Client::connect(addr).await;
    a.hello(vec![]).await;

    let envelope = client_envelope(&seed, channel, "ten isty post");
    a.send(MsgType::Record, &envelope).await;
    let ack1 = a.expect_ack().await;
    a.send(MsgType::Record, &envelope).await;
    let ack2 = a.expect_ack().await;

    assert_eq!(ack1, ack2, "duplicitný append → identický Ack (idempotentné)");

    // v logu je práve jeden záznam a alokátor nepokračoval
    let count = store
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .record_count()
        .unwrap();
    assert_eq!(count, 1, "duplikát sa nesmie zapísať dvakrát");

    // čerstvý klient s watermarkom 0 uvidí tiež práve jeden záznam
    let mut fresh = Client::connect(addr).await;
    fresh
        .hello(vec![HelloWatermark {
            channel,
            node_epoch: 0,
            node_seq: 0,
        }])
        .await;
    let rec = fresh.expect_record().await;
    assert_eq!(rec.hash(), myhsn_core::record::RecordHash(ack1.hash));
    fresh.expect_quiet().await;
}

/// **(d)** `Hello` s nekompatibilnou verziou → `Reject` s kódom
/// `REJECT_VERSION` (D-22/D-24).
#[tokio::test]
async fn hello_with_bad_version_is_rejected_with_code() {
    let (addr, _store) = spawn_server().await;
    let mut client = Client::connect(addr).await;

    client
        .send(
            MsgType::Hello,
            &wire::encode_hello(&Hello {
                proto_min: 5,
                proto_max: 9,
                caps: vec!["sync".to_string()],
                watermarks: vec![],
                session: None,
            }),
        )
        .await;

    let (msg_type, payload) = client.frame().await;
    assert_eq!(msg_type, MsgType::Reject as u8, "zlá verzia → Reject");
    let reject = wire::decode_reject(&payload).unwrap();
    assert_eq!(reject.code, REJECT_VERSION, "kód musí byť REJECT_VERSION (1)");
    assert!(!reject.reason.is_empty(), "Reject nesie aj ľudský dôvod");
}

/// **(e)** nadväznosť B4 → B5: podpis **revokovaným** device kľúčom sa
/// pri append odmietne (`REJECT_RECORD`); neznámy kľúč taktiež. Pred
/// revokáciou ten istý kľúč prešiel — testuje sa teda skutočná zmena
/// stavu, nie trvalé odmietanie.
#[tokio::test]
async fn revoked_device_key_is_rejected_on_append() {
    let (addr, store) = spawn_server().await;
    let seed = [0xd4u8; 32];
    let (channel, device_ids) = setup(&store, "klient-e", &[&seed]);
    let device_id = device_ids[0];

    let mut a = Client::connect(addr).await;
    a.hello(vec![]).await;

    // 1) aktívny kľúč: append prejde
    a.send(MsgType::Record, &client_envelope(&seed, channel, "pred revokaciou"))
        .await;
    let ack = a.expect_ack().await;
    assert_eq!(ack.node_seq, 1);

    // 2) uzol kľúč revokuje (B4: DELETE /devices/{id} → store)
    let account_id = {
        let s = store.lock().unwrap_or_else(|p| p.into_inner());
        s.device_account_if_active(&public_from_seed(&seed))
            .unwrap()
            .unwrap()
    };
    {
        let mut s = store.lock().unwrap_or_else(|p| p.into_inner());
        s.revoke_device(&account_id, device_id, 2_000).unwrap();
    }

    // 3) ten istý kľúč po revokácii: nový záznam sa odmietne kódom
    //    REJECT_RECORD — relácia zostáva otvorená (Reject nie je Close)
    a.send(MsgType::Record, &client_envelope(&seed, channel, "po revokacii"))
        .await;
    assert_eq!(a.expect_reject().await, REJECT_RECORD);

    // 4) neznámy kľúč (nikdy neatestovaný) → tiež REJECT_RECORD
    let stranger = [0xe5u8; 32];
    a.send(MsgType::Record, &client_envelope(&stranger, channel, "cudzí kľúč"))
        .await;
    assert_eq!(a.expect_reject().await, REJECT_RECORD);

    // log: pribudol len záznam z kroku 1
    let count = store
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .record_count()
        .unwrap();
    assert_eq!(count, 1, "odmietnuté správy sa nezapisujú");
}

// --- B6 (MYHSN-8): mazanie cez WebSocket, rozhodnutie D-30 ---------------

/// Mazací záznam tak, ako ho posiela klient: poradie nepozná, doplní ho
/// uzol (D-25) — rovnaký tvar ako `client_envelope`, len iné telo.
fn client_deletion(author_seed: &[u8; 32], channel: ChannelId, payload: &Payload) -> Vec<u8> {
    Envelope::build(
        author_seed,
        payload,
        NodeStamp::new(channel, 0, 0, [0u8; 32]),
        b"",
        None,
    )
    .encode()
}

/// Vodotlač na kanál: `from_seq = 0` znamená „poznám kanál od nuly“, uzol
/// teda dobieha od seq 1 (watermark je najvyššia aplikovaná pozícia, D-29).
fn wm(channel: ChannelId, from_seq: u64) -> HelloWatermark {
    HelloWatermark { channel, node_epoch: 0, node_seq: from_seq }
}

/// Pripojí klienta s vodotlačami a vráti **druhy** záznamov, ktoré mu uzol
/// dobehol. Ticho po dobehnutí ukončí zber — teda to, čo vráti, je presne
/// to, čo čítací pohľad ukazuje (D-30).
async fn catch_up_kinds(
    addr: SocketAddr,
    watermarks: &[HelloWatermark],
) -> Vec<myhsn_core::record::RecordKind> {
    let mut c = Client::connect(addr).await;
    c.hello(watermarks.to_vec()).await;
    let mut kinds = Vec::new();
    loop {
        let next = tokio::time::timeout(RECV_TIMEOUT, c.stream.next()).await;
        match next {
            Err(_) => break, // ticho = dobehnutie dokončené
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                let (hdr, payload) = wire::decode_frame(&bytes).expect("platny frame");
                if MsgType::from_u8(hdr.msg_type) == Some(MsgType::Record) {
                    kinds.push(
                        Envelope::decode(payload)
                            .expect("dobehnutá obálka ide dekódovať")
                            .kind,
                    );
                }
            }
            Ok(other) => panic!("neočakávaná správa v dobehnutí: {other:?}"),
        }
    }
    kinds
}

/// **Kritérium B6 (tombstone):** príspevok zmizne z feedu aj z dobehnutia.
/// Klient, ktorý ho už videl (watermark pred tombstone), musí dostať práve
/// tombstone — inby by nevedel, čo má vymazať zo svojej cache.
#[tokio::test]
async fn b6_tombstone_hides_post_from_feed_and_catch_up() {
    let (addr, store) = spawn_server().await;
    let seed_a = [0xa1u8; 32];
    let seed_c = [0xc3u8; 32];
    // dva device kľúče toho istého účtu — autorstvo sa posudzuje po kľúči
    let (channel, _devices) = setup(&store, "klient-a", &[&seed_a, &seed_c]);

    let mut a = Client::connect(addr).await;
    a.hello(vec![]).await;
    a.send(MsgType::Record, &client_envelope(&seed_a, channel, "viditelny prispevok"))
        .await;
    let ack = a.expect_ack().await;
    let post_hash = ack.hash;

    // čerstvý klient príspevok vidí
    assert_eq!(
        catch_up_kinds(addr, &[wm(channel, 0)]).await,
        vec![myhsn_core::record::RecordKind::Post],
        "pred tombstone je príspevok v dobehnutí"
    );

    // A tombstone → je to záznam logu s poradím (append-only, D-25)
    a.send(
        MsgType::Record,
        &client_deletion(&seed_a, channel, &Payload::Tombstone { target: post_hash }),
    )
    .await;
    let ts_ack = a.expect_ack().await;
    assert_eq!((ts_ack.node_epoch, ts_ack.node_seq), (0, 2));

    // čerstvý klient: príspevok už NEUZRIE, vidí len tombstone
    assert_eq!(
        catch_up_kinds(addr, &[wm(channel, 0)]).await,
        vec![myhsn_core::record::RecordKind::Tombstone],
        "tombstonovany prispevok zmizne z dobehnutia"
    );

    // klient so watermarkom na príspevku: dostane tombstone, nie príspevok
    assert_eq!(
        catch_up_kinds(addr, &[HelloWatermark { channel, node_epoch: 0, node_seq: 1 }]).await,
        vec![myhsn_core::record::RecordKind::Tombstone],
        "vodotlač nad cieľom musí dostať tombstone"
    );

    // cudzí kľúč nesmie tombstonevať cudzí príspevok (D-30: len autor)
    a.send(
        MsgType::Record,
        &client_deletion(&seed_c, channel, &Payload::Tombstone { target: post_hash }),
    )
    .await;
    assert_eq!(a.expect_reject().await, REJECT_RECORD);

    // odmietnutie NESMIE nechať dieru v poradí: ďalší záznam má seq 3
    a.send(MsgType::Record, &client_envelope(&seed_a, channel, "pokracovanie"))
        .await;
    let next = a.expect_ack().await;
    assert_eq!(
        (next.node_epoch, next.node_seq),
        (0, 3),
        "odmietnuty mazaci zaznam nealokoval node_seq"
    );

    // duplicitný tombstone (rovnaká správa znova) je idempotentný (D-29)
    a.send(
        MsgType::Record,
        &client_deletion(&seed_a, channel, &Payload::Tombstone { target: post_hash }),
    )
    .await;
    let dup = a.expect_ack().await;
    assert_eq!(dup.hash, ts_ack.hash, "duplikát dostane ten istý Ack");
    assert_eq!(
        store
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .record_count()
            .unwrap(),
        3,
        "duplikát nepridal rad"
    );
}

/// **Kritérium B6 (erase, D-30):** erase **zmizne obsah** a **zostane
/// dôvod**. Merané pred/after priamo v bajtoch, ktoré uzol vydáva, plus
/// pohľad na čitateľa.
#[tokio::test]
async fn b6_erase_removes_content_but_keeps_reason() {
    use myhsn_core::record::{EraseReason, RecordHash, RecordKind};
    use myhsn_core::storage::RangeQuery;

    let (addr, store) = spawn_server().await;
    let seed_a = [0xa1u8; 32];
    let (channel, _devices) = setup(&store, "klient-a", &[&seed_a]);

    let mut a = Client::connect(addr).await;
    a.hello(vec![]).await;
    a.send(MsgType::Record, &client_envelope(&seed_a, channel, "citlivy obsah na vymazanie"))
        .await;
    let ack = a.expect_ack().await;
    let target = ack.hash;

    // PRED: obsah je v bajtoch pod hashom, ktorý pozná klient
    let before = store
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&RecordHash(target))
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&before).contains("citlivy obsah"),
        "pred erase je obsah v logu"
    );

    // erase
    a.send(
        MsgType::Record,
        &client_deletion(
            &seed_a,
            channel,
            &Payload::Erase {
                target,
                reason: EraseReason::AuthorRequest,
                target_kind: RecordKind::Post,
            },
        ),
    )
    .await;
    let erase_ack = a.expect_ack().await;
    assert_eq!((erase_ack.node_epoch, erase_ack.node_seq), (0, 2));

    // PO: starý hash neexistuje (identifikátor je hash bajtov, D-25) a na
    // pozícii 1 ležia iné bajty — bez obsahu, s dôvodom
    let rows = {
        let s = store.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            s.get(&RecordHash(target)).unwrap().is_none(),
            "po erase starý identifikátor neplatí"
        );
        s.visible_range(
            &RangeQuery { channel, from_epoch: 0, from_seq: 1, limit: 10 },
            None,
        )
        .unwrap()
    };
    assert_eq!(rows.len(), 1, "čitateľ vidí práve jeden placeholder");
    let (pos, raw) = &rows[0];
    assert_eq!((pos.node_epoch, pos.node_seq), (0, 1), "erase nemení pozíciu");
    assert!(
        !String::from_utf8_lossy(raw).contains("citlivy obsah"),
        "bajty obsahu musia byť preč"
    );
    let env = Envelope::decode(raw).unwrap();
    assert_eq!(env.kind, RecordKind::Erase);
    assert_eq!(
        env.erased_reason(),
        Some(EraseReason::AuthorRequest),
        "kritérium: erase zmizne obsah ale zostane dôvod"
    );
    env.validate().expect("nahradená obálka je platná");

    // čerstvý čitateľ: vymenený rad, akcia erase sa neopakuje
    assert_eq!(catch_up_kinds(addr, &[wm(channel, 0)]).await, vec![RecordKind::Erase]);

    // klient NAD cieľom musí dostať akciu erase — ukazuje na hash, pod
    // ktorým má príspevok vo svojej cache (to je to, čo má vymazať)
    let mut c = Client::connect(addr).await;
    c.hello(vec![HelloWatermark { channel, node_epoch: 0, node_seq: 1 }])
        .await;
    let action = c.expect_record().await;
    assert_eq!(action.kind, RecordKind::Erase);
    assert!(!action.body_sig.is_nil(), "akciu erase podpísal autor");
    action.validate().expect("akcia je platná");
    match action.payload().unwrap() {
        Payload::Erase { target: t, reason, .. } => {
            assert_eq!(t, target, "akcia mierí na hash z cache klienta");
            assert_eq!(reason, EraseReason::AuthorRequest);
        }
        _ => panic!("ocekovany erase payload"),
    }
}

/// **Kritérium B6 (hide):** skrytie je osobná voľba — uzol ju nemaže
/// nikomu inému a na WS ju vôbec nefiltruje (relácia nemá autentizáciu),
/// takže hide záznam sa posiela a filter aplikuje klient.
#[tokio::test]
async fn b6_hide_is_accepted_and_broadcast_like_any_other_record() {
    use myhsn_core::record::RecordKind;

    let (addr, store) = spawn_server().await;
    let seed_a = [0xa1u8; 32];
    let seed_c = [0xc3u8; 32];
    let (channel, _devices) = setup(&store, "klient-a", &[&seed_a, &seed_c]);

    let mut a = Client::connect(addr).await;
    a.hello(vec![]).await;
    a.send(MsgType::Record, &client_envelope(&seed_a, channel, "nechcem to vidiet"))
        .await;
    let ack = a.expect_ack().await;

    // hide smie poslať aj cudzí kľúč — skryje to len pre seba
    a.send(
        MsgType::Record,
        &client_deletion(
            &seed_c,
            channel,
            &Payload::Hide { target: ack.hash, reason: "nechapem to".into() },
        ),
    )
    .await;
    let hide_ack = a.expect_ack().await;
    assert_eq!((hide_ack.node_epoch, hide_ack.node_seq), (0, 2));

    // príspevok ostáva pre ostatných; hide záznam ide s ním (klient filter
    // aplikuje sám, lebo WS nevie, kto číta)
    assert_eq!(
        catch_up_kinds(addr, &[wm(channel, 0)]).await,
        vec![RecordKind::Post, RecordKind::Hide]
    );

    // a s čitateľom = autorom hide úložňa príspevok vyfiltruje
    use myhsn_core::storage::RangeQuery;
    let kinds = {
        let s = store.lock().unwrap_or_else(|p| p.into_inner());
        s.visible_range(
            &RangeQuery { channel, from_epoch: 0, from_seq: 1, limit: 10 },
            Some(&public_from_seed(&seed_c)),
        )
        .unwrap()
        .into_iter()
        .map(|(_, raw)| Envelope::decode(&raw).unwrap().kind)
        .collect::<Vec<_>>()
    };
    assert_eq!(kinds, vec![RecordKind::Hide], "autorovi hide jeho príspevok zmizol");
}

// --- F14a (MYHSN-56): rolový cap, HelloAck role, gating pushov ----------

/// Ručný HTTP/1.1 POST (bez reqwest dev-dep): `Connection: close` a
/// axum odpoved s Content-Length → čítame do konca soketu.
async fn http_post(addr: SocketAddr, path: &str, bearer: &str, body: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {bearer}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let first = text.lines().next().unwrap_or_default().to_string();
    let status: u16 = first
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("neplatny status riadok: {text:?}"))
        .parse()
        .unwrap_or_else(|_| panic!("neplatny status: {text:?}"));
    (status, text)
}

/// Vloží session token priamo do úložne (cestu `/login` kryjú unit testy).
fn put_test_session(store: &SharedStore, account: &[u8; 32]) -> String {
    let token = node::auth::random_32();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    store
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .put_session(&node::auth::hash_session_token(&token), account, now, 3600)
        .unwrap();
    myhsn_core::record::to_hex(&token)
}

impl Client {
    /// `Hello` s capmi podľa výberu a voliteľným session tokenom (F14a).
    async fn hello_with(&mut self, caps: Vec<String>, session: Option<String>) -> wire::HelloAck {
        self.send(
            MsgType::Hello,
            &wire::encode_hello(&Hello {
                proto_min: 0,
                proto_max: 0,
                caps,
                watermarks: vec![],
                session,
            }),
        )
        .await;
        let (msg_type, payload) = self.frame().await;
        assert_eq!(msg_type, MsgType::HelloAck as u8, "očakávali sme HelloAck");
        wire::decode_hello_ack(&payload).expect("platny HelloAck")
    }
}

/// **F14a spätná kompatibilita + gating:**
/// - starý klient (caps `["sync"]`) dostane `HelloAck` s 3 prvkami
///   (`role == None`) a systémový kanál NEVIDÍ v epochách;
/// - klient s capom `"roles"` + session tokenom vidí rolu v `HelloAck`
///   (4. prvok) a systémový kanál v epochách áno;
/// - po grante role cez REST dostane roles-klient `RoleUpdate` (MsgType 9)
///   a auditný `Record`, starý klient NIČ (žiadny neznámy frame).
#[tokio::test]
async fn f14a_roles_cap_gating_and_role_update_push() {
    let (addr, store) = spawn_server().await;
    // simuluj štart uzla: systémový kanál existuje pred pripojením
    store.lock().unwrap_or_else(|p| p.into_inner()).ensure_system_channel().unwrap();
    let system = store.lock().unwrap_or_else(|p| p.into_inner()).system_channel_id().unwrap().unwrap();

    // účty: admin (povýšený priamo v úložni) + uci (user) — jeden kanál
    // stačí, `setup` voláme raz (názov kanála je v uzle UNIQUE)
    let (_ch, _) = setup(&store, "admin", &[&[0xa1u8; 32]]);
    let admin_id = {
        let s = store.lock().unwrap_or_else(|p| p.into_inner());
        s.account_by_username("admin").unwrap().unwrap().id
    };
    let uci_id = {
        let mut s = store.lock().unwrap_or_else(|p| p.into_inner());
        let acc = s.create_account("uci", DUMMY_PHC, 1_000).unwrap();
        s.attest_device_key(
            &acc.id,
            &DevicePublicKey::from_seed(&[0xb2u8; 32]),
            "d",
            1_000,
        )
        .unwrap();
        acc.id
    };
    store
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .apply_role_change(&admin_id, 2, 0, false, None)
        .unwrap();
    let admin_token = put_test_session(&store, &admin_id);
    let uci_token = put_test_session(&store, &uci_id);

    // 1) starý klient: 3-prvkový HelloAck, žiadny systémový kanál
    let mut old = Client::connect(addr).await;
    let ack = old.hello_with(vec!["sync".to_string()], None).await;
    assert!(ack.role.is_none(), "starý klient nesmie dostať 4. prvok");
    assert!(!ack.epochs.iter().any(|e| e.channel == system), "systémový kanál je pred starým klientom skrytý");

    // 2) roles-klient: rola v HelloAck + systémový kanál v epochách
    let mut roles_client = Client::connect(addr).await;
    let ack = roles_client
        .hello_with(vec!["sync".to_string(), "roles".to_string()], Some(uci_token.clone()))
        .await;
    assert_eq!(ack.role.as_ref().map(|(r, _)| r.as_str()), Some("user"));
    assert!(ack.epochs.iter().any(|e| e.channel == system), "roles-klient vidí systémový kanál");

    // 3) grant cez REST → roles-klient dostane Record (audit) + RoleUpdate,
    //    starý klient nedostane nič
    let (status, body) = http_post(
        addr,
        "/admin/roles",
        &admin_token,
        r#"{"account":"uci","role":"moderator","perms":5}"#,
    )
    .await;
    assert_eq!(status, 200, "grant adminom prechádza: {body}");

    let mut saw_record = false;
    let mut saw_role_update = false;
    for _ in 0..2 {
        let (msg_type, payload) = roles_client.frame().await;
        match MsgType::from_u8(msg_type) {
            Some(MsgType::Record) => {
                let env = Envelope::decode(&payload).expect("audit dekodovatelny");
                assert_eq!(env.stamp.channel, system);
                assert!(matches!(env.kind, myhsn_core::record::RecordKind::GrantRole));
                saw_record = true;
            }
            Some(MsgType::RoleUpdate) => {
                let u = wire::decode_role_update(&payload).expect("RoleUpdate dekodovatelny");
                assert_eq!(u.account, uci_id);
                assert_eq!(u.username, "uci");
                assert_eq!((u.role.as_str(), u.perms), ("moderator", 5));
                saw_role_update = true;
            }
            other => panic!("neočakávaný typ {other:?}"),
        }
    }
    assert!(saw_record && saw_role_update, "oboje pushy musia prísť");

    // starý klient: ďalšia správa počas grantu neprišla (žiadny unknown frame)
    // — overíme time-outom: čakáme len na vlastný re-Hello (pingpong)
    let old_ack = old.hello_with(vec!["sync".to_string()], None).await;
    assert!(old_ack.role.is_none());
}

// ===========================================================================
// F14c (MYHSN-58): skupinové kanály — caps gating, `ChannelRoleUpdate`
// (MsgType 10) a členstvo ako podmienka zápisu
// ===========================================================================

/// Pripraví uzol so **skupinovým** kanálom: `admin` je owner, `clen` je
/// member (má zariadenie pre podpis), `cudzie` nemá vzťah. Vráti id kanála,
/// id účtov a session tokeny (REST aj WS cesty).
fn setup_group(
    store: &SharedStore,
    name: &str,
    member_seed: &[u8; 32],
    alien_seed: &[u8; 32],
) -> (ChannelId, [u8; 32], [u8; 32], [u8; 32], String, String, String) {
    // `setup` dáva legacy kanál + účet `admin` so zariadením (seed 0xa1)
    let (_legacy, _) = setup(store, "admin", &[&[0xa1u8; 32]]);
    let mut s = store.lock().unwrap_or_else(|p| p.into_inner());
    let admin_id = s.account_by_username("admin").unwrap().unwrap().id;
    let member = s.create_account("clen", DUMMY_PHC, 1_000).unwrap();
    s.attest_device_key(
        &member.id,
        &DevicePublicKey::from_seed(member_seed),
        "d",
        1_000,
    )
    .unwrap();
    let alien = s.create_account("cudzie", DUMMY_PHC, 1_000).unwrap();
    s.attest_device_key(
        &alien.id,
        &DevicePublicKey::from_seed(alien_seed),
        "d",
        1_000,
    )
    .unwrap();
    let (group, _) = s
        .create_group_channel(
            name,
            ChannelKind::Mixed,
            &admin_id,
            "admin",
            (admin_id, [0xa1u8; 32]),
        )
        .unwrap();
    s.channel_add_member(&group.id, &member.id, (admin_id, [0xa1u8; 32]))
        .unwrap();
    drop(s);
    (
        group.id,
        admin_id,
        member.id,
        alien.id,
        put_test_session(store, &admin_id),
        put_test_session(store, &member.id),
        put_test_session(store, &alien.id),
    )
}

/// **Caps sú autorita protokolu (D-29):** group kanál sa starému klientu
/// vôbec neobjaví — ani v epochách, ani v 5. prvku `HelloAck`.
#[tokio::test]
async fn f14c_group_channels_hidden_without_channels_cap() {
    let (addr, store) = spawn_server().await;
    store
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .ensure_system_channel()
        .unwrap();
    let (group, _admin, _member, _alien, admin_token, _mt, _at) =
        setup_group(&store, "partia", &[0xb2u8; 32], &[0xc3u8; 32]);

    // 1) starý klient (len `sync`): ani s platnou session nedostane 5. prvok
    let mut old = Client::connect(addr).await;
    let ack = old
        .hello_with(vec!["sync".to_string()], Some(admin_token.clone()))
        .await;
    assert!(
        ack.role.is_none(),
        "4. prvok chce cap `roles` — starý klient ho nemá (F14a)"
    );
    assert!(
        ack.channel_roles.is_none(),
        "bez capu `channels` nesmie prísť 5. prvok"
    );
    assert!(
        !ack.epochs.iter().any(|e| e.channel == group),
        "group kanál je pred starým klientom skrytý"
    );

    // 2) klient s `roles` ale bez `channels`: group kanál stále nevidí
    let mut roles_only = Client::connect(addr).await;
    let ack = roles_only
        .hello_with(
            vec!["sync".to_string(), "roles".to_string()],
            Some(admin_token.clone()),
        )
        .await;
    assert!(ack.channel_roles.is_none());
    assert!(!ack.epochs.iter().any(|e| e.channel == group));

    // 3) klient s oboma capmi: epocha + 5. prvok s efektívnou rolou
    let mut full = Client::connect(addr).await;
    let ack = full
        .hello_with(
            vec!["sync".to_string(), "roles".to_string(), "channels".to_string()],
            Some(admin_token.clone()),
        )
        .await;
    assert!(
        ack.epochs.iter().any(|e| e.channel == group),
        "s capom `channels` musí byť group kanál v epochách"
    );
    let entries = ack.channel_roles.clone().expect("5. prvok musí prísť");
    assert_eq!(entries.len(), 1, "len kanály s rolou: {entries:?}");
    assert_eq!(entries[0].channel, group);
    assert_eq!(entries[0].role, "owner");
    assert!(!entries[0].muted);
    // uzol si svoje caps **nemení** — `lk` bot by neznámy cap mohol zhodiť
    assert_eq!(
        ack.caps,
        vec!["sync".to_string()],
        "NODE_CAPS ostáva [\"sync\"], schopnosti hlási GET /node/info"
    );

    // 4) bez session sa 5. prvok neposielava ani s capmi (rovnaká brána
    //    ako 4. prvok — žiadne pozičné `null`)
    let mut no_session = Client::connect(addr).await;
    let ack = no_session
        .hello_with(
            vec!["sync".to_string(), "roles".to_string(), "channels".to_string()],
            None,
        )
        .await;
    assert!(ack.role.is_none());
    assert!(ack.channel_roles.is_none());
}

/// **Push + gating zápisu:** audity a `ChannelRoleUpdate` (MsgType 10)
/// idú len reláciám s capom `"channels"`; do group kanála píšu len členovia
/// a stíšený člen dostane `Reject`.
#[tokio::test]
async fn f14c_channel_role_update_push_and_membership_gate() {
    let (addr, store) = spawn_server().await;
    let (group, _admin, member_id, _alien, admin_token, member_token, alien_token) =
        setup_group(&store, "partia2", &[0xd4u8; 32], &[0xe5u8; 32]);

    // člen s capmi + starý člen bez capov (ten nesmie vidieť nič skupinové)
    let mut capped = Client::connect(addr).await;
    let ack = capped
        .hello_with(
            vec!["sync".to_string(), "roles".to_string(), "channels".to_string()],
            Some(member_token.clone()),
        )
        .await;
    assert_eq!(
        ack.channel_roles.as_ref().expect("5. prvok")[0].role,
        "member",
        "člen vidí svoju kanálovú rolu"
    );
    let mut old = Client::connect(addr).await;
    let old_ack = old
        .hello_with(vec!["sync".to_string()], Some(member_token.clone()))
        .await;
    assert!(old_ack.channel_roles.is_none());

    // 1) **cudziec** (nie člen) appendne do group kanála → `Reject`
    let mut alien = Client::connect(addr).await;
    let alien_ack = alien
        .hello_with(
            vec!["sync".to_string(), "roles".to_string(), "channels".to_string()],
            Some(alien_token.clone()),
        )
        .await;
    assert!(
        alien_ack.channel_roles.as_ref().map(|v| v.is_empty()) == Some(true),
        "cudziec má prázdny zoznam rolí, nie `None`"
    );
    alien
        .send(MsgType::Record, &client_envelope(&[0xe5u8; 32], group, "cudzi text"))
        .await;
    assert_eq!(
        alien.expect_reject().await,
        REJECT_RECORD,
        "neclen nesmie pisat do skupiny"
    );

    // 2) **člen** appendne → `Ack` a poradie v skupinovej epoche
    let mut member = Client::connect(addr).await;
    let _ = member
        .hello_with(
            vec!["sync".to_string(), "roles".to_string(), "channels".to_string()],
            Some(member_token.clone()),
        )
        .await;
    member
        .send(MsgType::Record, &client_envelope(&[0xd4u8; 32], group, "clensky text"))
        .await;
    let ack = member.expect_ack().await;
    assert_eq!(ack.channel, group);
    assert_eq!(
        (ack.node_epoch, ack.node_seq),
        (0, 3),
        "skupina má vlastnú epochu: seq 1 = create_channel audit, 2 = pridanie          člena, 3 = tento príspevok"
    );

    // 3) **povýšenie cez REST** → capped klient dostane `Record` (audit
    //    kind 9 v group kanáli) + `ChannelRoleUpdate` (MsgType 10)
    let (status, body) = http_post(
        addr,
        &format!("/channels/{}/members", hex_of(&group)),
        &admin_token,
        r#"{"account":"cudzie"}"#,
    )
    .await;
    assert_eq!(status, 201, "owner prida člena: {body}");

    // (vlastný príspevok člena dorazí ako `Record` pred auditom — ten
    // preskočíme, počítame s ním)
    let mut saw_audit = false;
    let mut saw_update = false;
    for _ in 0..4 {
        let (msg_type, payload) = capped.frame().await;
        match MsgType::from_u8(msg_type) {
            Some(MsgType::Record) => {
                let env = Envelope::decode(&payload).expect("audit dekodovatelny");
                assert_eq!(env.stamp.channel, group, "záznam patrí do group kanála");
                if env.kind == myhsn_core::record::RecordKind::GrantChannelRole {
                    saw_audit = true;
                }
            }
            Some(MsgType::ChannelRoleUpdate) => {
                let u = wire::decode_channel_role_update(&payload).expect("ChannelRoleUpdate");
                assert_eq!(u.channel, group);
                assert_eq!(u.account, _alien);
                assert_eq!(u.username, "cudzie");
                assert_eq!(u.channel_role, "member");
                assert!(!u.muted);
                saw_update = true;
            }
            other => panic!("neočakávaný typ {other:?}"),
        }
        if saw_audit && saw_update {
            break;
        }
    }
    assert!(saw_audit && saw_update, "obe pushy musia prísť");

    // 4) **starý klient** nedostane z group kanála nič (ani audit, ani 10)
    old.expect_quiet().await;

    // 5) **stíšenie** → `ChannelRoleUpdate` s `muted = true`, ale **žiadny
    //    audit** (stíšenie je materializovaný stav bez zápisu do logu)
    let (status, body) = http_post(
        addr,
        &format!("/channels/{}/mute", hex_of(&group)),
        &admin_token,
        r#"{"account":"cudzie","duration_secs":3600}"#,
    )
    .await;
    assert_eq!(status, 200, "owner stíši člena: {body}");
    let mut update = None;
    for _ in 0..3 {
        let (msg_type, payload) = capped.frame().await;
        match MsgType::from_u8(msg_type) {
            Some(MsgType::ChannelRoleUpdate) => {
                update = Some(wire::decode_channel_role_update(&payload).unwrap());
                break;
            }
            // stíšenie **nie je** audit — žiadny `Record` k nemu nesmie prísť
            Some(MsgType::Record) => {
                let env = Envelope::decode(&payload).unwrap();
                assert_ne!(
                    env.kind,
                    myhsn_core::record::RecordKind::GrantChannelRole,
                    "stíšenie sa do logu nepíše"
                );
                continue;
            }
            other => panic!("neočakávaný typ {other:?}"),
        }
    }
    let u = update.expect("ChannelRoleUpdate s muted musí prísť");
    assert!(u.muted && u.channel_role == "member");
    old.expect_quiet().await;

    // 6) **stíšený člen** nemôže písať — `Reject` (rozhodnutie §7)
    let mut muted_client = Client::connect(addr).await;
    let _ = muted_client
        .hello_with(
            vec!["sync".to_string(), "roles".to_string(), "channels".to_string()],
            Some(alien_token.clone()),
        )
        .await;
    muted_client
        .send(MsgType::Record, &client_envelope(&[0xe5u8; 32], group, "po stíšeni"))
        .await;
    assert_eq!(
        muted_client.expect_reject().await,
        REJECT_RECORD,
        "stíšený účet nesmie pisat"
    );
    // ... a `HelloAck` mu to povie: `muted = true`
    let mut muted_probe = Client::connect(addr).await;
    let ack = muted_probe
        .hello_with(
            vec!["sync".to_string(), "roles".to_string(), "channels".to_string()],
            Some(alien_token.clone()),
        )
        .await;
    let entries = ack.channel_roles.expect("5. prvok");
    assert!(entries.iter().any(|e| e.channel == group && e.muted));
    let _ = member_id;
}

/// Hex id kanála pre REST cesty v testoch.
fn hex_of(id: &ChannelId) -> String {
    myhsn_core::record::to_hex(id)
}
