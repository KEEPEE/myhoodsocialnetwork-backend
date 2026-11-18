# MyHoodSocialNetwork — backend

Rust workspace pre backend P2P sociálnej siete pre malé komunity. Používatelia
si držia vlastné uzly (serverové programy, D-31); Flutter apka sa pripája cez
WSS. Tento repozitár obsahuje **jadro bez I/O** a **binárku uzla**.

Stav: **B2–B7 hotové** (mazanie D-30, médiá D-33) **plus** funkčné celky
**F10** (skupinové hovory cez LiveKit SFU + moderátorský kick), **F12d**
(CORS pre webové originy + kontrola `Origin` pri WS) a **F14** (rolový systém
účtov a skupinové role kanálov). Detail každého celku je v sekcích nižšie.
`cargo test --workspace` → **246 passed / 0 failed / 2 ignored** (2026-11-18,
rustc 1.100.0).

## Štruktúra

```
Cargo.toml            # workspace: crates/core + crates/node, resolver 2
config/node.toml      # ukážková konfigurácia uzla (listen, data_dir)
crates/core/          # sans-IO knižnica — NULOVÉ závislosti tokio/axum/rusqlite v jadre
  src/lib.rs
  src/record.rs       # obálka záznamu: raw bajty, BLAKE3(raw), dve vrstvy,
                      # slepý hash so soľou, tagy algoritmov, tombstone/hide/erase (D-25, D-30)
  src/channel.rs      # kanály, soľ, node_epoch, alokátor seq, reconciliation (D-25, D-10)
  src/seq.rs          # poradie per kanál: (channel, node_epoch, node_seq) (D-25)
  src/identity.rs     # account + device keys + atesty; root/operačný kľúč uzla (D-26, D-27)
  src/sync.rs         # watermark per kanál, idempotentná aplikácia podľa hashu (D-24)
  src/storage.rs      # storage trait: append / get(hash) / range(channel, seq) / meta KV (D-29)
  src/wire.rs         # framing: 8B hlavička s verziou, Hello/HelloAck/Reject, minicbor (D-24)
crates/node/          # binárka uzla (myhsn-node): axum REST + WS sync
  src/lib.rs          # lib + bin (D-31): build_router = healthz + REST + WS,
                      # rovnaký pre main aj integrné testy
  src/main.rs         # config z TOML, tracing, otvorenie úložne, bind
  src/store.rs        # RUSQLITE IMPLEMENTÁCIA traitov z core — jediné miesto s SQL (D-29);
                      # schéma v2: accounts, device_keys, sessions, records.client_hash
  src/auth.rs         # B4: Argon2id hash/overenie hesla, session tokeny (hash v DB)
  src/api.rs          # GET/POST /channels, GET /node/info + B4: register, login, devices
                      # + B5.1: GET /members (pubkey → username)
  src/ws.rs           # B5: WS relácia — Hello/HelloAck/Reject, watermark catch-up,
                      # append s B4 bránou, alloc_seq, opečiatkovanie, push/Ack;
                      # B5.1: logging relácie (pripojenie/Hello/Reject/disconnect)
  src/calls/          # F10a: hovory cez LiveKit SFU — [calls] off|managed|external,
                      # LiveKitManager (download+SHA pin, potomok, health, backoff),
                      # TokenService (JWT 60 s, kick), webhook kontrola členstva,
                      # REST /calls/{token,health,webhook,room/ensure}
  src/cors.rs         # F12d: HTTP vrstva — [http] allowed_origins, CorsLayer
                      # (preflight + ACAO) a pravidlá `Origin` pre WS handshake
  src/media.rs        # B7: POST/GET /media — pominuteľné bloby (D-33), kvóty,
                      # TOML [media], lazy cleanup; súbory mimo logu, metadáta v tab. media
  tests/ws_sync.rs    # integrné testy B5: skutočný server + 2 WS klienti
  tests/cors_http.rs  # integrné testy F12d: preflight/ACAO + WS `Origin` 101/403
```

## Build, spustenie, testovanie

Rust toolchain (`rust-version = 1.85`, testované z rustc 1.100.0):

```sh
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --workspace        # build (kód bez varovaní; 2 varovania z manifestu:
cargo test  --workspace        #                            unused deps axum-server, tokio-tungstenite)
                             # 246 testov: 62 core + 164 node unit + 9 CORS + 11 WS integrné
cargo run -p node              # spustenie uzla (hladá config/node.toml v CWD)
```

Konfigurácia: TOML súbor, výhľadne `config/node.toml` relatívne k CWD, alebo
cestu nastaví env premenná `MYHSN_NODE_CONFIG`. Výchozie bez súboru:
`listen = "0.0.0.0:8123"`, `data_dir = "./data"`. Logging cez `tracing`
(nastaviteľné cez `RUST_LOG`, default `info`).

Smoke test (overené so skutočnou binárkou 2026-11-12):

```sh
curl http://127.0.0.1:8123/healthz                       # -> ok
curl -X POST http://127.0.0.1:8123/channels \
     -H 'content-type: application/json' \
     -d '{"name":"nastienka","kind":"wall"}'             # -> 201 + id kanála
curl http://127.0.0.1:8123/channels                      # -> zoznam (soľ sa nevracia)
curl http://127.0.0.1:8123/node/info                     # -> node_id, proto, epochy
curl -X POST http://127.0.0.1:8123/register \
     -H 'content-type: application/json' \
     -d '{"username":"juraj","password":"hodne-dlhe-heslo",
          "device_pub":"<64 hex verejného ed25519 kľúča>"}'   # -> 201 + session token
curl -X POST http://127.0.0.1:8123/login \
     -H 'content-type: application/json' \
     -d '{"username":"juraj","password":"hodne-dlhe-heslo"}'  # -> 200 + session token
curl http://127.0.0.1:8123/members                       # -> {members: [{public_key_hex, username}]} (B5.1)
```

## B2 (MYHSN-4) — obálka podľa D-25 a SQLite úloža

**Obálka** (`core::record`) je kanonické CBOR pole 13 prvkov v pevnom poradí.
Platia dve vrstvy podpisu (D-25):

1. **vrstva autora** — `body_bytes` sú raw bajty autora (jadro do nich
   nesiahne), `body_hash = BLAKE3(body_bytes)`, `body_sig` je ed25519 podpis
   priamo týchto bajtov,
2. **vrstva uzla** — `stamp = (channel, node_epoch, node_seq, signed_by_node)`
   a `stamp_sig`, ktorý podpisuje `STAMP_DOMAIN || CBOR[fmt, algo, channel,
   epoch, seq, body_hash]` (doménový prefix zabraňuje kríženiu podpisov).

Ďalšie pravidlá: `hash` obálky je `BLAKE3(kanonických bajtov)` a **v obálke
sa neuchováva** (dá sa dopočítať), `blind_hash = BLAKE3(salt || body_hash)`
s per-kanálovou soľou (D-25: bez soli nezistíš rovnaký obsah), `AlgoTag` a
`fmt` sú separátne verzie/algortimy (D-22) a neznáma hodnota sa odmietne,
nie sa prehltnú.

**D-30 mazanie:** `Tombstone` a `Hide` menia len stav, `Erase` nahradí obsah
stubom `Erase { target, reason }` — obsah preč, **dôvod zostáva**. `erased()`
je pohľad na pôvodný záznam (rovnaká pozícia, nový hash, `body_sig = NIL`,
`blind_hash = NIL`); fyzické nahradenie obsahu v logu je úloha B6, nie B2 —
v logu naopak existuje **erase záznam** na vlastnom poradí, podpísaný uzlom.

**Úloža** (`node::store`) je rusqlite (`bundled`) implementácia traitov
`RecordStore` + `MetaStore` z jadra. Jadro ostáva sans-IO, SQL je len tu.
Schéma verzie 1 sa migruje v kóde cez `PRAGMA user_version` (žiadny externý
súbor), beží WAL, `foreign_keys=ON` a každý zápis je v transakcii.
`append` je **idempotentný podľa hashu** a naopak odmietne kolíziu pozície
`(channel, node_epoch, node_seq)` — poradie sa nesmie prepísať.

## Golden vektory (B2) — a ako sa dajú overiť nezávisle

Vektory G1–G3 sú z **RFC 8032 §7.1** (ed25519), G4–G7 sú naše BLAKE3 a
celá obálka. Testy `identity::tests::*` a `record::tests::golden_*` ich
assertujú; `cargo test -p core -- --ignored --nocapture` vypíše aktuálne
hodnoty obálky.

| # | vstup | výstup |
|---|---|---|
| G1 | seed `9d61b19d…7f60` | pubkey `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a` |
| G2 | ten istý seed, prázdná správa | sig `e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b` |
| G3 | seed `4ccd089b…a6fb`, správa `0x72` | pubkey `3d4017c3…660c`, sig `92a009a9…0c00` |
| G4 | `BLAKE3("")` | `af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262` |
| G5 | `BLAKE3("myhood post 1")` / `BLAKE3("myhood chat")` | `8f60188b7a93aa38e00ec6035a27078facaaaf0eb9c1ef6f5401a1a2463fd3ed` / `ae274152736d5fd1a6c78e0f6c300786ae7efb6af08e788c07f656bfe0d57f79` |
| G6 | `BLAKE3("wall-salt-0001" ‖ G5)` | `4205c68b84bc574219fad1ad2bf0357bbb9fb5125a9b5a43c1866d53425cfe63` |
| G7 | celá obálka (Post „moj prvy prispevok“, kanál `c0…c0`, epocha 0, seq 1) | viz nižšie |

G7 — kanonické bajty obálky a ich hash:

```
AUTHOR      = 873600d1521917ecef71ad1c1003f76cea9c9814e839915a757072a62844ab0d
BODY_HASH   = c7ddc5870083178937b14ca0b4dae782e332d1dc5523fde5d97e923f651ee931
BLIND_HASH  = 1992e94b716c74ca676e760c8cf6548ba6c9e6e458b5707797b76686a19fe87b
ENV_HASH    = cf1675f8ec4bf1925d188cdaa9302d114414beee02ec3fae76cc2b22f7a447c5
BODY_SIG    = 4a44c73c40b652f7852b139491076d4480c4a766e8f28f310cce58da1879f99c
              63e19d3d09f269a8c6898db0ab2c698f0d46063d9eacc577594e4d1ccb18f30f
ENV_BYTES   = 8d0100005820873600d1…(13-polové CBOR, kompletný výstup dá
              `cargo test -p core -- --ignored --nocapture`)
```

**Nezávislé overenie** (mimo Rustu, aby vektory nemohol potvrdiť len ich
vlastný kód) — referenčná CLI `b3sum` 1.8.7 a `cryptography` (OpenSSL
ed25519), overené 2026-11-12:

```sh
cargo install b3sum --locked          # referenčná BLAKE3 implementácia
printf '' | b3sum                     # -> af1349b9…3262  (G4)
# G7: hex obálky -> bajty, BLAKE3 celých bajtov = ENV_HASH,
#     BLAKE3(vytiahnuté body_bytes) = BODY_HASH,
#     BLAKE3(salt || body_hash)     = BLIND_HASH,
#     Ed25519PublicKey(author).verify(BODY_SIG, body_bytes) = OK
```

Výsledok overenia: všetky tri hashe sú zhodné s `b3sum`, podpis overí OpenSSL
s verejným kľúčom autora z obálky a **jednobajtová zmena tela podpis zneplatní**.

## B3 (MYHSN-5) — kanály, node_seq, epochy

`core::channel` drží logiku bez I/O: `Channel` (id, názov, druh `wall`/`chat`/
`mixed`, soľ, `node_epoch`), `SeqAllocator` a `reconcile()`. Node drží
tabuľky `channels` a `seq_counters` a **alokuje poradie jedným SQL príkazom**:

```sql
INSERT INTO seq_counters (channel, node_epoch, last_seq) VALUES (?1, ?2, 1)
  ON CONFLICT (channel, node_epoch) DO UPDATE SET last_seq = last_seq + 1
  RETURNING last_seq
```

Atómový inkrement bez prečítaj-zmeň-zapíš okna. Pozor na chyták: `RETURNING`
pri UPSERT vracia hodnotu **po** update, preto stĺpec uchováva „posledné
pridelené“, nie „ďalšie“ — inak by prvá alokácia vrátila 2.

**D-25 obnova zo zálohy:** `restore_new_epoch()` zvýši `node_epoch` všetkých
kanálov o 1, záznamy sa **nemažú** (ostávajú so starou epochou, takže
sa nič nestratí a kolízii pozície sa vyhneme) a poradie v novej epoche
začína od 1. Test to robí s reálnou kópiou `.db` súboru.

**Reconciliation** (D-24): klient pošle `(node_epoch, {seq → hash})`, uzol
vráti `missing` / `mismatched` / `client_extra` a príznak `stale_epoch`.
Kľúčové: **pozícia je `(epoch, seq)`**, nie len `seq` — záznam v epoche 1 na
seq 1 nie je tá istá pozícia ako epocha 0 seq 1, takže chýba, nie je v
nezshode.

REST (kanály a info o uzle — autentizácia prišla v B4, vid' nižšie;
`POST /channels` zostáva admin operácia bez prihlásenia):

| koncovka | význam |
|---|---|
| `GET /channels` | zoznam kanálov — **soľ sa nevracia** (D-25) |
| `POST /channels` | vytvor `{name, kind}`; duplicitný názov → 409, zlý druh → 400 |
| `GET /node/info` | `node_id`, `proto_version`, `node_epoch`, epochy a `next_seq` per kanál |

## B4 (MYHSN-6) — účty, device keys, login (D-26)

Model z D-26: **účet je množina uzlom atestovaných device kľúčov**, žiadny
escrow súkromného kľúča. Nové zariadenie = atest nového kľúča už overeným
účtom; históriu netreba revalidovať (revokácia je stav kľúča, nie dát).

**Argon2id** (`node::auth`, parametry zámerne dokumentované):
`m = 19 456 KiB (19 MB), t = 2, p = 1` — dolná hranica OWASP odporúčania
pre Argon2id (low-memory budget), lebo uzol beží aj na slabšom HW a login
nie je frekventovaná operácia. 32 B PHC kódovaný hash (`$argon2id$v=19$…`),
soľ 16 B z OS RNG. Kryptografia zámerne **nie v core** — core zostáva
ľahký pre WASM apku a login je serverová operácia; core drží len dátové
tvary (`Account`, `DeviceKey`).

**Session tokeny:** 32 B z `OsRng`, navonok hex, v tabuľke `sessions` sa
uchováva **len BLAKE3 hash** tokena (nikdy nie token), expirácia ~30 dní
(`SESSION_TTL_SECS`), pri každom vydaní sa premazávajú expirované. Token
**nikdy nevzniká v logoch** (ani pri chybách). Deviácia od doslovného
znenia zadania („hash v MetaStore“): session má vlastnú tabuľku —
podstatou je hashované uchovanie, nie konkrétny KV kľúč.

| koncovka | význam |
|---|---|
| `POST /register` | `{username, password, device_pub, device_label?}` → 201 `{account_id, session_token, device}`; duplicitné meno → **409**, krátke heslo/zlý kľúč → 400 |
| `POST /login` | `{username, password}` → 200 `{account_id, session_token}`; zlé heslo **aj** neexistujúci účet → **401** (rovnaká práca v Argone aj text chyby — netajíme existenciu) |
| `POST /devices` | atest nového kľúča `{device_pub, label?, account_session?}`; token v tele alebo `Authorization: Bearer`; duplicitný kľúč → 409, zlý token → 401 |
| `GET /devices` | zoznam zariadení (revokované s `revoked_at` — história, D-26) |
| `DELETE /devices/{id}` | revokácia (idempotentná); cudzie id → 404 |

Schéma `user_version=2`: tabuľky `accounts`, `device_keys` (UNIQUE
`account_id,public_key` + parciálny index na aktívne), `sessions`; migrácia
z v1 je `ALTER TABLE records ADD COLUMN client_hash` + parciálny UNIQUE
index (vid' B5). Testy kryjú kritériá B4: dve zariadenia jedného účtu
(oba podpisy overiteľné), revokovaný kľúč sa odmietne pri append, zlé
heslo 401, duplicitný username 409.

**`node_id` (D-27):** do správy root kľúča (C fáza) je `node_id`
odvodený z **operačného pečiatkovacieho kľúča** — 32 B seed sa generuje
raz pri prvej migrácii a perzistuje v `meta` pod `node_key_seed`;
`node_id = verejný kľúč`. Pri upgrade z B3 sa hodnota raz zmení (pole
`node_id` v `/node/info` ostáva, význam je stabilný od tohto release).

## B5 (MYHSN-7) — WebSocket sync (D-24, D-29)

`GET /ws` — vlastná tenká vrstva nad WSS: každá binárna správa je frame
z `core::wire` = **8B hlavička** `ver(1) | type(1) | channel(2) | len(4 BE)`
+ minicbor payload. Verzia je v hlavičke každého frame (D-22).

| typ | smer | payload |
|---|---|---|
| `Hello` (1) | klient → uzol | `[proto_min, proto_max, [caps], [[channel, epoch, seq], …]]` — watermark = najvyššia aplikovaná pozícia per kanál |
| `HelloAck` (2) | uzol → klient | `[verzia, [caps], [[channel, epoch], …]]` — caps uzla (`sync`) sú autorita protokolu |
| `Reject` (3) | uzol → klient | `[kod, dovod]`; kódy: 1 = verzia, 2 = handshake, 3 = record, 4 = protocol |
| `Ping` (4) | oboma smermi | heartbeat (protocol-level Ping/Pong rieši axum sám) |
| `Pong` (5) | uzol → klient | odpoveď na `Ping` (MsgType) |
| `Sync` (6) | oboma smermi | set-reconciliation (logika z B3); prenos cez WS je follow-up (F2) |
| `Record` (7) | klient → uzol → klienti | kanonické bajty obálky |
| `Ack` (8) | uzol → klient | `[finálny_hash, channel, epoch, seq]` |

Čísla v tabuľke sú presne `core::wire::MsgType` (B5.1 oprava MYHSN-19 —
predtým tu bolo `Record` 4 a `Sync`/`Pong` 5/7, čo nekorešpondovalo s kódom).

Relácia: klient pošle `Hello` (prvá správa, inak `Reject` kód 2; timeout
10 s). Nevyhovujúci rozsah verzií → `Reject` **kód 1** a zavretie. Potom
uzol **registroval reláciu pred catch-up dotazom** a dobehol chýbajúce:
pre každý watermark `RecordStore::range(channel, epoch, seq+1)` (limit
500/reláciu). Push a catch-up sa môžu prekryť — duplikát rieši
idempotentná aplikácia podľa hashu (D-29), strata nie je možná.

Klient posiela obálku s **placeholder stamp** (epocha/seq 0,
`signed_by_node` nuly, `stamp_sig = None`) — poradie predsa nemôže poznať
klient. Uzol: `Envelope::validate()` (body_hash + podpis autora), autor
musí byť **aktívny device key** inak `Reject` kód 3 (B4 brána — revokovaný
kľúč), `alloc_seq`, dosadí stamp, dopočíta `blind_hash` so soľou kanála
(klient ju nepozná, D-25), podpíše pečiatku operačným kľúčom a vloží.
`Ack` obsahuje **finálny hash** opečiatkovanej obálky.

**Idempotencia (kritérium c):** finálny hash závisí od poradia, ktoré
pridáva uzol — duplicitná správa by mala iný hash, preto uzol deduplikuje
podľa `client_hash = BLAKE3(prijatých bajtov)` (stĺpec `records.client_hash`,
parciálny UNIQUE). Rovnaká správa → `Ack` s pôvodnou pozíciou, nič sa
nepridá; pretek dvoch rovnakých správ rieši opätovný dotaz.

Bloby idú mimo WS cez HTTP (D-24) — koncovky `POST/GET /media` sú v B7
(MYHSN-9, D-33), vid' sekcia **B7** nižšie.
Integrné testy (`tests/ws_sync.rs`, skutočný axum server na ephemeral
porti + 2 WS klienti): push do 2 s, watermark catch-up presne chýbajúce,
idempotentný duplikát, `Hello` so zlou verziou → `Reject` kód 1,
revokovaný kľúč → `Reject` kód 3.

### B5.1 (MYHSN-19) — members lookup a WS logging

- **`GET /members`** (bez auth): `{members: [{public_key_hex, username}]}`
  pre všetky **atestované a nezrušené** device kľúče — jeden SQL dotaz
  (`device_keys` JOIN `accounts`, `revoked_at IS NULL`). Uzol tak apke dá
  mapu kľúč → meno a cudzie príspevky sa nezobrazujú ako odtlačok kľúča.
  Odpoveď obsahuje len verejné údaje (username je na uzle verejný, kľúč
  je verejný kľúč) — žiadne heslá, e-maily ani tokeny (GDPR minimum).
- **WS logging** (`ws.rs`): každá relácia loguje `ws pripojenie`,
  `ws hello` (rozsah verzií, caps, počet watermarkov), `ws reject`
  (kód + dôvod) a `ws disconnect` (dôvod ukončenia) na **INFO**; peer IP
  a počet dobehnutých záznamov na **DEBUG** (`RUST_LOG=debug`). V logoch
  nie je obsah správ ani tokeny — len anonymné id relácie a protokolové
  metadáta (IP je osobný údaj, preto len DEBUG). `main.rs` spúšťa server
  s `into_make_service_with_connect_info`, integrné testy bez neho —
  extractor `MaybePeer` s oboma variantami počíta.
- Tabuľka typov vyššie sedí s `wire.rs` (B5.1 oprava).

## B6 (MYHSN-8) — Mazanie: tombstone / hide / erase (D-30)

Mazanie nie je `DELETE FROM records`. Rozhodnutie **D-30** pozná tri
operácie s rôznym účinkom a všetci ich zapisujú **ako záznam logu** —
append-only platí aj pre mazanie (D-25), poradie má každý záznam svoje.

| kind | kto smie | účinok | čo ostane |
|---|---|---|---|
| `Tombstone(cieľ)` = 3 | **len autor** cieľa | cieľ zmizne z pohľadu na kanál | pozícia, autor, dôkaz že niečo bolo |
| `Hide(cieľ, dôvod)` = 4 | **ktokoľvek pre seba** | skryté len pre autora hide záznamu | cieľ pre ostatné, dôvod v zázname |
| `Erase(cieľ, dôvod)` = 5 | **len autor** cieľa | obsah cieľa sa **fyzicky** nahradí | **dôvod**, pozícia, autor; slepý hash → NIL |

Kde to je: pravidlá v `crates/node/src/deletion.rs`, fyzická náhrada obsahu
v `Store::insert_record_erasing`, čítací pohľad v `Store::visible_range`,
napojenie na WS vo `ws::process_record`. Jadro (`core::record`) drží len
formát — `Payload::{Tombstone, Hide, Erase}` a `Envelope::erased()`.

### Prečo sú pravidlá mimo `ws.rs`

Overenie cieľa vyžaduje **náhľad do logu** (existuje cieľ, je z tohto
kanála, je jeho autora podpisovateľ). To nie je protokolová vec, preto
`deletion::evaluate(store, env) -> Effect`. Volá sa **pred** `alloc_seq`,
aby odmietnutý záznam **nealokoval poradie** — inak by každé zamietnuté
mazanie zanechalo dieru v poradí kanála a dohľad nad logom by ochabol.
Test to meria: po odmietnutom cudzom tombstone má ďalší príspevok `seq 3`,
nie `seq 4`.

Poradie krokov v `process_record` nie je náhoda: idempotencia podľa
`client_hash` ide **pred** vyhodnotenie mazania. Inak by opakovaný erase
narazil na „cieľ je už vymazaný“ a klient by dostal `Reject` namiesto
idempotentného `Ack` (D-29).

### Erase zanechá v logu dva záznamy — a ako sa odlíšia

Jeden erase zapíše:

1. **akciu** erase — nový záznam na konci logu, podpísaný autorom,
   `target` = hash príspevku, **ako ho pozná klient**;
2. **vymenený rad** cieľa na pôvodnej pozícii — `kind = Erase`,
   `body_sig = NIL`, `target` = **ten istý hash**.

Rozlišovací znak je **NIL podpis autora**: `Envelope::erased()` ho nastavuje
a uzol ho pri výmene obsahu nedopĺňa (niet čo podpisovať), zatiaľ čo akciu
vždy podpisuje autor. `deletion::evaluate` preto **odmieta** erase záznam od
klienta s NIL podpisom — NIL je vyhradený uzlu. Bez tohto pravidla by
klient mohol do logu vložiť záznam, ktorý sa tvári ako vymenený rad.

`target` je **hash záznamu**, nie hash jeho obsahu: klient pozná hash
záznamu (je to id príspevku v jeho cache) a oba záznamy musia mierit na
tú istú hodnotu, inak by sa v pohľade nespárujali a čitateľ by videl
placeholder dvakrát. Hash obsahu je práve to, čo erase ruší.

Fyzická náhrada prebieha v **tej istej transakcii** ako vloženie akcie:
ak by sa nepodarila, rollback zmaže aj akciu. Log teda nikdy neobsahuje
dôvod so zachovaným obsahom — a to je kritérium B6.

### Čítací pohľad (`visible_range`)

`RecordStore::range` ostáva **surový log** (zmluva jadra, D-29). WS catch-up
aj `GET /channels/{id}/records` čítajú `visible_range`, ktorý v jednom
scane vyhodnotí mazacie záznamy:

* tombstone → cieľ **nevráti** (voľba „vrátiť cieľ s priznaným tombstonom“
  by apke vnútila dva stavy tam, kde D-30 hovorí „príspevok je preč“);
* hide → nevráti cieľ, len ak sa `reader` rovná autorovi hide;
* erase → vráti vymenený rad a **vynechá akciu**, ak je vymenený rad v
  tomto scane. Akciu **nevynechá** pre čitateľa so watermarkom nad cieľom:
  ten vymenený rad nevidí a práve z akcie vie, ktorý príspevok má zmazať
  zo svojej cache.

`limit` platí pred filtrovaním, takže vrátený počet môže byť menší — nie je
to stránovacia zmluva (stránovanie prinesie `Sync`, F2); limit je len
ochrana pred veľkým result-setom.

### REST na nahliadnutie (diagnostika, bez auth)

* `GET /records/{hash}` — **surový log**: druh, autor, pozícia a dekódovaný
  obsah. Po erase vráti **404** pre starý hash, lebo identifikátor je
  BLAKE3 bajtov a tie sa zmenili (D-25).
* `GET /channels/{id}/records?from_epoch=&from_seq=&limit=&reader=<hex>` —
  **čítací pohľad**: čo čitateľ naozaj vidí.

Obe vracajú dekódovaný obsah a nemajú autentizáciu (ako `GET /members`) —
na pilotnom LAN uzle zámer (testy, diagnostika), na verejnom uzle by obsah
patril za session token.

### Obmedzenia MVP (vedomé, nie chyba)

* **Koncept admina/operátora nie je.** Pôvodné D-30 rozdeľuje hide
  (moderátor) a erase (operátor, podpis uzla). Účty v B4 **nemajú role** a
  žiadny admin kľúč neexistuje, preto erase podpisuje **autor** a uzol k
  tomu nepridáva vlastný podpis. Dôsledok: erase dnes nespĺňa GDPR
  „záväzný príkaz operátora“ v plnom zmysle — je to erase na žiadosť
  autora (`EraseReason::AuthorRequest`). Keď role pribudnú, stačí v
  `deletion::evaluate` povoliť erase aj kľúču s rolí; formát záznamu sa
  meniť nemusí.
* **Hide nefiltruje na WS per-reader.** WS relácia nemá autentizáciu (B5),
  uzol nevie, kto číta. Hide záznam sa teda posiela a **filter aplikuje
  klient** vo svojej cache. REST filter existuje cez `?reader=`.
* **Prune (naplánovaný erase) nie je.** D-30 ho definuje ako erase s
  odloženým vykonaním; bez plánovača v MVP ho nechávame otvorený.
* **Replikácia erase medzi uzlami** (záväznosť pre repliky a cache) je
  úloha I2/I3 — fyzická náhrada je lokálna a atomická, prenos medzi uzlami
  zatestovaný nie je.

### Testy B6

Unit (`core::record`): roundtrip všetkých kindov, kódy dôvodov, **zpätná
kompatibilita** erase payloadu arity 3 (starší klient číta nový záznam),
`erased()` podľa D-30.
Unit (`node::deletion`): tombstone vlastný ✓ / cudzí ✗, erase vyžaduje
autora, hide smie ktokoľvek, neznámy cieľ, krížový kanál, klamanie o druhu
cieľa, dvojitý erase (cez starý hash → `TargetMissing`, cez nový →
`AlreadyErased`).
Unit (`node::store`): tombstone zmizne z pohľadu ale nie zo surového logu,
hide len pre jeho autora, **erase fyzicky vymení bajty** (priamy SQL dotaz
na `raw`, `author`, `blind_hash`, pozíciu) a dôvod ostáva, akcia erase sa
neopakuje, duplikát mazacieho záznamu je idempotentný.
Unit (`node::api`): `GET /records/{hash}` obsah + 404 po erase,
`GET /channels/{id}/records` s tombstone a per-reader hide.
Integrné (`tests/ws_sync.rs`, skutočný server + WS klienti): tombstone
zmizne príspevok z dobehnutia a klient nad cieľom dostane tombstone,
cudzí tombstone → `Reject` **bez alokácie poradia**, duplikát → `Ack`,
erase zmizne obsah a ponechá dôvod (merané pred/after na bajtoch),
klient nad cieľom dostane akciu erase s hashom zo svojej cache,
hide sa akceptuje od kohokoľvek a filtruje len pre jeho autora.

## B7 (MYHSN-9) — Médium: upload/stiahnutie s kvótami, pominuteľné bloby (D-33, D-24, D-25)

Obrázky a prílohy **nie sú** súčasťou append-only logu — keby boli, nedali by
sa zmysť (rozhodnutie **D-33**). Preto žijú vedľa logu: **súbory na disku**
v `<data_dir>/media` a **metadáta** (veľkosť, hash, expirácia) v SQLite
tabuľke `media` (migrácia **v3**). Do logu sa dostane len *referencia* —
`Payload::ChatMsg` má nepovinné pole `media` (hex id blobu + BLAKE3 hash +
rozmer náhľadu), ktoré si klient stiahne z `GET /media/{id}`. Blob sa prenáša
cez **HTTP**, nie cez WS (D-24).

**Formát referencie v tele správy** (`core::record::Payload::ChatMsg`):
- textová správa: `[2, text]` — arity **2**, nezmenené oproti B2 (spätná
  kompatibilita, golden vektory platia),
- správa s obrázkom: `[2, text, media_id_hex, hash_hex, width, height]` —
  arity **6**; dekóder akceptuje obe (2 aj 6), iná arita je `BadCbor`.
  Prvý prvok je vždy druh `2` (ChatMsg), takže obálka je validná pre uzol.

**Koncovky:**

| koncovka | význam |
| --- | --- |
| `POST /media` | telo = **raw bajty** (`application/octet-stream`), hlavička `Authorization: Bearer <session token>`. Overí reláciu → **401** bez nej; veľkosť → **413** nad `max_upload_bytes`; kvótu na účet → **507 Insufficient Storage** nad `max_bytes_per_account`; inak uloží súbor + záznam a vráti **201** `{id, url, expires_at, hash}`. `id` = hex 32 náhodných bajtov (neuhádnuiteľné), `hash` = BLAKE3 obsahu. |
| `GET /media/{id}` | **bez auth** (id je neuhádnuiteľné) → **200** s bajtami a `Content-Type: application/octet-stream`; **404** neznáme/nesprávne id, po exspirácii, alebo ak súbor chýba (vtedy zmaze aj osirelý záznam). |

**Kódy:** `401` neplatná relácia · `413` jeden upload nad limit · **`507`**
kvota účtu vyčerpaná (zdokumentovaná voľba: 507 je registrovaná IANA kód pre
„server sa nezmestí“/WebDAV kvótu; 429 je rate-limit a 452 nie je štandard) ·
`404` expirované/neznáme.

**Kvóty a retention (D-33)** nastavuje **operátor v TOML** — sekcia `[media]`
je **voliteľná**, jej absencia = defaulty (spätná kompatibilita starého
`node.toml`):

```toml
[media]
max_upload_bytes      = 8388608    # 8 MiB — strop jedného uploadu
max_bytes_per_account = 209715200  # 200 MiB — súčet neexpirovaných blobov na účet
ephemeral_ttl_secs    = 86400      # 1 deň — TTL pominuteľného blobu
# dir = "./data/media"             # voliteľné; inak <data_dir>/media
```

**Lazy cleanup (D-33):** expirované záznamy a ich súbory mažeme **pri každom
uploade aj stiahnutí** — v tejto fáze bez cronu/dedicovaného vlákna. Expirácia
je teda viazaná na prevádzku uzla (rovnaká filozofia ako Retention erase,
`EraseReason::Retention`). Testy kryjú: roundtrip (zhodný hash + bajty),
`413` nad limitom, `507` pri kvote, expiráciu → `404` **a zmazaný súbor**,
`401` bez auth, `404` neznáme id, a konfiguráciu (defaulty pri absencii
sekcie, `dir` override).

## Overené verzie (crates.io, živý `cargo add` + Cargo.lock, 2026-11-11)

| Crate | Verzia v Cargo.lock | Poznámka |
|---|---|---|
| axum | 0.8.9 | presne podľa D-24, feature `ws` |
| axum-server | 0.9.2 | presne podľa D-24, feature `tls-rustls` (TLS sa zapne v I1/B5) |
| tokio | 1.54.1 | 1.x podľa zadania |
| tokio-tungstenite | 0.30.0 | priama závislosť podľa D-24; axum 0.8.9 má interne 0.29.0 (transitive, koexistujú) |
| rustls | 0.23.46 | 0.23 podľa D-24 |
| minicbor | 2.3.1 | presne podľa D-24 — **vyžaduje explicitne feature `std`/`alloc`** (od 2.x nemá default features) |
| rusqlite | 0.40.2 | feature `bundled` (kompiluje SQLite v C, potrebný `cc`) — **len v node** |
| toml | 1.2.1 | čítanie konfigurácie |
| tracing / tracing-subscriber | 0.1.44 / 0.3.23 | logging, feature `env-filter` |
| argon2 | 0.5.3 | podľa zadania 0.5 — B4 login beží na tejto rade (0.6 by bola migrácia PHC pravidiel navyše; ponechané zámerne) |
| rand_core | 0.6.4 | **B4:** OS RNG pre soľ a session tokeny — `argon2`-ov `rand` feature spúšťa len `password-hash/rand_core` bez `getrandom`, OsRng sa pridáva priamo (verzia sedí na strom argon2) |
| futures | 0.3 | dev-dependency: `split()` WS klientov v integrných testoch B5 |
| ed25519-dalek | 2.2.0 | 2.x podľa zadania — **v jadre** (výpočet, nie I/O) |
| blake3 | 1.8.7 | 1.x podľa zadania |
| serde | 1.0.229 | derive, potrebné pre deserializáciu TOML configu |
| serde_json | 1.0.154 | JSON telá REST odpovedí (B3) — len v node |

Odchýlky od zadania: žiadne verzie neboli potrebné meniť — všetky požadované
presné verzie (axum 0.8.9, axum-server 0.9.2, tokio-tungstenite 0.30.0,
minicbor 2.3.1, rustls 0.23, argon2 0.5, ed25519-dalek 2, blake3 1) existujú
na crates.io a boli overené živým `cargo add`. Doplnené veci: `serde`
(nevyhnutné pre TOML), features `std` pri minicbor (bez nich sa v 2.x nedá
kódovať do `Vec<u8>`), `serde_json` pre REST.

## sans-IO kontrola (D-29)

Jadro `core` nesmie obsahovať tokio/axum/rusqlite. Overené 2026-11-12
(`cargo tree -p core`, default features aj `--features client,server`):

```
core v0.1.0
├── blake3 v1.8.7
├── ed25519-dalek v2.2.0
└── minicbor v2.3.1
```

`grep -cE 'tokio|axum|rusqlite'` nad oboma stromami → **0**. D-29 zakazuje v
jadre I/O rámce (tokio/axum/rusqlite), **kryptografiu nie** — BLAKE3 a
ed25519 sú čisté výpočty, preto `ed25519-dalek` pribudol do `core` (B2) a
`rusqlite` ostáva výhradne v `node`.

**Pomenovanie crate `core`:** balík sa volá `core` (per špecifikácia,
`cargo tree -p core` funguje). V `crates/node` je importovaný pod aliasom
`myhsn_core` (`myhsn_core = { package = "core", path = "../core" }`), lebo
dependency named `core` shadowuje sysroot crate `core` v absolute cestách
makier (napr. `#[tokio::main]` emituje `::core::future::…`).

## Testy

`cargo test --workspace` → **246 passed / 0 failed / 2 ignored**
(baseline pred B2 bolo 12, pred B4/B5 61, pred B5.1 95, pred B7 97, pred B6 106,
pred F14a 126 — namerané 2026-11-18 s rustc 1.100.0):

| crate | testy | čo kryjú |
|---|---|---|
| `core` | 62 (+1 ignored dump) | golden vektory G1–G7, deterministickosť CBOR (rovnaká obálka → rovnaké bajty), podpis overí **len** kľúč autora, zmena bajtu v tele rozbije hash aj podpis, slepý hash bez soli nezistí obsah, tombstone/hide/erase (D-30), odmietnutie neznámych verzií a tagov, alokátor seq 1-2-3, obnova epochy, reconciliation (missing/mismatched/extra/stale_epoch), **B4** Account/DeviceKey (Argon2 hash nie je heslo, aktívny-do-revokácie, dva kľúče overia), **B5 wire** framing: Hello s watermarkami + legacy 3-polové Hello, HelloAck epochy, Reject kódy, Ack, odmietnutie krátkych polí, **B7** `ChatMsg` s mediom: roundtrip arity 6 + **spätná kompatibilita** (text = arity 2, prefix `0x82 0x02`, staré telo → `media: None`), **B6** erase payload arity 4 + **zpätná kompatibilita** (staré 3-polové telo → `target_kind = Post`, cudzí kód druhu → chyba), `erased()` podľa D-30 (obsah preč, dôvod, NIL slepý hash aj podpis, cieľ = hash záznamu) |
| `node` (unit) | 164 (+1 ignored) | schéma **v3** + WAL + **migrácia z v1 s dátami**, append → range, idempotentný append, kolízia pozície, meta KV, perzistencia operačného kľúča a `node_id`, kanály, **B3a/b/c** seq/epochy/reconciliation, REST handlery, **B4** Argon2id roundtrip + parametre v PHC, soľ náhodná, token hash stabilný, účty/duplicitné meno 409, dva device kľúče + revokácia, session tokeny hashované s expiráciou, `client_hash` idempotentný insert, register/login/devices handlery (401 zlé heslo, 409 duplicitné meno, atest bez tokena 401), **B5.1** `GET /members`: 2 účty → obaja, 2. zariadenie → 2 záznamy, **revokovaný kľúč zmizne**, prázdny uzol → prázdne pole, **B7 media** (`media.rs`, router cez `tower::oneshot`): roundtrip upload→download so zhodným BLAKE3 hashom a bajtmi, `413` nad `max_upload_bytes`, `507` pri kvote účtu, **expirácia → `404` a zmazaný súbor** (lazy cleanup), `401` bez relácie, `404` neznáme id, konfigurácia `[media]` (defaulty pri absencii sekcie, `dir` override), **B6 mazanie** `deletion::evaluate` (vlastný autor ✓, cudzí ✗, neznámy cieľ, krížový kanál, klamanie o druhu cieľa, dvojitý erase cez starý aj nový hash), `visible_range` (tombstone zmizne z pohľadu ale nie zo surového logu, hide len pre jeho autora, erase akcia sa neopakuje), **erase fyzicky vymení bajty** — priamy SQL na `raw`/`author`/`blind_hash`/pozíciu, dôvod ostáva, duplikát mazacieho záznamu idempotentný, `GET /records/{hash}` obsah + 404 po erase, `GET /channels/{id}/records` s tombstone a per-reader hide |
| `node` (integrné `tests/ws_sync.rs`) | 11 | **skutočný server + 2 WS klienti**: (a) A appendne → B push do 2 s so zhodným finálnym hashom a overiteľnou pečiatkou voči `node_id`, (b) offline klient s watermarkom dostane **presne chýbajúce** (2,3,4) a potom ticho, (c) duplicitný append → identický `Ack`, v logu 1 záznam, (d) `Hello` proto 5..9 → `Reject` kód 1, (e) **revokovaný kľúč → `Reject` kód 3** (pred revokáciou ten istý prešiel), neznámy kľúč taktiež, **B6** tombstone zmizne príspevok z dobehnutia a klient nad cieľom dostane tombstone, **cudzí tombstone → `Reject` bez alokácie `node_seq`** (ďalší záznam má seq 3), duplicitný tombstone → `Ack` bez nového radu, erase zmizne obsah a ponechá dôvod (merané pred/after na bajtoch z úložne), klient nad cieľom dostane **akciu** erase s hashom zo svojej cache, hide akceptovaný od kohokoľvek a v pohľade filtrovaný len pre jeho autora |

| `node` (integrné `tests/cors_http.rs`) | 9 | **skutočný HTTP router**: preflight `OPTIONS` s `authorization, content-type` → ACAO presného povoleného originu, cudzí origin **bez** ACAO, 404 aj 401 s ACAO (aby prehliadač nenahlásil CORS namiesto skutočného stavu), WS handshake `Origin` 101/101/101/403 (povolený / chýba / vlastný host / cudzí) a dôkaz, že `[http]` z TOML sa skutočne číta (explicitný zoznam nahradí defaulty) |

Ignorovaný test `dump_golden_vectors` netestuje — vypisuje hodnoty pre
revíziu a nezávislé overenie.

## Plán nadväznosti (z implementačného plánu)

- **B2** ✅ úloža (rusqlite implementácia traitov z `storage`), obálka do bodu, golden vektory
- **B3** ✅ poradie per kanál + `node_epoch` pri obnove
- **B4** ✅ identity: device keys, atesty, Argon2id login, revokácia;
  `node_id` dočasne z operačného kľúča (root kľúč a jeho správa: C fáza)
- **B5** ✅ WS sync: Hello/HelloAck/Reject, watermark range dobehnutie,
  append/push/Ack, idempotencia po `client_hash`; `snow` handshake (D-24)
  a `Sync` správa cez WS sú follow-up (F2), TLS (axum-server) zapne I1
- **B5.1** ✅ members lookup (`GET /members`), WS logging relácie,
  README tabuľka typov zosúladená s `wire.rs` (MYHSN-19)
- **B6** ✅ mazanie v logu (MYHSN-8, **D-30**): tombstone/hide/erase sa
  aplikujú do čítacieho pohľadu (`visible_range`), erase **fyzicky** nahradí
  obsah a ponechá dôvod; otvorené ostávajú role admina/operátora a `prune`
  (naplánovaný erase) — detaily v sekcii **B6** vyššie
- **B7** ✅ kvóty/retention (D-33): `POST/GET /media`, pominuteľné bloby
  mimo logu s TTL, per-účet kvóty, TOML `[media]`, lazy cleanup (MYHSN-9)
- **I1** build a deploy na pilotný uzol (port 8123) (healthz už existuje)

## Pravidlá

- Slovenské komentáre a dokumentácia, kódové identifikátory anglicky.
- Žiadne tajné v repozitári (tokeny/kľúce idú cez env, nie do TOML).
- Rozhodnutia D-24…D-33 (wiki *11 Rozhodnutia ADR*) sú záväzné.

## Hovory (F10a, LiveKit SFU)

Sekcia `[calls]` v `node.toml` (viď `config/node.toml`), default `mode = "off"`.

- `managed`: uzol stiahne `livekit-server` 1.13.11 z GitHub release, overí
  **SHA-256 voči pinu v kóde** (`calls/manager.rs`, `RELEASES`), nainštaluje
  do `<data_dir>/addons/livekit/1.13.11/`, vygeneruje `livekit.yaml` (0600)
  a drží ho ako potomka: health `GET http://127.0.0.1:7880/` každých 5 s,
  reštart s backoffom 1→60 s, logy do `tracing` targetu `livekit`
  (`RUST_LOG=info,livekit=warn` ich stíši). Linux: `PR_SET_PDEATHSIG`,
  Windows: Job Object — LiveKit nikdy neprežije uzol.
- `external`: `livekit_url` + `api_key` + `api_secret`; webhook URL
  `…/calls/webhook` treba nastaviť v LiveKite ručne.

Koncovky: `POST /calls/token` (Bearer session, telo `{channel, device_pub?}`
→ `{url, token, room, can_moderate}`; token TTL 60 s), `GET /calls/health`,
`POST /calls/webhook` (LiveKit JWT podpis + SHA-256 tela; nečlena uzol
vyhodí cez `RemoveParticipant`), `POST /calls/room/ensure`,
`POST /calls/kick` (F10d, viď nižšie). Revokácia
zariadenia (`DELETE /devices/{id}`) ho vyhodí zo všetkých hovorov.

### Moderátorský kick (F10d, MYHSN-39)

`POST /calls/kick` s Bearer session a telom `{room, identity}` — `room` je
presne to, čo klient dostal v `POST /calls/token` (hex id kanála),
`identity` je identita účastníka `D<base32>` zo zoznamu v hovore. Kick ide
cez `TokenService::kick` (`RemoveParticipant`), LiveKit tým participantovi
pošle `RoomDisconnected` — obe strany uvidia odchod do ~1 s.

**Oprávnenie je konfigurácia uzla, nie dátový model.** `[calls] moderators =
["anna"]` v `node.toml`. Prečo: uzol v MVP **nemá role** —
[`deletion.rs`](crates/node/src/calls/mod.rs) to povie narovinu („koncept
admina/operátora uzla v MVP nie je“) a `Channel` v `crates/core` nemá pole
owner (a `crates/core` sa F10d nesmie dotknúť). Jediný oprávnený zdroj
rozhodnutia je teda operátor uzla. Je to zámerne **per uzol**: moderátor na
jednom uzle nie je moderátor na druhom, a presne to po F5 (viac uzlov)
chceme. Prázdny zoznam = nikto nemoderuje (403 pre každého).

Rebríček: 503 (hovory vypnuté) → 400 (zlý tvar `room`/`identity`) → 401
(relácia) → 404 (kanál neexistuje) → 403 (nie moderátor) → Server API.
Klient sa o práve dozvie z poľa `can_moderate` v `POST /calls/token` —
nie z `GET /calls/health`, ktorá je **verejná** bez authentifikácie a
zoznam moderátorov by prezradila komukoľvek. Obrana je na oboch koncoch:
apka tlačidlo tají, uzol aj tak vráti 403 (klient môže byť starý).

Integrný test so skutočnou binárkou (sieť, porty 7880–7882):
`cargo test -p node -- --ignored livekit_manager_real`.

### Známe obmedzenia F10a.1 (vedome mimo rozsah tohto MR)

- **ACL kanálov ešte nie je.** Brána členstva je jediná funkcia
  [`calls::device_may_join`](crates/node/src/calls/mod.rs) a dnes je totožná s
  bránou WS append: kanál musí existovať a zariadenie musí byť atestované a
  nezrušené. Keď vznikne členstvo per kanál, mení sa **len** táto funkcia —
  mint tokena aj webhook ju volajú rovnako, takže sa sprísnia naraz.
- **Uzol za NAT/Docker musí nastaviť `node_ip`.** `rtc.use_external_ip`
  ostáva `false` (rozhodnutie z doc 1003: CGNAT mimo rozsah, verejné IP
  zisťujeme explicitne). V `managed` režime preto nastav `[calls] node_ip`
  na IP, ktorú klienti skutočne vidia, a publikuj porty **7880/TCP,
  7881/TCP, 7882/UDP** — bez toho sa WebRTC media nenadviažu, hoci signál
  a token prejdú. `use_external_ip` (auto-detekcia verejnej IP) je k
  dispozícii v `render_config`, len ho nikto nezapína.
- **Windows: celý uzol sa cross-kompilovať nedá** (rusqlite + ring vyžadujú
  mingw/nasm toolchain). Kód `calls` pre Windows (Job Object, rozbalenie
  `.zip`) je preložený pre `x86_64-pc-windows-gnu` bez varovaní, ale na
  Windows **nebol spustený**. Ani ARM LiveKit neboli na HW otestované.
- **macOS nemá LiveKit server binárku** (release assety sú len linux +
  windows) → `managed` na macOS nie je podporovaný, dev použitie ide cez
  Docker (rozhodnutie z doc 1003).
- **Token TTL 60 s je vstupenka, nie relácia.** LiveKit si spojenie sám
  obnovuje, ale po opakovanom pripojení si klient musí vypýtať nový token
  (`POST /calls/token`) — rieši to F10b (klientská vrstva).
- **`POST /calls/room/ensure` overí session a existenciu kanála, nie
  členstvo** — vytvorenie prázdnej miestnosti je neškodné (po
  `empty_timeout` 300 s zmizne) a skutočné dvere do hovoru drží
  `POST /calls/token` + webhook.

## Webový klient: CORS a kontrola `Origin` (F12d, MYHSN-47)

Webová apka (F12) beží na inej adrese než uzol — `http://192.0.2.10:8080`
proti `http://192.0.2.20:8123` — teda **cross-origin**. Bez CORS
hlavičky prehliadač zahodí každú odpoveď (`ERR_FAILED`), hoci uzol odpovedal
200. Sekcia `[http]` v `node.toml` je **voliteľná**: bez nej platia
defaulty z `cors::default_allowed_origins` (dva pilotné webové originy +
tri dočasné dev-only, ktoré sa majú s TLS/doménou vymazať).

```toml
[http]
allowed_origins = ["http://192.0.2.10:8080", "http://web.example.com:8080"]
```

`allowed_origins` sú **presné** reťazce originu (`scheme://host:port`, bez
koncového `/`); explicitný zoznam defaulty **nahradí**, nie rozšíri. Uzol z
neho robí dve nezávislé veci:

1. **REST/HTTP — `CorsLayer`** (`tower-http` 0.6, feature `cors`; bol v
   strome už transitive, `Cargo.lock` preto pribudol o jeden riadok).
   `AllowOrigin::list` → ACAO presne toho originu (nikdy `*`), metódy
   `GET/POST/PUT/PATCH/DELETE/OPTIONS`, hlavičky `authorization` +
   `content-type`, `allow_credentials(false)` (autentifikácia je Bearer
   token, nie cookie), `max_age` 3600 s a `Vary: Origin` automaticky.
   Preflight je nevyhnutný: `authorization` ani `application/json` nie sú
   CORS-safelisted, takže bez neho by apka vôbec nevolala.
   **`CorsLayer` je posledná `.layer()`** v `build_router_with_calls`, teda
   najvrchnejšia: na `OPTIONS` (s `Access-Control-Request-Method`) odpovie
   sama skôr, než sa vôbec routuje, a na každú ďalšiu odpoveď — vrátane
   **401 a 404** — prilepí ACAO. Keby bola pod routami, prehliadač by pri
   neplatnom toku nahlásil CORS chybu namiesto 401.
2. **WebSocket — vlastná kontrola `Origin`** (`ws::ws_handler`,
   `cors::check_ws_origin`). WS **nepodlieha** CORS špecifikácii (žiadny
   preflight, uzol môže odpovedať bez `Access-Control-Allow-*` — overené
   sondou vo F12a), ale bez kontroly hrozí **CSWSH**: identita je až v
   `Hello` frame, nie v hlavičke, takže hociktorá stránka mohla otvoriť WS
   a posielať `Record`-y. Pravidlá: `Origin` chýba → **povoliť** (natívny
   `dart:io` klient a `lk` bot ho neposielajú — overené sondou
   `origin_probe.dart`, handshake obsahuje len `user-agent`, `connection`,
   `cache-control`, `accept-encoding`, `sec-websocket-*`, `host`,
   `upgrade`); `Origin` je v zozname → povoliť; `Origin` sa rovná
   vlastnému hostovi (`http://`/`https://` + `Host` hlavička) → povoliť,
   aby apka nasadená priamo na uzle fungovala; inak **403** ešte pred
   `on_upgrade` (žiadny frame sa neprečíta) + WARN do logu.

Testy: unit v `cors.rs` (TOML spätná kompatibilita, normalizácia, matica
`Origin`), integrné v `tests/cors_http.rs` (preflight s `authorization,
content-type` → ACAO presného originu, cudzí origin bez ACAO, 404/401 s
ACAO, WS 101/101/101/403, a dôkaz, že `[http]` sa skutočne číta).

## Role a registrácia (F14a, MYHSN-56)

Trojurové role (`user` / `moderator` / `admin`) + bitmask práv moderátora,
politika registrácie a jednorazové pozvánky. Materializovaný stav je v
stĺpcoch `accounts` (migrácia V5), **audit každej zmeny je obálka kind 6
(`GrantRole`) / 7 (`RevokeRole`) v systémovom kanáli** — stav aj audit v
jednej transakcii, audit píše uzol sám (author = operačný kľúč, `by`/
`by_device` v tele; device kľúč admina neopustí zariadenie, D-26).

**Politika** (`[auth] registration_policy`, default `open` — starý
`node.toml` sa správa identicky): `open` | `invite_only` | `admin_approved`.
Efektívna politika = runtime override z `PUT /admin/settings` → TOML →
default. Prvý admin: bez `bootstrap_admin` prvý registrovaný; s ním len
zhodné meno (aj pri štarte, ak účet už existuje). Na uzle bez admina
kandidát prejde aj bez pozvánky (inak by `invite_only` nikto neodomykal).

**API** (chyby s strojovým kódom v JSON `{"error","code"}`):
- `POST /register` + voliteľné `invite`; `invite_only` bez → 403
  `invite_required`, neplatná → 400 `invite_invalid`, `admin_approved` →
  403 `account_pending` (účet vznikne, bez tokena);
- `POST /login` pending → 403 `account_pending`; `/me` a `/login` vracajú
  `role`/`perms`; `GET /node/info` + `has_admin`, `system_channel`
  (systémový kanál nie je v zozname kanálov);
- `POST /admin/roles` `{account: meno|hex id, role, perms?}` /
  `{account, revoke:true}` — len admin (403 `admin_required`), perms len
  moderator (400), neznáme bity 400, posledný admin 409 `last_admin`;
  grant schváli pending účet;
- `DELETE /admin/users/{id}` — reject len pending účtu (400 `not_pending`);
- `GET/PUT/DELETE /admin/settings` — politika + `source` (meta|config);
- `GET/POST /invites`, `DELETE /invites/{id}` — admin alebo moderator s
  bitom `INVITE_USERS`; token single-use, v DB len BLAKE3 hash.

**Bitmaska práv** (`myhsn_core::roles`): `MODERATE_CHANNELS=1<<0`,
`DELETE_POSTS=1<<1`, `INVITE_USERS=1<<2`, `MUTE_ACCOUNT=1<<3`,
`MANAGE_CHANNELS=1<<4`. Vo F14a sa vynucuje len `INVITE_USERS` (pozvánky);
zvyšné bity sú deklaratívne pre nadväzujúce funkcie. Admin má kanonicky
`perms = 0` (má všetko).

**WS kompatibilita (viazaná):** stará apka neznámy `MsgType` zahodí a
reláciu ukončí — preto cap `"roles"` v `Hello.caps`:
- `Hello` + voliteľný 5. prvok (session token hex), `HelloAck` + voliteľný
  4. prvok `[role, perms]` — len klientom s capom a platným tokenom;
- `RoleUpdate` (MsgType 9) a audity zo systémového kanála idú **len**
  reláciám s capom; staré relácie systémový kanál nevidia ani v epochách;
- externý klient nemôže appendovať do systémového kanála (402→`Reject`)
  ani mimoň poslať kind 6/7.

`[calls] moderators` (F10d) ostáva zachované — kick hovorov sa riadi
stále zoznamom z konfigu, nie rolami.

Testy: unit `core::roles` + `core::wire` (roundtripy 3/4/5-prvkových
správ), `store.rs` (atómová registrácia, single-use pozvánky, invariant
posledného admina, audit v logu), `api.rs` (matica politík a kódov chýb,
grant/revoke, viditeľnosť pozvánok), integrný `tests/ws_sync.rs`
(gating starý vs. roles klient + `RoleUpdate` push po REST grante).

## Interné odkazy v kóde a dokumentácii

- `MYHSN-##` sú **interné čísla úloh** nášho trackeru (Jira). Nie sú verejne čitateľné —
  prezrádzajú len to, ktorá funkcia čo riešila; text úlohy dostupný na vyžiadanie.
- `D-xx` (napr. D-25, D-30, D-31) a „doc NNNN" sú odkazy na **interné záznamy
  rozhodnutí (ADR)**, ktoré zverejnené nie sú. Kód ich cituje preto, aby odôvodnil,
  prečo niečo robí práve tak — správanie sa dá odvodiť z testov.
- `F2`, `F10a`, `F12d`, `F14a` … sú označenia **funkčných celkov** z nášho plánu.

## Licencia

**Backend je pod licenciou [FSL 1.1](https://fsl.software/) — Functional Source
License, Version 1.1, ALv2 Future License** (skratka `FSL-1.1-ALv2`, budúca
licencia Apache-2.0). Plný text: [LICENSE.md](LICENSE.md).

Čo to znamená po slovensky:

- **slobodne** stiahnuť, zostaviť, upravovať a prevádzkovať — pre seba, rodinu,
  spolok, školu aj **firmu pre vlastné potreby**;
- **nesmieš** z toho robiť **konkurenčnú platenú službu** (napríklad predávať
  hostované uzly MyHood treťím stranám);
- každá verzia sa **2 roky po vydaní** automaticky stáva voľnou
  licenciou **Apache-2.0** (to je zabudovaná súčasť FSL 1.1, nie naša veta).

In English: you may use, build, modify and run this backend for yourself, your
family, your club or your own company at no cost; you may not offer it to others
as a competing commercial product or service. Every release becomes
Apache-2.0 on its second anniversary.

- Príspevky od tretích strán prijímame **len s CLA** (contributor license
  agreement), aby ich majiteľ projektu vedel naložiť aj do budúceho licencovania.
- `THIRD_PARTY_NOTICES` (zoznam licencií všetkých knižníc a NOTICE súborov)
  zatiaľ v repozitári nie je — pripravujeme ho v úlohe F16c. Všetky priame
  závislosti sú permisívne (MIT / Apache-2.0 / BSD / ISC / BlueOak / public
  domain), takže s FSL sú kompatibilné.
- `/myhsn-node` crate-y z tohto workspace **neverejňujeme** na crates.io
  (`publish = false`); distribúcia je zo zdrojákov alebo binárky uzla.
