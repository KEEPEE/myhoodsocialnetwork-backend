//! Aplikačná vrstva mazacích kindov (B6, MYHSN-8, rozhodnutie **D-30**).
//!
//! Core (B2) už umel *formát* troch druhov mazania — `RecordKind::Tombstone`,
//! `Hide`, `Erase` a pohľad [`myhsn_core::record::Envelope::erased`]. Chýbala
//! vrstva, ktorá povie, **čo robia**, keď ich klient pošle uzlu. To je tento
//! modul: pravidlá, kto smie čo, plus výpočet účinku. Fyzickú náhradu obsahu
//! robí úložňa ([`crate::store::Store::insert_record_erasing`]) a čítací
//! pohľad ([`crate::store::Store::visible_range`]).
//!
//! ## Tri operácie, tri rôzne účinky (D-30)
//!
//! | kind | kto smie | čo to urobí |
//! |---|---|---|
//! | `Tombstone(cieľ)` | **len autor** cieľa | cieľ zmizne z pohľadu na kanál; v logu ostáva dôkaz, že niečo bolo |
//! | `Hide(cieľ, dôvod)` | **ktokoľvek pre seba** | skryté len pre účet autora záznamu; ostatní vidia cieľ ďalej |
//! | `Erase(cieľ, dôvod)` | **len autor** cieľa | obsah cieľa sa **fyzicky** nahradí (bajty sú preč), dôvod a meta ostávajú |
//!
//! Autoritu má **podpis v obálke** overený voči aktívnemu device kľúču
//! (D-26, B4 brána v [`crate::ws`]) — nie transportná relácia. Pravidlo
//! „len autor“ teda kontrolujeme tak, že autor mazacieho záznamu sa musí
//! rovnať autorovi cieľového záznamu.
//!
//! ## Obmedzenie MVP: erase nemá moderátora ani operátora
//!
//! Pôvodné znenie D-30 rozdeľuje tombstone (autor), hide (moderátor) a erase
//! (operátor, podpis uzla). **Koncept admina/operátora uzla v MVP nie je**
//! (ani účty nemajú role — B4 ich nedefinoval), preto tu erase podpisuje
//! **autor** a uzol k tomu nepridáva vlastný podpis. Dôsledok: erase
//! momentálne nespĺňa GDPR „záväzný príkaz operátora“ v plnom zmysle — je to
//! erase na žiadosť autora (`EraseReason::AuthorRequest`). Keď príde koncept
//! rolí, stačí v [`evaluate`] povoliť erase aj kľúču s rolou a doplniť
//! podpis uzla; formát záznamu sa meniť nemusí.
//!
//! ## Prečo cieľ musí byť v tom istom kanáli
//!
//! Mazací záznam je záznam v logu **jedného** kanála (D-25: poradie viaže
//! kanál) a čítací pohľad ho vyhodnocuje v scane toho istého kanála.
//! Tombstone z kanála A by v pohľade na kanál B nikdy neplatil — preto
//! uzol krížové mazanie odmietne a klient ho musí poslať do kanála cieľa.
//! (Veta o tom je aj v `Reject` dôvode, aby klient vedel čo opraviť.)

use crate::store::Store;
use myhsn_core::record::{EraseReason, RecordHash, RecordKind};
use myhsn_core::seq::ChannelId;
// `Store::get` je trait metoda (`RecordStore`), preto musí byť trait v scope.
use myhsn_core::storage::RecordStore;

/// Čo uzol urobí s mazacím záznamom po overení (výstup [`evaluate`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Záznam nie je mazací druh — normálna cesta appendu.
    None,
    /// Cieľ zmizne z pohľadu; do logu sa pridá tombstone záznam.
    Tombstone,
    /// Cieľ sa skryje autorovi záznamu; do logu sa pridá hide záznam.
    Hide,
    /// Do logu sa pridá erase záznam **a v tej istej transakcii** sa
    /// fyzicky nahradí obsah cieľa (D-30).
    Erase {
        target: RecordHash,
        reason: EraseReason,
    },
}

/// Dôvod, prečo uzol mazací záznam odmietne. Každá variant má svoju vetu do
/// `Reject.dôvod` — klient musí vedieť, čo má opraviť.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeletionError {
    /// Cieľový záznam v logu uzla nie je (neznámy alebo už zabudnutý hash).
    TargetMissing,
    /// Cieľ patrí do iného kanála, než je kanál mazacieho záznamu.
    TargetOtherChannel(ChannelId),
    /// Autor mazacieho záznamu nie je autor cieľa (tombstone/erase, D-30)
    /// a **nemá ani delete schopnosť** v tomto kanáli (F14c §6).
    NotAuthor,
    /// **F14c:** aktér má delete schopnosť, ale jeho **hodnosť nie je
    /// prísne vyššia** ako hodnosť autora príspevku (rozhodnutie §6 —
    /// channel admin nemaze príspevok ownera, member ten čoho, moderator
    /// ten adminovho a pod.).
    RankTooLow { actor: u8, target: u8 },
    /// Cieľ je už vymazaný — ďalší erase by zahodil prvý dôvod.
    AlreadyErased,
    /// Cieľ je sám mazací záznam — mazanie sa nemaže.
    TargetIsDeletion,
    /// Klient tvrdí iný druh cieľa, než aký cieľ v logu je.
    TargetKindMismatch { claimed: RecordKind, actual: RecordKind },
    /// **F14c (MYHSN-58):** cieľom je **audit** kind 6 – 11 (roly, skupiny).
    /// Tie píše výhradne uzol a ich mazaním by sa istoria členstva rozpadla,
    /// preto sú chránené proti Tombstone/Hide/Erase (rozhodnutie F14c §3).
    ProtectedTarget,
    /// Mazací záznam má nečitateľné telo (po `validate` prakticky nemožné).
    BadPayload,
    /// Erase bez podpisu autora. NIL podpis vyhradzuje **uzol** pre
    /// vymenený rad po erase (`Envelope::erased`) a podľa neho ho čítací
    /// pohľad odlíši od akcie erase — klient ho teda nesmie posielať.
    AnonymousErase,
}

impl DeletionError {
    /// Ľudská slovenská veta do `Reject` (bez hashov a citlivých detailov —
    /// logy aj odpovede držíme bez osobných údajov, MYHSN-19).
    pub fn message(&self) -> String {
        match self {
            DeletionError::TargetMissing => {
                "cieľ mazania neexistuje (neznámy hash príspevku)".into()
            }
            DeletionError::TargetOtherChannel(_) => {
                "cieľ je v inom kanáli — mazanie pošli do kanála, v ktorom cieľ je".into()
            }
            DeletionError::NotAuthor => {
                "mazať môže len autor príspevku (tombstone a erase)".into()
            }
            DeletionError::AlreadyErased => "obsah už bol vymazaný".into(),
            DeletionError::RankTooLow { actor, target } => format!(
                "cudzí príspevok maze len ten s vyssou hodnostou ({actor} <= {target})"
            ),
            DeletionError::TargetIsDeletion => "cieľ je samotný mazací záznam".into(),
            DeletionError::TargetKindMismatch { .. } => {
                "cieľ má iný druh, ako záznam tvrdí".into()
            }
            DeletionError::ProtectedTarget => {
                "ciel je auditny zaznam (role alebo skupina) — ten sa neda mazat \
                 (protected_target)".into()
            }
            DeletionError::BadPayload => "nesprávne telo mazacieho záznamu".into(),
            DeletionError::AnonymousErase => {
                "erase musí byť podpísaný kľúčom autora (NIL podpis patrí uzlu)".into()
            }
        }
    }
}

/// **F14c (MYHSN-58):** brána mazania **cudzieho** príspevku (rozhodnutie
/// §6). Aktér musí mať (a) **delete schopnosť** v danom kanáli — server
/// admin, moderator s `DELETE_POSTS` (tí v KAŽDOM kanáli, teda aj v legacy),
/// owner kanála alebo channel admin (posledné dvoje len v group) — a (b)
/// **prísne vyššiu hodnosť** ako autor príspevku.
///
/// Kľúč, ktorý k účtu nevieme priradiť (neznámy alebo revokovaný), má
/// hodnosť 0 a schopnosť mazania z neho nevychádza — preto cudzí príspevok
/// nikdy nemazne hocikto, kto len podpísal platnú obálku.
fn moderation_gate(
    store: &Store,
    channel: &ChannelId,
    actor_device: &[u8; 32],
    target_device: &[u8; 32],
) -> Result<(), DeletionError> {
    let rank_of = |device: &[u8; 32]| -> Option<crate::store::ChannelAuthority> {
        let account = store.account_for_device(device)?;
        store.channel_authority(channel, &account).ok().flatten()
    };
    let actor = rank_of(actor_device).ok_or(DeletionError::NotAuthor)?;
    if !actor.can_delete() {
        return Err(DeletionError::NotAuthor);
    }
    let target_rank = rank_of(target_device).map(|a| a.rank()).unwrap_or(0);
    let actor_rank = actor.rank();
    if actor_rank > target_rank {
        Ok(())
    } else {
        Err(DeletionError::RankTooLow {
            actor: actor_rank,
            target: target_rank,
        })
    }
}

/// Over mazací záznam `env` voči logu v `store` a vráti jeho účinok.
///
/// Volá sa **pred** alokáciou `node_seq`, aby odmietnutý záznam nenechal
/// dieru v poradí kanála. Obsahuje len pravidlá, ktoré potrebujú pohľad do
/// logu — formát obálky, podpis autora a aktívny device kľúč už overil
/// `Envelope::validate` a B4 brána vo [`crate::ws`].
pub fn evaluate(store: &Store, env: &myhsn_core::record::Envelope) -> Result<Effect, DeletionError> {
    let (target, reason, claimed_kind) = match env.kind {
        RecordKind::Tombstone => {
            let t = match env.payload().map_err(|_| DeletionError::BadPayload)? {
                myhsn_core::record::Payload::Tombstone { target } => target,
                _ => return Err(DeletionError::BadPayload),
            };
            (RecordHash(t), None, RecordKind::Post)
        }
        RecordKind::Hide => {
            let t = match env.payload().map_err(|_| DeletionError::BadPayload)? {
                myhsn_core::record::Payload::Hide { target, .. } => target,
                _ => return Err(DeletionError::BadPayload),
            };
            (RecordHash(t), None, RecordKind::Post)
        }
        RecordKind::Erase => {
            match env.payload().map_err(|_| DeletionError::BadPayload)? {
                myhsn_core::record::Payload::Erase {
                    target,
                    reason,
                    target_kind,
                } => (RecordHash(target), Some(reason), target_kind),
                _ => return Err(DeletionError::BadPayload),
            }
        }
        // bežný záznam: žiadny mazací účinok
        _ => return Ok(Effect::None),
    };

    // Erase **bez podpisu autora** je vyhradený uzlu: NIL podpis má práve
    // vymenený rad po erase (`Envelope::erased`) a čítací pohľad podľa neho
    // rozlíši „tento rad už neobsahuje obsah“ od „niekto niečo vymazal“.
    // Klient by s NIL podpisom vložil záznam, ktorý sa tvári ako vymenený
    // rad — a ten nik nepodpisuje, lebo jeho obsah je prázdny.
    if env.kind == RecordKind::Erase && env.body_sig.is_nil() {
        return Err(DeletionError::AnonymousErase);
    }

    // 1) cieľ musí existovať — inak mazanie nemaže nič a erase by nechal
    //    dôvod bez obsahu. Chybu úložne tu netlmočíme ako „neexistuje“
    //    naslepo: ak cieľ nedokážeme prečítať, mazanie odmietame (bez
    //    potvrdeného cieľa by erase mohol zmazať niečo iné, než klient myslel)
    let raw = store
        .get(&target)
        .map_err(|_| DeletionError::TargetMissing)?
        .ok_or(DeletionError::TargetMissing)?;
    let goal = myhsn_core::record::Envelope::decode(&raw)
        .map_err(|_| DeletionError::TargetMissing)?;

    // 2) cieľ musí byť z toho istého kanála — čítací pohľad kanála nevidí
    //    mazacie záznamy iných kanálov (pozri hlavičku modulu)
    if goal.stamp.channel != env.stamp.channel {
        return Err(DeletionError::TargetOtherChannel(goal.stamp.channel));
    }

    // 3) mazací záznam sa nemaže; erase už vymazaného cieľa by zahodil
    //    prvý dôvod, a to je strata dôkazu (D-30)
    match goal.kind {
        RecordKind::Erase => return Err(DeletionError::AlreadyErased),
        RecordKind::Tombstone | RecordKind::Hide => {
            return Err(DeletionError::TargetIsDeletion)
        }
        // **F14c (MYHSN-58):** audity kind 6 – 11 (roly, skupiny) píše
        // výhradne uzol a sú zdrojom histórie členstva. V group kanáli bežne
        // píšu aj členovia, takže ochrana nevznikne sama — musíme ju
        // vynútiť tu (rozhodnutie F14c §3).
        RecordKind::GrantRole
        | RecordKind::RevokeRole
        | RecordKind::CreateChannel
        | RecordKind::GrantChannelRole
        | RecordKind::RevokeChannelRole
        | RecordKind::TransferChannelOwner => return Err(DeletionError::ProtectedTarget),
        _ => {}
    }

    // 4) erase nesmie klamať o tom, aký druh vymazáva — placeholder sa
    //    kreslí podľa tohto druhu a zlý druh by ho dal na zlé miesto
    if env.kind == RecordKind::Erase && claimed_kind != goal.kind {
        return Err(DeletionError::TargetKindMismatch {
            claimed: claimed_kind,
            actual: goal.kind,
        });
    }

    // 5) tombstone aj erase smie podpísať **autor** cieľa (D-30) — alebo
    //    od F14c niekto s **delete schopnosťou** v danom kanáli a **prísne
    //    vyššou hodnosťou**, než má autor (rozhodnutie §6). Hide je osobná
    //    voľba, preto autorovo právo nepotrebuje vôbec.
    if env.kind != RecordKind::Hide && goal.author.0 != env.author.0 {
        moderation_gate(store, &env.stamp.channel, &env.author.0, &goal.author.0)?;
    }

    Ok(match env.kind {
        RecordKind::Tombstone => Effect::Tombstone,
        RecordKind::Hide => Effect::Hide,
        RecordKind::Erase => Effect::Erase {
            target,
            // dôvod prišiel v tele; `None` by znamenal neplatné telo, to je
            // vyššie ošetrené, preto tu len dopĺňame default pre istotu
            reason: reason.unwrap_or(EraseReason::Other(0)),
        },
        _ => Effect::None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use myhsn_core::channel::ChannelKind;
    use myhsn_core::identity::{public_from_seed, DevicePublicKey};
    use myhsn_core::record::{Envelope, NodeStamp, Payload};
    use myhsn_core::seq::SeqPos;
    use crate::store::Store;

    /// Kľúč autora a kľúč cudzinca (dva rôzne ed25519 kľúče).
    const AUTHOR_SEED: [u8; 32] = [3u8; 32];
    const STRANGER_SEED: [u8; 32] = [9u8; 32];
    /// Pečiatkový kľúč uzla — testy ním podpisujú poradie, ako to robí uzol.
    const NODE_SEED: [u8; 32] = [42u8; 32];

    /// Úložňa s kanálom a dvoma aktívnymi device kľúčmi (autor + cudzinec),
    /// aby B4 brána neprekážala pravidlám, ktoré tu testujeme.
    fn store_with_channel() -> (Store, ChannelId) {
        let mut store = Store::open_in_memory().unwrap();
        let ch = store.create_channel("nastienka", ChannelKind::Wall).unwrap();
        for (name, seed) in [("autor", AUTHOR_SEED), ("cudzinec", STRANGER_SEED)] {
            let acc = store.create_account(name, "x", 1).unwrap();
            store
                .attest_device_key(
                    &acc.id,
                    &DevicePublicKey::from_seed(&seed),
                    "zariadenie",
                    1,
                )
                .unwrap();
        }
        (store, ch.id)
    }

    /// Záznam tak, ako ho uzol uloží: opečiatkovaný **kľúčom tejto úložne**
    /// (v produkcii ho dáva `store.node_sign_seed()`, nie cudzí seed).
    fn stamped(store: &mut Store, ch: ChannelId, seq: u64, author_seed: &[u8; 32], text: &str) -> Envelope {
        let node_pub = store.node_pub().unwrap();
        let env = Envelope::build(
            author_seed,
            &Payload::Post { text: text.into(), media_ref: None },
            NodeStamp::new(ch, 0, seq, node_pub),
            b"so",
            Some(&NODE_SEED),
        );
        let pos = SeqPos::new(ch, 0, seq);
        store.insert_record(&pos, &env.hash(), &env.encode(), None).unwrap();
        env
    }

    /// Mazací záznam tak, ako ho posiela klient: bez poradia aj bez pečiatky.
    fn client_deletion(seed: &[u8; 32], ch: ChannelId, payload: &Payload) -> Envelope {
        Envelope::build(
            seed,
            payload,
            NodeStamp::new(ch, 0, 0, public_from_seed(&NODE_SEED)),
            b"so",
            None,
        )
    }

    #[test]
    fn tombstone_of_own_post_is_allowed() {
        let (mut store, ch) = store_with_channel();
        let post = stamped(&mut store, ch, 1, &AUTHOR_SEED, "muj prispevok");
        let ts = client_deletion(
            &AUTHOR_SEED,
            ch,
            &Payload::Tombstone { target: post.hash().0 },
        );
        assert_eq!(evaluate(&store, &ts), Ok(Effect::Tombstone));
    }

    #[test]
    fn tombstone_of_someone_elses_post_is_rejected() {
        let (mut store, ch) = store_with_channel();
        let post = stamped(&mut store, ch, 1, &AUTHOR_SEED, "cudzi prispevok");
        let ts = client_deletion(
            &STRANGER_SEED,
            ch,
            &Payload::Tombstone { target: post.hash().0 },
        );
        assert_eq!(evaluate(&store, &ts), Err(DeletionError::NotAuthor));
    }

    #[test]
    fn hide_is_allowed_for_anyone_because_it_hides_only_for_its_author() {
        let (mut store, ch) = store_with_channel();
        let post = stamped(&mut store, ch, 1, &AUTHOR_SEED, "cudzi prispevok");
        let h = client_deletion(
            &STRANGER_SEED,
            ch,
            &Payload::Hide { target: post.hash().0, reason: "nechcem to vidiet".into() },
        );
        assert_eq!(evaluate(&store, &h), Ok(Effect::Hide));
    }

    #[test]
    fn erase_requires_author_and_reports_reason() {
        let (mut store, ch) = store_with_channel();
        let post = stamped(&mut store, ch, 1, &AUTHOR_SEED, "gdpr erase");
        let e = client_deletion(
            &AUTHOR_SEED,
            ch,
            &Payload::Erase {
                target: post.hash().0,
                reason: EraseReason::AuthorRequest,
                target_kind: RecordKind::Post,
            },
        );
        assert_eq!(
            evaluate(&store, &e),
            Ok(Effect::Erase { target: post.hash(), reason: EraseReason::AuthorRequest })
        );

        let stranger = client_deletion(
            &STRANGER_SEED,
            ch,
            &Payload::Erase {
                target: post.hash().0,
                reason: EraseReason::LegalOrder,
                target_kind: RecordKind::Post,
            },
        );
        assert_eq!(evaluate(&store, &stranger), Err(DeletionError::NotAuthor));
    }

    #[test]
    fn unknown_target_is_rejected() {
        let (store, ch) = store_with_channel();
        let ts = client_deletion(&AUTHOR_SEED, ch, &Payload::Tombstone { target: [0xee; 32] });
        assert_eq!(evaluate(&store, &ts), Err(DeletionError::TargetMissing));
    }

    #[test]
    fn cross_channel_target_is_rejected() {
        let mut store = Store::open_in_memory().unwrap();
        let a = store.create_channel("a", ChannelKind::Wall).unwrap().id;
        let b = store.create_channel("b", ChannelKind::Wall).unwrap().id;
        let acc = store.create_account("autor", "x", 1).unwrap();
        store
            .attest_device_key(
                &acc.id,
                &DevicePublicKey::from_seed(&AUTHOR_SEED),
                "zariadenie",
                1,
            )
            .unwrap();
        let post = stamped(&mut store, a, 1, &AUTHOR_SEED, "v kanale a");
        let ts = client_deletion(&AUTHOR_SEED, b, &Payload::Tombstone { target: post.hash().0 });
        assert_eq!(evaluate(&store, &ts), Err(DeletionError::TargetOtherChannel(a)));
    }

    /// Dvojitý erase nemá zmysel a uzol ho nepustí — a to **dvomi**
    /// spôsobmi, podľa toho, ktorým hashom cieľ adresujeme:
    ///
    ///  * starým hashom: po výmene obsahu je hash iný (D-25: hash je
    ///    BLAKE3 bajtov), takže cieľ už neexistuje → `TargetMissing`,
    ///  * novým hashom vymenenej obálky: cieľ existuje, ale je to erase
    ///    záznam → `AlreadyErased`, druhý dôvod by prepísal ten prvý.
    ///
    /// Obe sú správne: žiadna cesta nenechá log s dôvodom, ktorý bol
    /// nahradený iným dôvodom (D-30 vyžaduje zachovať dôvod).
    #[test]
    fn erasing_twice_loses_the_first_reason_so_it_is_rejected() {
        let (mut store, ch) = store_with_channel();
        let post = stamped(&mut store, ch, 1, &AUTHOR_SEED, "druhy erase");
        let target = post.hash();
        let e = Payload::Erase { target: target.0, reason: EraseReason::AuthorRequest, target_kind: RecordKind::Post };
        let env = client_deletion(&AUTHOR_SEED, ch, &e);
        // Aplikuj prvý erase skutočne (vrátane fyzickej náhrady obsahu).
        // Pečiatku dáva uzol, preto `signed_by_node` a podpis idú z kľúča
        // **tejto** úložne — úložňa nahradenú obálku overuje vlastným kľúčom.
        let node_pub = store.node_pub().unwrap();
        let seed = store.node_sign_seed().unwrap();
        let pos = SeqPos::new(ch, 0, 2);
        let mut signed = env.clone();
        signed.stamp = NodeStamp::new(ch, 0, 2, node_pub);
        signed.stamp_sig = Some(myhsn_core::identity::sign(&seed, &signed.stamp_signing_bytes()));
        store
            .insert_record_erasing(&pos, &signed.hash(), &signed.encode(), None, Some((&target, EraseReason::AuthorRequest)))
            .unwrap();

        // 1) druhý erase tou istou adresou: starý hash už neplatí
        let second = client_deletion(
            &AUTHOR_SEED,
            ch,
            &Payload::Erase { target: target.0, reason: EraseReason::LegalOrder, target_kind: RecordKind::Post },
        );
        assert_eq!(evaluate(&store, &second), Err(DeletionError::TargetMissing));

        // 2) druhý erase novým hashom: cieľ je erase záznam, dôvod by sa prepísal
        let new_hash = store
            .channel_hashes(&ch)
            .unwrap()
            .into_iter()
            .find(|(p, _)| p.node_seq == 1)
            .expect("pozícia 1 má v logu zostať")
            .1;
        assert_ne!(new_hash, target, "nahradená obálka má nový hash");
        let again = client_deletion(
            &AUTHOR_SEED,
            ch,
            &Payload::Erase { target: new_hash.0, reason: EraseReason::LegalOrder, target_kind: RecordKind::Post },
        );
        assert_eq!(evaluate(&store, &again), Err(DeletionError::AlreadyErased));
    }

    #[test]
    fn erase_lying_about_target_kind_is_rejected() {
        let (mut store, ch) = store_with_channel();
        let post = stamped(&mut store, ch, 1, &AUTHOR_SEED, "klamstvo o druhu");
        let e = client_deletion(
            &AUTHOR_SEED,
            ch,
            &Payload::Erase {
                target: post.hash().0,
                reason: EraseReason::AuthorRequest,
                target_kind: RecordKind::ChatMsg,
            },
        );
        assert_eq!(
            evaluate(&store, &e),
            Err(DeletionError::TargetKindMismatch { claimed: RecordKind::ChatMsg, actual: RecordKind::Post })
        );
    }

    #[test]
    fn ordinary_post_has_no_deletion_effect() {
        let (mut store, ch) = store_with_channel();
        let post = stamped(&mut store, ch, 1, &AUTHOR_SEED, "normalny");
        let other = client_deletion(&AUTHOR_SEED, ch, &Payload::Post { text: "iný".into(), media_ref: None });
        assert_eq!(evaluate(&store, &other), Ok(Effect::None));
        let _ = post;
    }
}
