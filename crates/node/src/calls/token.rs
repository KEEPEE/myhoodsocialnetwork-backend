//! Mint LiveKit JWT + Server API (miestnosti, `RemoveParticipant`).
//!
//! Referenčná implementácia je spike `token_mint` (G4, `livekit-api` 0.10.2).
//! Token je **vstupenka na 60 s**: LiveKit ho po pripojení sám obnovuje,
//! takže TTL obmedzuje len okno, v ktorom sa dá token zneužiť na vstup.
//! Trvalé ACL drží uzol (webhook + kick).

use super::{CallsError, ROOM_EMPTY_TIMEOUT_SECS, TOKEN_TTL_SECS};
use livekit_api::access_token::{AccessToken, TokenVerifier, VideoGrants};
use livekit_api::services::room::{CreateRoomOptions, RoomClient};
use livekit_api::services::{ServerError, ServiceError};
use std::time::Duration;

/// Timeout jednej Server API požiadavky (default knižnice je 10 s; kick
/// a ensure idú na lokálny LiveKit, dlhšie čakanie by blokovalo REST).
const API_TIMEOUT: Duration = Duration::from_secs(5);

/// Kto a kam — vstup pre [`TokenService::mint`].
#[derive(Debug, Clone)]
pub struct CallGrant<'a> {
    /// `d_<device_pubkey_b32>`
    pub identity: &'a str,
    /// username účtu (zobrazované meno v hovore)
    pub name: &'a str,
    /// hex id kanála
    pub room: &'a str,
}

/// Služba tokenov a Server API jedného LiveKitu.
pub struct TokenService {
    api_key: String,
    api_secret: String,
    ttl: Duration,
    rooms: RoomClient,
}

impl std::fmt::Debug for TokenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenService")
            .field("api_key", &self.api_key)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

/// `not_found` z twirp = participant/miestnosť tam nie je (pre kick OK).
fn is_not_found(e: &ServiceError) -> bool {
    matches!(e, ServiceError::Twirp(ServerError::Twirp(code)) if code.code == "not_found")
}

fn lk_err(e: ServiceError) -> CallsError {
    CallsError::LiveKit(e.to_string())
}

impl TokenService {
    /// `api_url` = `http(s)://host:port` Server API.
    pub fn new(api_url: &str, api_key: &str, api_secret: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            api_secret: api_secret.to_string(),
            ttl: Duration::from_secs(TOKEN_TTL_SECS),
            rooms: RoomClient::with_api_key(api_url, api_key, api_secret)
                .with_failover(false)
                .with_request_timeout(API_TIMEOUT),
        }
    }

    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Overovač JWT podpísaných týmto kľúčom (webhook, testy).
    pub fn verifier(&self) -> TokenVerifier {
        TokenVerifier::with_api_key(&self.api_key, &self.api_secret)
    }

    /// Mint JWT: `roomJoin + canPublish + canSubscribe` len pre `room`,
    /// TTL 60 s. `canPublishSources` je prázdne = všetky zdroje vrátane
    /// zdieľania obrazovky (F10). Vlastné metadáta participant meniť
    /// nesmie — meno a identitu určuje uzol.
    pub fn mint(&self, grant: &CallGrant<'_>) -> Result<String, CallsError> {
        let grants = VideoGrants {
            room_join: true,
            room: grant.room.to_string(),
            can_publish: Some(true),
            can_subscribe: Some(true),
            can_update_own_metadata: Some(false),
            ..Default::default()
        };
        AccessToken::with_api_key(&self.api_key, &self.api_secret)
            .with_identity(grant.identity)
            .with_name(grant.name)
            .with_ttl(self.ttl)
            .with_grants(grants)
            .to_jwt()
            .map_err(|e| CallsError::Token(e.to_string()))
    }

    /// Vytvor miestnosť, ak neexistuje (`room.auto_create: false`).
    /// Idempotentné; `Ok(true)` = práve vytvorená. Volať **tesne pred**
    /// pripojením — prázdnu miestnosť LiveKit zmaže po `empty_timeout`
    /// (spike nález č. 11).
    pub async fn ensure_room(&self, room: &str) -> Result<bool, CallsError> {
        let existing = self
            .rooms
            .list_rooms(vec![room.to_string()])
            .await
            .map_err(lk_err)?;
        if existing.iter().any(|r| r.name == room) {
            return Ok(false);
        }
        // CreateRoom je v LiveKite idempotentný aj pri súbehu dvoch volaní
        self.rooms
            .create_room(
                room,
                CreateRoomOptions {
                    empty_timeout: ROOM_EMPTY_TIMEOUT_SECS,
                    ..Default::default()
                },
            )
            .await
            .map_err(lk_err)?;
        tracing::info!(%room, "LiveKit miestnosť vytvorená");
        Ok(true)
    }

    /// Vyhoď participanta z miestnosti (spike G4c: klient odpojený do
    /// 7 ms). Participant/miestnosť, ktorá neexistuje, je úspech.
    pub async fn kick(&self, identity: &str, room: &str) -> Result<(), CallsError> {
        match self.rooms.remove_participant(room, identity).await {
            Ok(()) => {
                tracing::info!(%identity, %room, "participant vyhodený z hovoru");
                Ok(())
            }
            Err(e) if is_not_found(&e) => Ok(()),
            Err(e) => Err(lk_err(e)),
        }
    }

    /// Vyhoď identitu zo všetkých miestností, kde je. Vracia počet
    /// miestností, z ktorých bola vyhodená. Pokračuje aj po chybe jednej
    /// miestnosti a vráti poslednú chybu.
    pub async fn kick_everywhere(&self, identity: &str) -> Result<usize, CallsError> {
        let rooms = self.rooms.list_rooms(Vec::new()).await.map_err(lk_err)?;
        let mut kicked = 0;
        let mut last_err = None;
        // bez filtra na num_participants — počet v ListRooms môže zaostávať
        // za práve pripojeným participantom; miestností je na uzle málo
        for room in &rooms {
            match self.rooms.remove_participant(&room.name, identity).await {
                Ok(()) => kicked += 1,
                Err(e) if is_not_found(&e) => {}
                Err(e) => last_err = Some(lk_err(e)),
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(kicked),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "myhsn-test-key";
    const SECRET: &str = "myhsn-test-secret-0123456789abcdef-xyz";

    fn svc() -> TokenService {
        // port 9 (discard) — mint nič nevolá, Server API v unit testoch nie
        TokenService::new("http://127.0.0.1:9", KEY, SECRET)
    }

    /// **Kritérium F10a:** mint → decode: identity, meno, room, grants, TTL.
    #[test]
    fn mint_decodes_with_expected_claims() {
        let ident = super::super::device_identity(&[7u8; 32]);
        let room = "ab".repeat(32);
        let jwt = svc()
            .mint(&CallGrant {
                identity: &ident,
                name: "anna",
                room: &room,
            })
            .unwrap();
        let claims = svc().verifier().verify(&jwt).expect("podpis musí sedieť");
        assert_eq!(claims.iss, KEY);
        assert_eq!(claims.sub, ident);
        assert_eq!(claims.name, "anna");
        assert_eq!(claims.exp - claims.nbf, TOKEN_TTL_SECS as usize, "TTL 60 s");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;
        assert!(claims.nbf <= now && claims.exp > now);
        let v = &claims.video;
        assert!(v.room_join);
        assert_eq!(v.room, room, "token platí len pre jeden kanál");
        assert_eq!(v.can_publish, Some(true));
        assert_eq!(v.can_subscribe, Some(true));
        assert_eq!(v.can_update_own_metadata, Some(false));
        assert!(
            v.can_publish_sources.is_empty(),
            "všetky zdroje vrátane screen share"
        );
        assert!(!v.room_admin && !v.room_create && !v.room_list && !v.room_record);
    }

    /// Token podpísaný iným tajomstvom sa neoverí.
    #[test]
    fn mint_rejected_by_other_secret() {
        let jwt = svc()
            .mint(&CallGrant {
                identity: "d_aa",
                name: "x",
                room: "r",
            })
            .unwrap();
        let other = TokenService::new(
            "http://127.0.0.1:9",
            KEY,
            "ine-tajomstvo-0123456789abcdef-123",
        );
        assert!(other.verifier().verify(&jwt).is_err());
    }

    /// Prázdna identita/room je chyba knižnice, nie panika.
    #[test]
    fn mint_requires_identity_and_room() {
        let r = svc().mint(&CallGrant {
            identity: "",
            name: "x",
            room: "r",
        });
        assert!(matches!(r, Err(CallsError::Token(_))));
    }

    /// Nedostupný LiveKit → `CallsError::LiveKit`, nie panika/visenie.
    #[tokio::test]
    async fn kick_against_dead_server_is_error() {
        let r = svc().kick("d_aa", "room").await;
        assert!(matches!(r, Err(CallsError::LiveKit(_))), "{r:?}");
    }
}
