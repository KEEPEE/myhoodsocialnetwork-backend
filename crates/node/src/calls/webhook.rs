//! Overenie LiveKit webhookov.
//!
//! **Schéma (LiveKit, nie HMAC hlavička):** LiveKit pošle v hlavičke
//! `Authorization` JWT podpísaný HS256 tajomstvom `api_secret`, s
//! `iss = api_key` a claimom `sha256 = base64(SHA-256(telo))`. Overenie =
//! podpis + `iss` + `exp/nbf` + zhoda hashu **presných bajtov tela** (preto
//! handler číta telo ako `String`, nie `Json`). Implementácia je
//! `livekit_api::webhooks::WebhookReceiver`; tu je len tenký obal s našimi
//! chybami a odstránením prípadného prefixu `Bearer `.

use super::CallsError;
use livekit_api::access_token::TokenVerifier;
use livekit_api::webhooks::WebhookReceiver;

/// Udalosť, na ktorú uzol reaguje kontrolou členstva.
pub const EVENT_PARTICIPANT_JOINED: &str = "participant_joined";

/// Polia webhooku, ktoré uzol potrebuje (bez priamej závislosti na
/// `livekit-protocol` typoch v API modulu).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookInfo {
    /// `participant_joined`, `room_finished`, …
    pub event: String,
    /// id udalosti (LiveKit pri opakovaní posiela rovnaké)
    pub id: String,
    pub created_at: i64,
    /// meno miestnosti (= hex id kanála)
    pub room: Option<String>,
    /// identita participanta (`d_<b32>`)
    pub identity: Option<String>,
}

/// Over podpis a rozparsuj udalosť.
pub fn verify(
    body: &str,
    authorization: Option<&str>,
    verifier: TokenVerifier,
) -> Result<WebhookInfo, CallsError> {
    let auth = authorization
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CallsError::Webhook("chýba hlavička Authorization".into()))?;
    let jwt = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
    let ev = WebhookReceiver::new(verifier)
        .receive(body, jwt)
        .map_err(|e| CallsError::Webhook(e.to_string()))?;
    Ok(WebhookInfo {
        event: ev.event,
        id: ev.id,
        created_at: ev.created_at,
        room: ev.room.map(|r| r.name).filter(|n| !n.is_empty()),
        identity: ev.participant.map(|p| p.identity).filter(|i| !i.is_empty()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known vector vygenerovaný NEZÁVISLE od livekit-api (Python hmac +
    // hashlib, `exp` = 2100-01-01): JWT {iss, nbf, exp, sha256} nad
    // presne týmto telom a tajomstvom.
    const KEY: &str = "myhsn-test-key";
    const SECRET: &str = "myhsn-test-secret-0123456789abcdef-xyz";
    const BODY: &str = r#"{"event":"participant_joined","room":{"name":"abababababababababababababababababababababababababababababababab"},"participant":{"identity":"d_ceirceirceirceirceirceirceirceirceirceirceirceirceiq","name":"anna"},"id":"EV_vector1","createdAt":"1763200000"}"#;
    const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJteWhzbi10ZXN0LWtleSIsIm5iZiI6MTcwMDAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwLCJzaGEyNTYiOiJmNU9ndmJDck1nNXFJUUN2Y0s3Z2lHMDNlVEVHMHljS0l4aHk3amRIN2g0PSJ9.GPHj5NYAk-dgPLjxZv9hnJ9J1CRdrMV_JrsF5xP_okY";

    fn verifier() -> TokenVerifier {
        TokenVerifier::with_api_key(KEY, SECRET)
    }

    #[test]
    fn known_vector_verifies_and_parses() {
        let ev = verify(BODY, Some(JWT), verifier()).unwrap();
        assert_eq!(ev.event, EVENT_PARTICIPANT_JOINED);
        assert_eq!(ev.id, "EV_vector1");
        assert_eq!(ev.created_at, 1_763_200_000);
        assert_eq!(ev.room.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(
            ev.identity.as_deref(),
            Some(super::super::device_identity(&[0x11; 32]).as_str())
        );
        // „Bearer “ prefix sa toleruje
        assert!(verify(BODY, Some(&format!("Bearer {JWT}")), verifier()).is_ok());
    }

    #[test]
    fn tampered_body_is_rejected() {
        let tampered = BODY.replace("anna", "anno");
        assert!(matches!(
            verify(&tampered, Some(JWT), verifier()),
            Err(CallsError::Webhook(_))
        ));
        // aj zmena bielych znakov mení hash — overuje sa presné telo
        assert!(verify(&format!("{BODY} "), Some(JWT), verifier()).is_err());
    }

    #[test]
    fn wrong_secret_key_or_missing_header_is_rejected() {
        let other_secret = TokenVerifier::with_api_key(KEY, "ine-tajomstvo-0123456789abcdef-xyz");
        assert!(verify(BODY, Some(JWT), other_secret).is_err());
        let other_key = TokenVerifier::with_api_key("iny-kluc", SECRET);
        assert!(
            verify(BODY, Some(JWT), other_key).is_err(),
            "iss musí sedieť s api_key"
        );
        assert!(verify(BODY, None, verifier()).is_err());
        assert!(verify(BODY, Some("  "), verifier()).is_err());
        assert!(verify(BODY, Some("sha256,deadbeef"), verifier()).is_err());
    }
}
