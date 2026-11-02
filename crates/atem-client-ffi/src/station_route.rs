//! Selected-Station handoff: shared parsing, normalization and MAC bytes.
use crate::error::{AtemError, Result};
use atem_client::station_route::{Message, Offer};
use zeroize::Zeroizing;

fn invalid(detail: &str) -> AtemError {
    AtemError::Invalid {
        code: "station_route".into(),
        detail: detail.into(),
    }
}

/// Native must check request context against the exact paired session and
/// capture/recheck its active account, Station and connection before sending.
/// This helper establishes no R9 permission and performs no transport I/O.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn station_route_offer(
    request_json: String,
    relay_url: String,
    relay_only: bool,
    session_token: String,
) -> Result<String> {
    let token = Zeroizing::new(session_token);
    let Message::Request { request, .. } =
        Message::parse(request_json.as_bytes()).map_err(invalid)?
    else {
        return Err(invalid("expected a routing request"));
    };
    let offer = Offer::sign(request, &relay_url, relay_only, token.as_bytes()).map_err(invalid)?;
    Ok(Message::Offer { v: 1, offer }.to_json())
}

/// Verifies durable selection of exactly the caller's pending offer.
/// Native also rechecks its captured account/Station/session/connection.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn station_route_verify_accepted(
    offer_json: String,
    accepted_json: String,
    session_token: String,
) -> Result<u64> {
    let token = Zeroizing::new(session_token);
    let Message::Offer { offer, .. } = Message::parse(offer_json.as_bytes()).map_err(invalid)?
    else {
        return Err(invalid("expected a routing offer"));
    };
    let Message::Accepted { accepted, .. } =
        Message::parse(accepted_json.as_bytes()).map_err(invalid)?
    else {
        return Err(invalid("expected a routing acceptance"));
    };
    accepted.verify(&offer, token.as_bytes()).map_err(invalid)
}
