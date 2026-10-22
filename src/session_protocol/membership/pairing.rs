//! The device list a pairing pins (§R9.2 "Pairing"): `verifyKeys` names the
//! account's genesis, `verifyReveal` reveals this host's new
//! `host_channel_key`, and `deviceVerified` carries the log from its genesis
//! to the `add_host` the verified Astation signed for this host. Atem
//! verifies the whole chain and the pairing checks, then pins it (the list,
//! the key and the applied head) before it reports success. A verification
//! that fails after the pin takes the pin back.
use super::{HostPin, LEFTOVERS, MembershipHost, frozen_genesis, journal_of, store};
use crate::paths::PairingPaths;
use atem_client::canonical::StrictValue;
use atem_client::encoding::Hash32;
use atem_client::keys::{Alg, PublicKey};
use atem_client::membership::{Entry, HostNow, Membership};
use serde_json::Value;

/// Largest log a pairing carries (§R9.2 log limit).
const MAX_ENTRIES: usize = 1024;

/// What the ceremony learned about this host and the account.
pub struct PairingInputs<'a> {
    /// The verified data account (the signed `deviceVerified`).
    pub account_id: &'a str,
    /// `verifyKeys.genesis_hash`.
    pub genesis_hash: [u8; 32],
    /// Astation's ceremony P-256 identity (SEC1, 65 bytes).
    pub astation_sign_pub: &'a [u8],
    /// This host: its `atem_device_id` and the binding's trust generation.
    pub host_id: &'a str,
    pub host_trust_gen: u64,
    /// The `host_channel_key` this ceremony revealed.
    pub host_pub: [u8; 32],
}

/// Verifies `deviceVerified.membership` (`{"entries": [...]}`) for a
/// pairing: the chain from the pinned genesis, no entry waiting on a
/// pending one, a genesis this host never froze on, and the newest
/// `add_host` of this host naming its key and trust generation, signed by
/// the verified Astation (`Membership::check_pairing`).
pub fn verify_pairing_log(
    membership: Option<&Value>,
    inputs: &PairingInputs<'_>,
    pairing: &PairingPaths,
    now: &HostNow,
) -> Result<Membership, String> {
    let entries = membership
        .and_then(|m| m.get("entries"))
        .and_then(Value::as_array)
        .ok_or("Astation sent no device list (an r9 Astation is required)")?;
    if entries.is_empty() || entries.len() > MAX_ENTRIES {
        return Err(format!(
            "the device list must hold 1 to {MAX_ENTRIES} entries"
        ));
    }
    let entries = entries
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let strict = StrictValue::parse(value.to_string().as_bytes(), usize::MAX)
                .map_err(|e| format!("device list entry {index}: {e:?}"))?;
            Entry::from_strict(&strict).map_err(|e| format!("device list entry {index}: {e}"))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let genesis = Hash32(inputs.genesis_hash);
    let verified = Membership::verify_chain(inputs.account_id, &genesis, &entries, now)
        .map_err(|e| format!("the device list doesn't verify ({e})"))?;
    if let Some((index, _)) = verified.deferred {
        return Err(format!(
            "device list entry {index} waits for a pending recovery; pair again later"
        ));
    }
    let m = verified.membership;
    let host_key = PublicKey::new(Alg::Ed25519, &inputs.host_pub)
        .map_err(|e| format!("this host's channel key: {e}"))?;
    let astation = PublicKey::new(Alg::P256, inputs.astation_sign_pub)
        .map_err(|e| format!("Astation's signing key: {e}"))?;
    m.check_pairing(
        inputs.host_id,
        inputs.host_trust_gen,
        &host_key,
        &astation,
        &frozen_genesis(pairing)?,
    )
    .map_err(|refusal| match refusal {
        atem_client::membership::PairingRefusal::FrozenGenesis => {
            "this account's device list was frozen on this host; pair from a new device list".into()
        }
        other => format!("the device list can't be pinned ({})", other.as_str()),
    })?;
    if m.head().seq
        != m.entries()
            .iter()
            .rev()
            .find(|e| matches!(&e.action, atem_client::membership::entry::Action::AddHost { host } if host.host_id == inputs.host_id))
            .map_or(0, |e| e.seq)
    {
        return Err("the device list must end at this host's add_host".into());
    }
    Ok(m)
}

/// Pins the verified log for this host, with its `host_channel_key`, under
/// `trust_gen.lock` held by the caller (the ceremony's apply).
pub fn pin_at_pairing_locked(
    pairing: &PairingPaths,
    m: &Membership,
    host_id: &str,
    host_trust_gen: u64,
    host_seed: &[u8; 32],
) -> Result<(), String> {
    let pin = HostPin {
        host_id: host_id.to_string(),
        host_trust_gen,
    };
    MembershipHost::pin_locked(pairing, &journal_of(pairing), &pin, m, host_seed)
}

/// A verification that failed after its pin (the cred side couldn't be
/// applied): the pin goes, so the host isn't left with a list its pairing
/// never confirmed. Best effort; anything left fails closed (a leftover)
/// until the next pin or `atem unpair`. The caller holds `trust_gen.lock`.
pub fn unpin_locked(pairing: &PairingPaths) {
    let mut store = store::Store::new(pairing, &journal_of(pairing));
    if let Err(e) = store.remove(store::DlFile::State) {
        eprintln!("atem: device list: cannot take the pin back: {e}");
        return;
    }
    for file in LEFTOVERS {
        if let Err(e) = store.remove(file) {
            eprintln!("atem: device list: cannot take the pin back: {e}");
        }
    }
}
