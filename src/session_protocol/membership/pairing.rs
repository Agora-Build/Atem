//! The device list a pairing pins (§R9.2 "Pairing"): `verifyKeys` names the
//! account and its genesis, `verifyReveal` reveals this host's new
//! `host_channel_key` and its new encryption key (host-work-v1 §11.5), and
//! `deviceVerified` carries the log from its genesis to the `add_host` the
//! verified Astation signed for this host, or to the `host_enc_key` of the
//! revealed key right after it. Atem verifies the whole chain and the
//! pairing checks, then pins it (the list, both keys and the applied head)
//! before it reports success. A verification that fails after the pin
//! takes the pin back.
use super::{DELETE_ONLY, HostPin, LEFTOVERS, MembershipHost, frozen_genesis, journal_of, store};
use crate::paths::PairingPaths;
use atem_client::canonical::StrictValue;
use atem_client::encoding::Hash32;
use atem_client::keys::{Alg, PublicKey};
use atem_client::membership::{Entry, HostNow, MAX_ENTRIES, Membership};
use serde_json::Value;

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
    /// The host encryption key this ceremony revealed (host-work-v1
    /// §11.5): its public half and `enc_sig`.
    pub enc_pub: [u8; 32],
    pub enc_sig: [u8; 64],
}

/// Verifies `deviceVerified.membership` (`{"entries": [...]}`) for a
/// pairing: the chain from the pinned genesis, no entry waiting on a
/// pending one, a genesis this host never froze on, and the newest
/// `add_host` of this host naming its key and trust generation, signed by
/// the verified Astation (`Membership::check_pairing`), and the entries
/// ending there or at the revealed encryption key's `host_enc_key` right
/// after it (host-work-v1 §11.5).
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
    if entries.is_empty() || entries.len() as u64 > MAX_ENTRIES {
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
    ends_at_this_ceremony(&m, inputs)?;
    Ok(m)
}

/// host-work-v1 §11.5: the entries end at this host's `add_host` (seq `A`;
/// the signing gate closed, or the key entry's append failed), or at its
/// `host_enc_key` at `A` + 1 naming exactly the key this ceremony revealed
/// at its trust generation, with its `enc_sig` and no `retire_previous`
/// (the chain already verified that `enc_sig` against the `add_host`'s key).
/// Anything else fails the verification.
fn ends_at_this_ceremony(m: &Membership, inputs: &PairingInputs<'_>) -> Result<(), String> {
    use atem_client::membership::entry::Action;
    const NOT_AT_END: &str =
        "the device list must end at this host's add_host or at its host_enc_key right after it";
    let add_host = m
        .entries()
        .iter()
        .rev()
        .find(|e| matches!(&e.action, Action::AddHost { host } if host.host_id == inputs.host_id))
        .map_or(0, |e| e.seq);
    let head = m.head().seq;
    if head == add_host {
        return Ok(());
    }
    if head != add_host + 1 {
        return Err(NOT_AT_END.into());
    }
    match m.entries().last().map(|e| &e.action) {
        Some(Action::HostEncKey {
            host_id,
            host_trust_gen,
            enc_key,
            enc_sig,
            retire_previous,
        }) if host_id == inputs.host_id => {
            if *host_trust_gen != inputs.host_trust_gen
                || enc_key.alg() != Alg::X25519
                || enc_key.as_bytes() != inputs.enc_pub.as_slice()
                || enc_sig.as_slice() != inputs.enc_sig.as_slice()
                || *retire_previous
            {
                return Err(
                    "the device list's host_enc_key for this host isn't the key this ceremony revealed"
                        .into(),
                );
            }
            Ok(())
        }
        _ => Err(NOT_AT_END.into()),
    }
}

/// Pins the verified log for this host, with its `host_channel_key` and
/// the host encryption key the ceremony made and revealed (host-work-v1
/// §11.5; `r9::host_enc::keep_at_pin`, written before the list: a key that
/// can't be kept fails the pin), under `trust_gen.lock` held by the caller
/// (the ceremony's apply). In every build: the reveal carried the key.
pub fn pin_at_pairing_locked(
    pairing: &PairingPaths,
    m: &Membership,
    host_id: &str,
    host_trust_gen: u64,
    host_seed: &[u8; 32],
    enc_key: &crate::session_protocol::r9::host_enc::CeremonyKey,
) -> Result<(), String> {
    if enc_key.host_id() != host_id || enc_key.host_trust_gen() != host_trust_gen {
        return Err(format!(
            "the host encryption key was made for {} at trust generation {}, not {host_id} at {host_trust_gen}",
            enc_key.host_id(),
            enc_key.host_trust_gen()
        ));
    }
    let pin = HostPin {
        host_id: host_id.to_string(),
        host_trust_gen,
    };
    let lines = MembershipHost::pin_locked(
        pairing,
        &journal_of(pairing),
        &pin,
        m,
        host_seed,
        Some(enc_key),
    )?;
    let listed = m
        .host_enc_key(host_id)
        .is_some_and(|keys| keys.current.key.as_bytes() == enc_key.enc_pub().as_slice());
    for line in lines {
        eprintln!("atem: host encryption key: {line}");
    }
    eprintln!(
        "atem: host encryption key: {}",
        if listed {
            "the device list names it (signed in the verification)"
        } else {
            "the device list has no entry for it yet"
        }
    );
    Ok(())
}

/// A verification that failed after its pin (the cred side couldn't be
/// applied): the pin goes, so the host isn't left with a list its pairing
/// never confirmed, and the encryption key kept with it goes too; the record
/// of its id stays (the reveal handed it out; host-work-v1 §11.5). Best
/// effort; anything left fails closed (a leftover) until the next pin or
/// `atem unpair`. The caller holds `trust_gen.lock`.
pub fn unpin_locked(pairing: &PairingPaths) {
    let mut store = store::Store::new(pairing, &journal_of(pairing));
    if let Err(e) = store.remove(store::DlFile::State) {
        eprintln!("atem: device list: cannot take the pin back: {e}");
        return;
    }
    for file in LEFTOVERS
        .into_iter()
        .chain(DELETE_ONLY)
        .filter(|f| *f != store::DlFile::HostEncGenerated)
    {
        if let Err(e) = store.remove(file) {
            eprintln!("atem: device list: cannot take the pin back: {e}");
        }
    }
}
