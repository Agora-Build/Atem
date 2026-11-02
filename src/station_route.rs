//! Durable routing metadata; never an account trust or agent permission.
use anyhow::{Context as _, Result, anyhow, bail};
use atem_client::station_route::{Context, Offer, Request};
use serde::{Deserialize, Serialize};

use crate::{paths::PairingPaths, profile::Sources};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    pub offer: Offer,
    /// Only an R9 manager's durable allow-direct set clears this bit.
    pub direct_blocked: bool,
}

impl Selection {
    pub fn revision(&self) -> u64 {
        self.offer.request.route_revision + 1
    }
}

pub(crate) fn identity(
    src: &Sources,
    atem_id: &str,
) -> Result<(Context, zeroize::Zeroizing<String>)> {
    // The caller holds the pairing lock while authenticating an offer.
    let state = crate::pairing::load(src)?;
    let binding = state
        .binding
        .ok_or_else(|| anyhow!(crate::pairing::NO_BINDING))?;
    let record = crate::records::PairingRecord::load(&src.paths.pairing)?
        .ok_or_else(|| anyhow!(crate::pairing::NO_BINDING))?;
    if record.astation_id != binding.astation_id {
        bail!(crate::pairing::CHANGED);
    }
    // Expiry ends session authorization, not a previously authenticated
    // endpoint: r9 host-route proofs can still use the retained Station.
    let session = record
        .session
        .as_ref()
        .ok_or_else(|| anyhow!("no saved paired session for Station routing"))?;
    let pin = crate::session_protocol::membership::peek_pin_genesis(&src.paths.pairing);
    if pin
        .as_ref()
        .is_some_and(|p| p.1.host_trust_gen != state.host_trust_gen)
    {
        bail!("selected Station host generation does not match pinned membership");
    }
    Ok((
        Context {
            astation_id: binding.astation_id,
            atem_id: atem_id.into(),
            binding_id: binding.binding_id,
            host_trust_gen: state.host_trust_gen,
            session_id: session.session_id.clone(),
            host_device_id: pin.as_ref().map(|p| p.1.host_id.clone()),
            account_id: pin.as_ref().map(|p| p.0.clone()),
            genesis_hash: pin.map(|p| p.2),
        },
        zeroize::Zeroizing::new(session.token.clone()),
    ))
}

fn read(paths: &PairingPaths) -> Result<Option<Selection>> {
    let path = &paths.station_route;
    let Some(bytes) =
        crate::session_protocol::membership::store::read_private(path).map_err(|e| anyhow!(e))?
    else {
        return Ok(None);
    };
    if bytes.len() > 8192 {
        bail!("selected Station file too large");
    }
    serde_json::from_slice(&bytes)
        .context("selected Station file unreadable")
        .map(Some)
}

pub(crate) fn load(src: &Sources, context: &Context, token: &str) -> Result<Option<Selection>> {
    let Some(selection) = read(&src.paths.pairing)? else {
        return Ok(None);
    };
    if selection.offer.request.context != *context {
        return Ok(None);
    }
    selection
        .offer
        .verify(token.as_bytes())
        .map_err(|e| anyhow!(e))?;
    if selection.offer.request.route_revision >= atem_client::canonical::MAX_SAFE_INTEGER {
        bail!("selected Station revision exhausted");
    }
    Ok(Some(selection))
}

pub(crate) fn save(paths: &PairingPaths, selection: &Selection) -> Result<()> {
    crate::memory::crypto::write_private(&paths.station_route, &serde_json::to_vec(selection)?)
}

/// Both the automatic link and its reconnect use this. A saved selection
/// takes priority over config; an unavailable selected Station never falls
/// back to the compiled default.
pub(crate) fn destination(src: &Sources, atem_id: &str) -> Result<(String, bool)> {
    if std::fs::symlink_metadata(&src.paths.pairing.station_route)
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok((src.config.astation_relay_url().into(), false));
    }
    let (context, token) = identity(src, atem_id)?;
    match load(src, &context, &token)? {
        Some(s) => Ok((s.offer.relay_url, s.direct_blocked)),
        None => Ok((src.config.astation_relay_url().into(), false)),
    }
}

pub(crate) fn policy_revision(paths: &PairingPaths) -> Result<u64> {
    let Some((account, _, genesis)) = crate::session_protocol::membership::peek_pin_genesis(paths)
    else {
        if paths.host_policy.exists() || paths.host_policy_pending.exists() {
            bail!("host policy unreadable");
        }
        return Ok(0);
    };
    crate::session_protocol::r9::host_policy::current(paths, &account, &genesis)
        .map(|p| p.doc.revision)
        .map_err(|e| anyhow!(e))
}

/// Called only inside the R9 manager admission path after a durable
/// allow-direct set, including an explicit unchanged `false`.
pub(crate) fn allow_direct(
    paths: &PairingPaths,
    account: &str,
    genesis: &str,
    policy_revision: u64,
) -> Result<bool> {
    let Some(mut selection) = read(paths)? else {
        return Ok(false);
    };
    if policy_revision <= selection.offer.request.policy_revision {
        return Ok(false);
    }
    if selection
        .offer
        .request
        .context
        .account_id
        .as_deref()
        .is_some_and(|a| a != account)
        || selection
            .offer
            .request
            .context
            .genesis_hash
            .as_deref()
            .is_some_and(|g| g != genesis)
    {
        return Ok(false);
    }
    if selection.direct_blocked {
        selection.direct_blocked = false;
        save(paths, &selection)?;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) fn apply(
    src: &Sources,
    context: &Context,
    token: &str,
    request: &Request,
    offer: &Offer,
) -> Result<bool> {
    if offer.request != *request
        || request.context != *context
        || request.policy_revision != policy_revision(&src.paths.pairing)?
    {
        bail!("stale Station selection");
    }
    offer.verify(token.as_bytes()).map_err(|e| anyhow!(e))?;
    let previous = load(src, context, token)?;
    if request.route_revision != previous.as_ref().map_or(0, Selection::revision)
        || request.route_revision >= atem_client::canonical::MAX_SAFE_INTEGER
    {
        bail!("Station selection conflict");
    }
    let blocked = offer.relay_only || previous.as_ref().is_some_and(|s| s.direct_blocked);
    let changed = previous
        .as_ref()
        .is_none_or(|p| p.offer.relay_url != offer.relay_url || p.direct_blocked != blocked);
    save(
        &src.paths.pairing,
        &Selection {
            offer: offer.clone(),
            direct_blocked: blocked,
        },
    )?;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ATEM: &str = "atem-test";
    const ASTATION: &str = "astation-test";
    const TOKEN: &str = "test-session-token";

    fn setup() -> (
        tempfile::TempDir,
        crate::test_profile::Scope,
        Sources,
        Context,
        Request,
    ) {
        let (dir, scope) = crate::test_profile::temp();
        crate::pairing::tests::write_bound(
            dir.path(),
            ASTATION,
            15,
            "binding-test",
            ("session-test", TOKEN),
        );
        let src = Sources::in_dir(dir.path());
        let (context, _) = identity(&src, ATEM).unwrap();
        let request = Request {
            id: uuid::Uuid::new_v4().to_string(),
            context: context.clone(),
            route_revision: 0,
            policy_revision: 0,
        };
        (dir, scope, src, context, request)
    }

    #[test]
    fn selected_dev_and_custom_replace_default_and_persist_without_token() {
        let (_dir, _scope, src, context, mut request) = setup();
        for (revision, url) in [
            "https://station-dev.agora.build",
            "https://custom.example:8443",
        ]
        .into_iter()
        .enumerate()
        {
            request.route_revision = revision as u64;
            request.id = uuid::Uuid::new_v4().to_string();
            let offer = Offer::sign(request.clone(), url, true, TOKEN.as_bytes()).unwrap();
            assert!(apply(&src, &context, TOKEN, &request, &offer).unwrap());
            assert_eq!(destination(&src, ATEM).unwrap(), (url.into(), true));
            assert_eq!(
                load(&src, &context, TOKEN).unwrap().unwrap().revision(),
                revision as u64 + 1
            );
        }
        let bytes = std::fs::read(src.paths.pairing.dir().join("station_route.json")).unwrap();
        assert!(!String::from_utf8(bytes).unwrap().contains(TOKEN));
    }

    #[test]
    fn stale_forged_conflicting_and_old_context_offers_do_not_redirect() {
        let (_dir, _scope, src, context, request) = setup();
        let offer = Offer::sign(
            request.clone(),
            "https://station-dev.agora.build",
            true,
            TOKEN.as_bytes(),
        )
        .unwrap();
        let forged = Offer::sign(
            request.clone(),
            "https://forged.example",
            true,
            b"wrong-key",
        )
        .unwrap();
        assert!(apply(&src, &context, TOKEN, &request, &forged).is_err());
        apply(&src, &context, TOKEN, &request, &offer).unwrap();
        assert!(
            apply(&src, &context, TOKEN, &request, &offer).is_err(),
            "CAS prevents replay"
        );
        let mut different = request.clone();
        different.id = uuid::Uuid::new_v4().to_string();
        assert!(
            apply(&src, &context, TOKEN, &different, &offer).is_err(),
            "another connection's nonce"
        );
        different.context.account_id = Some("different-account".into());
        assert!(apply(&src, &different.context, TOKEN, &different, &offer).is_err());
        let mut changed = context.clone();
        changed.binding_id = "new-binding".into();
        assert!(load(&src, &changed, TOKEN).unwrap().is_none());
        assert!(load(&src, &context, "new-session-token").is_err());
        assert_eq!(
            destination(&src, ATEM).unwrap().0,
            "https://station-dev.agora.build"
        );
    }

    #[test]
    fn an_offer_cannot_relax_direct_block_only_an_r9_manager_can() {
        let (_dir, _scope, src, context, mut request) = setup();
        let offer = Offer::sign(
            request.clone(),
            "https://station-dev.agora.build",
            true,
            TOKEN.as_bytes(),
        )
        .unwrap();
        apply(&src, &context, TOKEN, &request, &offer).unwrap();
        request.route_revision = 1;
        request.id = uuid::Uuid::new_v4().to_string();
        let offer = Offer::sign(
            request.clone(),
            "https://custom.example",
            false,
            TOKEN.as_bytes(),
        )
        .unwrap();
        apply(&src, &context, TOKEN, &request, &offer).unwrap();
        assert!(destination(&src, ATEM).unwrap().1);
        assert!(!allow_direct(&src.paths.pairing, "account-test", &"12".repeat(32), 0).unwrap());
        assert!(
            destination(&src, ATEM).unwrap().1,
            "older decisions cannot undo a newer route restriction"
        );
        allow_direct(&src.paths.pairing, "account-test", &"12".repeat(32), 1).unwrap();
        assert!(!destination(&src, ATEM).unwrap().1);
    }

    #[test]
    fn damaged_or_unwritable_selection_never_falls_back_to_production() {
        let (_dir, _scope, src, context, request) = setup();
        let path = src.paths.pairing.dir().join("station_route.json");
        std::fs::write(&path, b"damaged").unwrap();
        assert!(destination(&src, ATEM).is_err());
        std::fs::remove_file(&path).unwrap();
        let _fault = crate::memory::crypto::fail_writes_to(&path);
        let offer = Offer::sign(
            request.clone(),
            "https://station-dev.agora.build",
            true,
            TOKEN.as_bytes(),
        )
        .unwrap();
        assert!(apply(&src, &context, TOKEN, &request, &offer).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn session_expiry_does_not_lose_the_retained_r9_transport_endpoint() {
        let (_dir, _scope, src, context, request) = setup();
        let offer = Offer::sign(
            request.clone(),
            "https://station-dev.agora.build",
            true,
            TOKEN.as_bytes(),
        )
        .unwrap();
        apply(&src, &context, TOKEN, &request, &offer).unwrap();
        crate::records::PairingRecord::update_locked(&src.paths.pairing, ASTATION, |record| {
            record.session.as_mut().unwrap().last_activity = 0
        })
        .unwrap();
        assert_eq!(
            destination(&src, ATEM).unwrap(),
            ("https://station-dev.agora.build".into(), true)
        );
    }
}
