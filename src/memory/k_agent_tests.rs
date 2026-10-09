//! The key agent holding `K` (build step 2b): installed from signed grants,
//! kept sealed, used only through `Crypt`, retired by signed states.
use base64::{Engine, engine::general_purpose::STANDARD};

use crate::memory::account_keys::CryptOp;
use crate::memory::crypto::{EncryptionMode, fail_writes_to};
use crate::memory::device_keys::UnlockAuthKey;
use crate::memory::fake_astation::{
    ACCOUNT, ASTATION_ID, DEVICE_ID, UnlockedDevice, migrated_device, pin_as, sealed_account_keys,
    sealed_device, set_state, set_state_as, unlock_with,
};
use crate::memory::grant::seal_k_grant;
use crate::memory::key_agent::{KeyAgentApi, build_unlock_request, error_of, holds_k, test_agent};
use crate::memory::statements::FakeAstation;
use crate::memory::storage_key::{SealedDeviceKeys, new_storage_key};
use crate::memory::trust::TrustStore;

const A: &str = "0123abcd";
const B: &str = "89abcdef";

/// Locks the agent and unlocks it again through the fake Astation: what the
/// agent then holds came from the sealed file.
fn relock(device: &UnlockedDevice) {
    device.agent.lock_keys().unwrap();
    unlock_with(device.agent.as_ref(), &device.server, &device.paths).unwrap();
}

fn seal(device: &UnlockedDevice, plain: &[u8]) -> String {
    device
        .agent
        .crypt(ASTATION_ID, vec![CryptOp::seal("mem", "content", plain)])
        .unwrap()
        .remove(0)
        .into_text()
        .unwrap()
}

fn open(device: &UnlockedDevice, value: &str) -> anyhow::Result<Vec<u8>> {
    let out = device
        .agent
        .crypt(ASTATION_ID, vec![CryptOp::open("mem", "content", value)])?
        .remove(0);
    Ok(out.into_plain()?.to_vec())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_granted_k_is_kept_sealed_and_never_handed_out() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::On, Some(A));
    // The reply names the kid only.
    let kid: String = device
        .agent
        .install_grant(ASTATION_ID, &device.grant(A, [42; 32]))
        .unwrap();
    assert_eq!(kid, A);
    assert_eq!(
        device.agent.held_kid(ASTATION_ID).unwrap().as_deref(),
        Some(A)
    );
    let sealed = seal(&device, b"fact");
    assert_eq!(open(&device, &sealed).unwrap(), b"fact");
    // On disk K is only inside the sealed payload.
    let raw = String::from_utf8(std::fs::read(&device.paths.device_keys_sealed).unwrap()).unwrap();
    assert!(!raw.contains(&STANDARD.encode([42u8; 32])));
    assert!(!raw.contains(&hex(&[42u8; 32])));
    // Locked, K is gone from memory; the sealed file still carries it.
    device.agent.lock_keys().unwrap();
    assert!(
        error_of(
            device
                .agent
                .crypt(ASTATION_ID, vec![CryptOp::keyed_hash(b"x")])
        )
        .contains("atem cred unlock")
    );
    assert_eq!(device.sealed_accounts().current_kid(ACCOUNT), Some(A));
    // Unlocked again, it comes from the file.
    unlock_with(device.agent.as_ref(), &device.server, &device.paths).unwrap();
    assert_eq!(open(&device, &sealed).unwrap(), b"fact");
}

#[test]
fn a_grant_must_name_the_kid_of_the_latest_signed_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    let error = error_of(
        device
            .agent
            .install_grant(ASTATION_ID, &device.grant(A, [1; 32])),
    );
    assert!(error.contains("before the account mode"), "{error}");
    device.state(EncryptionMode::On, Some(A));
    let error = error_of(
        device
            .agent
            .install_grant(ASTATION_ID, &device.grant(B, [2; 32])),
    );
    assert!(error.contains("does not match"), "{error}");
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
    assert!(device.sealed_accounts().is_empty());
}

#[test]
fn a_grant_with_an_invalid_kid_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::On, Some("NOT-A-KID"));
    let error = error_of(
        device
            .agent
            .install_grant(ASTATION_ID, &device.grant("NOT-A-KID", [1; 32])),
    );
    assert!(error.contains("key id"), "{error}");
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
}

#[test]
fn crypt_needs_an_unlocked_agent_a_signed_state_and_k() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, server, _) = sealed_device(dir.path(), "0a1b2c3d");
    let agent = test_agent(&paths);
    let hash = || vec![CryptOp::keyed_hash(b"x")];
    assert!(error_of(agent.crypt(ASTATION_ID, hash())).contains("atem cred unlock"));
    unlock_with(&agent, &server, &paths).unwrap();
    assert!(error_of(agent.crypt(ASTATION_ID, hash())).contains("signed encryption state"));
    set_state(&paths, &server.astation, EncryptionMode::On, Some(A), 2);
    assert!(error_of(agent.crypt(ASTATION_ID, hash())).contains("requires encryption"));
    assert!(error_of(agent.crypt("astation-2", hash())).contains("isn't verified"));
}

#[test]
fn a_failed_re_seal_installs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::Enabling, A, [1; 32]);
    device.state(EncryptionMode::Enabling, Some(B));
    let before = std::fs::read(&device.paths.device_keys_sealed).unwrap();
    {
        let _failing = fail_writes_to(&device.paths.device_keys_sealed);
        assert!(
            device
                .agent
                .install_grant(ASTATION_ID, &device.grant(B, [2; 32]))
                .is_err()
        );
    }
    assert_eq!(
        std::fs::read(&device.paths.device_keys_sealed).unwrap(),
        before
    );
    assert_eq!(
        device.agent.held_kid(ASTATION_ID).unwrap().as_deref(),
        Some(A)
    );
    // The grant comes again (keyRequest) and installs.
    device
        .agent
        .install_grant(ASTATION_ID, &device.grant(B, [2; 32]))
        .unwrap();
    assert_eq!(
        device.agent.held_kid(ASTATION_ID).unwrap().as_deref(),
        Some(B)
    );
    assert_eq!(device.sealed_accounts().current_kid(ACCOUNT), Some(B));
}

#[test]
fn a_failed_prune_write_does_not_fail_crypt_or_held_kid() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::Enabling, A, [1; 32]);
    device.set_key(EncryptionMode::Enabling, B, [2; 32]);
    device.state(EncryptionMode::On, Some(B));
    {
        let _failing = fail_writes_to(&device.paths.device_keys_sealed);
        assert_eq!(
            device.agent.held_kid(ASTATION_ID).unwrap().as_deref(),
            Some(B)
        );
        let sealed = seal(&device, b"fact");
        assert_eq!(open(&device, &sealed).unwrap(), b"fact");
    }
    // The file still has A; the next call prunes it there too.
    assert_eq!(device.sealed_accounts().previous_kids(ACCOUNT), [A]);
    device.agent.held_kid(ASTATION_ID).unwrap();
    assert!(device.sealed_accounts().previous_kids(ACCOUNT).is_empty());
}

#[test]
fn k_survives_a_storage_key_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, A, [42; 32]);
    let rotation = device.agent.begin_rotation(ASTATION_ID).unwrap();
    let ack = device.server.accept_rotation(&rotation).unwrap();
    let (new_kid, confirm) = device.agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
    device.server.confirm(&confirm).unwrap();
    // The promoted file is under the new storage key and carries K.
    let current = SealedDeviceKeys::load_from(&device.paths.device_keys_sealed)
        .unwrap()
        .unwrap();
    assert_eq!(current.storage_kid, new_kid);
    assert_eq!(device.sealed_accounts().current_kid(ACCOUNT), Some(A));
    relock(&device);
    assert!(holds_k(device.agent.as_ref(), ASTATION_ID));
}

#[test]
fn k_installed_mid_rotation_also_reaches_the_next_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::On, Some(A));
    // Phase 1 wrote .next before K arrived.
    let rotation = device.agent.begin_rotation(ASTATION_ID).unwrap();
    device
        .agent
        .install_grant(ASTATION_ID, &device.grant(A, [42; 32]))
        .unwrap();
    let ack = device.server.accept_rotation(&rotation).unwrap();
    let (_, confirm) = device.agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
    device.server.confirm(&confirm).unwrap();
    assert_eq!(device.sealed_accounts().current_kid(ACCOUNT), Some(A));
    relock(&device);
    assert!(
        holds_k(device.agent.as_ref(), ASTATION_ID),
        "the promoted file carries K"
    );
}

#[test]
fn off_drops_k_and_on_drops_previous_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::Enabling, A, [1; 32]);
    let old = seal(&device, b"old");
    device.set_key(EncryptionMode::Enabling, B, [2; 32]);
    assert_eq!(
        open(&device, &old).unwrap(),
        b"old",
        "migration still reads A"
    );
    assert_eq!(device.sealed_accounts().previous_kids(ACCOUNT), [A]);
    device.state(EncryptionMode::On, Some(B));
    assert!(format!("{:#}", open(&device, &old).err().unwrap()).contains("unavailable key id"));
    relock(&device);
    let sealed = device.sealed_accounts();
    assert_eq!(sealed.current_kid(ACCOUNT), Some(B));
    assert!(
        sealed.previous_kids(ACCOUNT).is_empty(),
        "A is gone from the sealed file too"
    );
    assert!(holds_k(device.agent.as_ref(), ASTATION_ID));
    device.state(EncryptionMode::Off, None);
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
    assert!(device.sealed_accounts().is_empty());
    relock(&device);
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
}

#[test]
fn an_off_state_that_arrived_while_locked_is_applied_at_unlock() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, A, [1; 32]);
    device.agent.lock_keys().unwrap();
    device.state(EncryptionMode::Off, None);
    unlock_with(device.agent.as_ref(), &device.server, &device.paths).unwrap();
    device.agent.lock_keys().unwrap();
    // Re-sealed at that unlock: the file no longer carries K.
    assert!(device.sealed_accounts().is_empty());
    device.state(EncryptionMode::On, Some(A));
    unlock_with(device.agent.as_ref(), &device.server, &device.paths).unwrap();
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
}

#[test]
fn check_grant_opens_against_given_pins_and_stores_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::On, Some(A));
    let entry = TrustStore::load_from(&device.paths.trust)
        .unwrap()
        .verified(ASTATION_ID)
        .unwrap()
        .clone();
    assert_eq!(
        device
            .agent
            .check_grant(&device.grant(A, [1; 32]), &entry)
            .unwrap(),
        A
    );
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
    assert!(device.sealed_accounts().is_empty());
}

#[test]
fn an_unlock_of_a_lone_previous_file_keeps_k() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, A, [42; 32]);
    device.agent.lock_keys().unwrap();
    std::fs::rename(
        &device.paths.device_keys_sealed,
        &device.paths.device_keys_prev,
    )
    .unwrap();
    unlock_with(device.agent.as_ref(), &device.server, &device.paths).unwrap();
    assert!(!device.paths.device_keys_prev.exists(), "promoted");
    assert_eq!(device.sealed_accounts().current_kid(ACCOUNT), Some(A));
    assert!(holds_k(device.agent.as_ref(), ASTATION_ID));
}

#[test]
fn unlocked_via_the_previous_file_k_goes_there_and_never_into_a_foreign_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.agent.lock_keys().unwrap();
    std::fs::rename(
        &device.paths.device_keys_sealed,
        &device.paths.device_keys_prev,
    )
    .unwrap();
    // A current file under a storage key the agent will not hold appears
    // during the unlock.
    let challenge = device.agent.begin_unlock(ASTATION_ID).unwrap();
    let unlock_auth = UnlockAuthKey::load_from(&device.paths.unlock_auth_key)
        .unwrap()
        .unwrap();
    let request = build_unlock_request(&challenge, "boot-1", 1, &unlock_auth);
    SealedDeviceKeys::seal_with(
        &device.keys,
        &Default::default(),
        DEVICE_ID,
        "4e5f6a7b",
        &new_storage_key(),
    )
    .unwrap()
    .save_to(&device.paths.device_keys_sealed)
    .unwrap();
    let foreign = std::fs::read(&device.paths.device_keys_sealed).unwrap();
    let grant = device.server.grant_unlock(&request).unwrap();
    device
        .agent
        .finish_unlock(ASTATION_ID, &request.statement, &grant)
        .unwrap();
    device.set_key(EncryptionMode::On, A, [42; 32]);
    assert_eq!(
        std::fs::read(&device.paths.device_keys_sealed).unwrap(),
        foreign
    );
    let prev = sealed_account_keys(
        &device.server,
        &device.paths,
        &device.paths.device_keys_prev,
    );
    assert_eq!(prev.current_kid(ACCOUNT), Some(A));
}

#[test]
fn the_first_escrow_and_a_crash_after_it_keep_k() {
    let dir = tempfile::tempdir().unwrap();
    let (paths, mut server, keys, agent) = migrated_device(dir.path());
    set_state(&paths, &server.astation, EncryptionMode::On, Some(A), 2);
    let grant = seal_k_grant(
        &server.astation,
        ACCOUNT,
        DEVICE_ID,
        keys.device_pub(),
        A,
        [42; 32],
    );
    // Installed before Astation holds the storage key.
    agent.install_grant(ASTATION_ID, &grant).unwrap();
    let rotation = agent.begin_rotation(ASTATION_ID).unwrap();
    let ack = server.accept_rotation(&rotation).unwrap();
    let (_, confirm) = agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
    server.confirm(&confirm).unwrap();
    assert_eq!(
        sealed_account_keys(&server, &paths, &paths.device_keys_sealed).current_kid(ACCOUNT),
        Some(A)
    );
    agent.lock_keys().unwrap();
    unlock_with(&agent, &server, &paths).unwrap();
    assert!(holds_k(&agent, ASTATION_ID));
    // A crash after the escrow was recorded left the plain file: the next
    // start keeps the escrowed sealed file, and K with it.
    drop(agent);
    keys.save_to(&paths.device_keys).unwrap();
    let agent = test_agent(&paths);
    assert!(!paths.device_keys.exists());
    unlock_with(&agent, &server, &paths).unwrap();
    assert!(holds_k(&agent, ASTATION_ID));
}

#[test]
fn a_grant_a_newer_signed_state_retired_at_once_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::On, Some(A));
    // A second verified Astation names the same account: its newer signed
    // state turned encryption off.
    let other = FakeAstation::new();
    pin_as(&device.paths, "astation-2", &other, &device.keys, false);
    set_state_as(
        &device.paths,
        "astation-2",
        &other,
        EncryptionMode::Off,
        None,
        9,
    );
    let before = std::fs::read(&device.paths.device_keys_sealed).unwrap();
    let error = error_of(
        device
            .agent
            .install_grant(ASTATION_ID, &device.grant(A, [42; 32])),
    );
    assert!(
        error.contains("a newer signed state retired this key"),
        "{error}"
    );
    assert!(!holds_k(device.agent.as_ref(), ASTATION_ID));
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
    assert_eq!(
        std::fs::read(&device.paths.device_keys_sealed).unwrap(),
        before,
        "nothing is sealed for a key that is dropped at once"
    );
}

#[test]
fn a_failed_prune_write_is_logged_once_until_it_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::Enabling, A, [1; 32]);
    device.set_key(EncryptionMode::Enabling, B, [2; 32]);
    device.state(EncryptionMode::On, Some(B));
    let logged = |device: &UnlockedDevice| device.agent.lock().unwrap().prune_failures_logged;
    {
        let _failing = fail_writes_to(&device.paths.device_keys_sealed);
        for _ in 0..3 {
            device.agent.held_kid(ASTATION_ID).unwrap();
            seal(&device, b"fact");
        }
        assert_eq!(logged(&device), 1, "logged when the keys first go unsaved");
    }
    device.agent.held_kid(ASTATION_ID).unwrap();
    assert_eq!(logged(&device), 1);
    assert!(device.sealed_accounts().previous_kids(ACCOUNT).is_empty());
    // A later failure is a new one: logged again.
    device.set_key(EncryptionMode::Enabling, A, [3; 32]);
    device.state(EncryptionMode::Off, None);
    {
        let _failing = fail_writes_to(&device.paths.device_keys_sealed);
        device.agent.held_kid(ASTATION_ID).unwrap();
        device.agent.held_kid(ASTATION_ID).unwrap();
    }
    assert_eq!(logged(&device), 2);
}

#[test]
fn a_failed_current_file_write_mid_rotation_installs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::On, Some(A));
    let rotation = device.agent.begin_rotation(ASTATION_ID).unwrap();
    let before = std::fs::read(&device.paths.device_keys_sealed).unwrap();
    {
        // .next is written first and succeeds; the current file fails.
        let _failing = fail_writes_to(&device.paths.device_keys_sealed);
        assert!(
            device
                .agent
                .install_grant(ASTATION_ID, &device.grant(A, [42; 32]))
                .is_err()
        );
    }
    assert!(
        !holds_k(device.agent.as_ref(), ASTATION_ID),
        "memory has no K"
    );
    assert_eq!(
        std::fs::read(&device.paths.device_keys_sealed).unwrap(),
        before,
        "the current file is unchanged"
    );
    let ack = device.server.accept_rotation(&rotation).unwrap();
    let (_, confirm) = device.agent.confirm_rotation(ASTATION_ID, &ack).unwrap();
    device.server.confirm(&confirm).unwrap();
    assert_eq!(device.agent.held_kid(ASTATION_ID).unwrap(), None);
    // .next was written before the current file failed: the promoted file
    // already carries K (harmless: the signed state names it).
    assert_eq!(device.sealed_accounts().current_kid(ACCOUNT), Some(A));
    // The grant comes again (keyRequest) and installs.
    device
        .agent
        .install_grant(ASTATION_ID, &device.grant(A, [42; 32]))
        .unwrap();
    assert!(holds_k(device.agent.as_ref(), ASTATION_ID));
    assert_eq!(device.sealed_accounts().current_kid(ACCOUNT), Some(A));
}

#[test]
fn key_needed_follows_the_newest_signed_state_of_the_account() {
    use crate::memory::verification::key_needed;
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.state(EncryptionMode::On, Some(A));
    let other = FakeAstation::new();
    pin_as(&device.paths, "astation-2", &other, &device.keys, false);
    // astation-1's state is stale: the newer one, from astation-2, is off.
    set_state_as(
        &device.paths,
        "astation-2",
        &other,
        EncryptionMode::Off,
        None,
        9,
    );
    let agent = device.agent.as_ref();
    assert!(!key_needed(&device.paths, agent, ASTATION_ID).unwrap());
    assert!(!key_needed(&device.paths, agent, "astation-2").unwrap());
    // The newer state moves to B: K for B is what both need.
    set_state_as(
        &device.paths,
        "astation-2",
        &other,
        EncryptionMode::On,
        Some(B),
        10,
    );
    assert!(key_needed(&device.paths, agent, ASTATION_ID).unwrap());
    let grant = seal_k_grant(
        &other,
        ACCOUNT,
        DEVICE_ID,
        device.keys.device_pub(),
        B,
        [7; 32],
    );
    agent.install_grant("astation-2", &grant).unwrap();
    assert!(!key_needed(&device.paths, agent, ASTATION_ID).unwrap());
    assert!(!key_needed(&device.paths, agent, "astation-2").unwrap());
}

#[test]
fn a_prune_error_before_anything_changed_is_logged_once() {
    let dir = tempfile::tempdir().unwrap();
    let mut device = UnlockedDevice::new(dir.path());
    device.set_key(EncryptionMode::On, A, [1; 32]);
    let logged = |device: &UnlockedDevice| device.agent.lock().unwrap().prune_failures_logged;
    let trust = std::fs::read(&device.paths.trust).unwrap();
    std::fs::write(&device.paths.trust, b"not json").unwrap();
    for _ in 0..3 {
        assert!(device.agent.held_kid(ASTATION_ID).is_err());
    }
    assert_eq!(
        logged(&device),
        1,
        "an unreadable cred_state.json is logged once"
    );
    std::fs::write(&device.paths.trust, trust).unwrap();
    assert_eq!(
        device.agent.held_kid(ASTATION_ID).unwrap().as_deref(),
        Some(A)
    );
    assert_eq!(logged(&device), 1);
}
