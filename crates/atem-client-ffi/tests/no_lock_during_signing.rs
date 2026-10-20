//! No binding lock is held while the app's provider signs: a provider
//! whose `sign` waits (as an owner-auth prompt does) until another thread
//! has read the same objects must complete. Covers the channel signature
//! (`ClientConnection::on_accept`), a browser grant, an entry and a K-backup
//! entry. Before the fix, the grant and the handshake held the log's lock
//! through the prompt and a UI thread reading the log blocked.
#[path = "../../atem-client/tests/support/mod.rs"]
#[allow(unused_imports)]
mod support;

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use atem_client::KeyProvider as _;
use atem_client::provider::KeyId;
use atem_client_ffi::connection::ClientConnection;
use atem_client_ffi::log::MembershipLog;
use atem_client_ffi::provider::{AppKeyProvider, ProviderError};
use atem_client_ffi::publish::{EntryPublisher, KBackupWriter};
use atem_client_ffi::types::{
    BackupStep, ClientIdentity, ConnectionState, HostClock, KeyAlg, PrincipalKind, PublicKeyData,
    SignRequest,
};
use support::host::{HostConn, HostCore, HostSession};
use support::*;

const WALL: u64 = 1_793_264_001_000;

fn clock() -> HostClock {
    HostClock {
        wall_ms: WALL,
        mono_ms: 1_000,
        boot_id: "boot-1".into(),
    }
}

fn entries(v: &Vectors) -> Vec<String> {
    ["E1", "E2", "E3", "E4", "E5", "E6"]
        .iter()
        .map(|l| v.object(l).to_json().to_string())
        .collect()
}

type Probe = Box<dyn Fn() + Send + Sync>;

/// The test book's keys, whose `sign` runs `probe` on another thread and
/// waits for it (5 s at most) before signing.
struct Prompting {
    book: Book,
    probe: Mutex<Option<Arc<Probe>>>,
    prompts: Mutex<Vec<SignRequest>>,
}

impl Prompting {
    fn new() -> Arc<Self> {
        Arc::new(Prompting {
            book: Book::load(),
            probe: Mutex::new(None),
            prompts: Mutex::new(Vec::new()),
        })
    }

    fn set_probe(&self, probe: Probe) {
        *self.probe.lock().unwrap() = Some(Arc::new(probe));
    }
}

fn failed(e: impl std::fmt::Display) -> ProviderError {
    ProviderError::Failed {
        reason: e.to_string(),
    }
}

impl AppKeyProvider for Prompting {
    fn public_key(&self, key_id: String) -> Result<PublicKeyData, ProviderError> {
        let k = self
            .book
            .provider
            .public_key(&KeyId::new(key_id))
            .map_err(failed)?;
        Ok((&k).into())
    }

    fn sign(&self, request: SignRequest) -> Result<Vec<u8>, ProviderError> {
        if let Some(probe) = self.probe.lock().unwrap().clone() {
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                probe();
                let _ = tx.send(());
            });
            rx.recv_timeout(Duration::from_secs(5))
                .map_err(|_| failed("the other thread blocked on a binding lock"))?;
        }
        self.prompts.lock().unwrap().push(request.clone());
        let fields = atem_client::encoding::dec(&request.input).map_err(failed)?;
        let label = [
            atem_client::SignLabel::MembershipEntry,
            atem_client::SignLabel::BrowserGrant,
            atem_client::SignLabel::ChannelClient,
        ]
        .into_iter()
        .find(|l| l.as_str().as_bytes() == fields[0])
        .ok_or_else(|| failed("label"))?;
        let input = atem_client::SigningInput::new(label, fields[1]);
        self.book
            .provider
            .sign(&KeyId::new(request.key_id), &input)
            .map_err(failed)
    }

    fn x25519(&self, _: String, _: Vec<u8>) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::UnknownKey)
    }

    fn hpke_open(
        &self,
        _: String,
        _: Vec<u8>,
        _: Vec<u8>,
        _: Vec<u8>,
        _: Vec<u8>,
    ) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::UnknownKey)
    }
}

fn log_l() -> Arc<MembershipLog> {
    MembershipLog::verify(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        entries(&Vectors::load()),
        clock(),
    )
    .unwrap()
}

#[test]
fn the_channel_signature_holds_no_lock() {
    let book = Book::load();
    let log = log_l();
    let core_log = atem_client::membership::Membership::verify_chain(
        ACCOUNT,
        &genesis_hash(),
        &Vectors::load().entries(&["E1", "E2", "E3", "E4", "E5", "E6"]),
        &support::Clock::at(WALL).now,
    )
    .unwrap()
    .membership;
    let seed = unhex32(
        book.keys["host-a"]["host_key"]["secret_hex"]
            .as_str()
            .unwrap(),
    );
    let mut core = HostCore::new(
        core_log,
        support::Clock::at(WALL).now,
        &seed,
        vec![HostSession {
            session_id: "ses-aaaaaaaaaaaa".into(),
            process_gen: "22222222-2222-4222-8222-222222222222".into(),
            project: "h1.b982533d.abababababababababababababababababababababababababababababababab"
                .into(),
        }],
    );
    let mut host = HostConn::new(&mut core);
    let conn = ClientConnection::new(
        "host-a".into(),
        ClientIdentity {
            kind: PrincipalKind::Native,
            device_id: Some("dev-phone".into()),
            key_id: "dev-phone/auth".into(),
            grant_json: None,
        },
        None,
    )
    .unwrap();
    let provider = Prompting::new();
    let (l, c) = (log.clone(), conn.clone());
    provider.set_probe(Box::new(move || {
        let _ = l.head();
        let _ = l.members();
        assert_eq!(c.state(), ConnectionState::AwaitSignature);
    }));
    let init = conn.start(log.clone(), 1_000).unwrap();
    let accept = host.on_frame(&mut core, &init).frames.remove(0);
    let finish = conn
        .on_accept(accept, log.clone(), provider.clone(), 1_000)
        .unwrap();
    let first = host.on_frame(&mut core, &finish).frames.remove(0);
    let welcome = conn.on_welcome(first, log, 1_000).unwrap();
    assert_eq!(welcome.principal, "member:dev-phone");
    assert_eq!(provider.prompts.lock().unwrap().len(), 1);
}

#[test]
fn a_browser_grant_and_entries_hold_no_lock() {
    let book = Book::load();
    let log = log_l();
    let provider = Prompting::new();

    // A browser grant: a fresh confirmation while the UI reads the log.
    let l = log.clone();
    provider.set_probe(Box::new(move || {
        let _ = l.head();
        let _ = l.members();
    }));
    let browser = book.public("browser/auth");
    let grant = atem_client_ffi::push::issue_browser_grant(
        log.clone(),
        provider.clone(),
        "dev-phone/auth".into(),
        "dev-phone".into(),
        PublicKeyData {
            alg: KeyAlg::P256,
            raw: browser.as_bytes().to_vec(),
        },
        "host-a".into(),
        1,
        Some("ses-aaaaaaaaaaaa".into()),
        vec!["view".into()],
        WALL,
        WALL + 600_000,
    )
    .unwrap();
    assert!(grant.contains("atem-browser-grant"));

    // An entry: the UI reads the log and the publisher's state meanwhile.
    let body = log
        .draft_entry(
            "dev-phone".into(),
            WALL,
            r#"{"action":"remove","device_id":"svc-discord"}"#.into(),
        )
        .unwrap();
    let publisher = EntryPublisher::new();
    publisher.prepare(log.clone(), body).unwrap();
    let (l, p) = (log.clone(), publisher.clone());
    provider.set_probe(Box::new(move || {
        let _ = l.head();
        assert!(p.prepared_json().is_some());
    }));
    let request = publisher
        .sign(provider.clone(), "dev-phone/auth".into(), None)
        .unwrap();
    assert_eq!(request.expected.seq, 6);
    drop(publisher);

    // A K-backup entry: the UI reads the writer's step meanwhile.
    let kit = book.kit("recovery");
    let writer = KBackupWriter::start(
        log.clone(),
        vec!["b982533d".into()],
        (&kit.recovery_key()).into(),
        "dev-mac".into(),
    )
    .unwrap();
    let envelope = atem_client_ffi::kit::seal_k_backup(
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        1,
        (&kit.recovery_key()).into(),
        vec![atem_client_ffi::types::AccountKey {
            kid: "b982533d".into(),
            k: vec![7u8; 32],
        }],
    )
    .unwrap();
    assert!(matches!(
        writer.sealed(log.clone(), envelope, WALL).unwrap(),
        BackupStep::Sign { .. }
    ));
    let (l, w) = (log.clone(), writer.clone());
    provider.set_probe(Box::new(move || {
        let _ = l.head();
        assert!(matches!(w.step(), BackupStep::Sign { .. }));
    }));
    assert!(matches!(
        writer
            .sign(provider.clone(), "dev-mac/auth".into())
            .unwrap(),
        BackupStep::Put { .. }
    ));
    let purposes: Vec<_> = provider
        .prompts
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.purpose)
        .collect();
    use atem_client_ffi::types::SigningPurpose::*;
    assert_eq!(purposes, vec![BrowserGrant, Remove, KeyBackup]);
}
