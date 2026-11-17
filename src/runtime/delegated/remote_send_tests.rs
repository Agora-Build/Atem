// The sending host's delivery rows (design II.4.4; collaboration §7): a
// list of this host `a` and hosts `b`, `c` with keys and a project that
// lists all three, the rows reserved while context publishes, sealed once
// at acceptance, moved by the put engine, accepted by the results back.
use super::*;
use crate::runtime::delegated::send_plan::{Me, plan};
use crate::session_protocol::membership::r9log::{MAC, TestLog, secret};
use atem_client::host_mail::mailbox::PutRefusal;
use atem_client::host_mail::{VerifiedMail, unseal_envelope};
use atem_client::membership::{ProjectOp, project_set};
use atem_client::session::host_work::{ContextKind, ContextSnapshot, digest};
use atem_client::{KeyId, SoftwareKeys};

const ME: Me<'static> = Me {
    host_id: "a",
    atem_id: "a",
    host_trust_gen: 1,
};
const T0: u64 = 1_800_000_000_000;

fn list() -> TestLog {
    let mut log = TestLog::genesis("acct", &secret("rows astation"));
    for host in ["a", "b", "c"] {
        log.add_host(host, 1, &secret(host));
    }
    for host in ["a", "b", "c"] {
        crate::runtime::delegated::send_plan::tests::add_enc(&mut log, host);
    }
    log.append(
        MAC,
        project_set(
            "build",
            ["a", "b", "c"],
            [ProjectOp::Message, ProjectOp::Notify, ProjectOp::Prompt],
            0,
        )
        .unwrap(),
    );
    log
}

fn store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    prepare(&store).unwrap();
    (dir, store)
}

/// The stage-1 message a send of `to` from `a` makes, with `context`.
fn local(context: Vec<ContextSnapshot>) -> Message {
    Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        workflow_id: uuid::Uuid::new_v4().to_string(),
        sender: "local".into(),
        kind: Default::default(),
        reply_to: None,
        from_session: Some("ses-aaaaaaaaaaaa".into()),
        created_at: T0,
        expires_at: T0 + 3_600_000,
        recipients: vec![],
        text: "adapt the client".into(),
        context,
        mark: None,
    }
}

fn snapshot(text: &str) -> ContextSnapshot {
    ContextSnapshot {
        kind: ContextKind::Memory,
        id: "mem_1".into(),
        version: 1,
        digest: digest(text.as_bytes()),
        text: text.into(),
    }
}

/// (host, state, code, detail) of `message`'s rows.
fn rows_of(store: &Store, message: &str) -> Vec<(String, String, Option<String>, String)> {
    rows(&store.db, message)
        .unwrap()
        .into_iter()
        .map(|r| (r.host_id, r.state, r.code, r.detail))
        .collect()
}

fn engine_bytes(store: &Store, host: &str, object: &str) -> (i64, Vec<u8>) {
    store
        .db
        .query_row(
            "SELECT n, bytes FROM mail_outbox WHERE target_host=?1 AND object_id=?2",
            [host, object],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

fn commit(
    store: &Store,
    log: &TestLog,
    me: Me,
    message: &Message,
    part: &RemotePart,
) -> Result<()> {
    let key = HostKey::new(&secret("a"));
    let sealer = Sealer {
        list: &log.log,
        me,
        account: "acct",
        key: &key,
    };
    let tx = store.db.unchecked_transaction()?;
    commit_request(&tx, &sealer, message, part)?;
    tx.commit()?;
    Ok(())
}

/// Each target's envelope is sealed once to its current key in the
/// committed list, signed by this host at the committed head, as one
/// host-sender Message carrying the frozen context; its exact bytes are
/// the engine's, committed with the row `ready`.
#[test]
fn each_hosts_envelope_is_sealed_once_with_the_frozen_context() {
    let (_dir, store) = store();
    let log = list();
    let to = ["project:build+tag:auth".to_string(), "atem:c".to_string()];
    let p = plan(&log.log, ME, &to, false).unwrap();
    let part = RemotePart::of(&p, "acct");
    let message = local(vec![snapshot("the contract changed")]);
    commit(&store, &log, ME, &message, &part).unwrap();
    let ready = "waiting to be put in the host's mailbox".to_string();
    assert_eq!(
        rows_of(&store, &message.message_id),
        [
            ("b".into(), "ready".into(), None, ready.clone()),
            ("c".into(), "ready".into(), None, ready),
        ]
    );
    for (host, recipient) in ["b", "c"].iter().zip(&part.recipients) {
        let (_, bytes) = engine_bytes(&store, host, &message.message_id);
        let object = atem_client::host_mail::parse_object(&bytes).unwrap();
        assert_eq!(
            object.to_json().to_string().into_bytes(),
            bytes,
            "kept exactly"
        );
        let (_, body) = atem_client::host_mail::MailBody::from_object(&object).unwrap();
        assert_eq!(body.signed_at_head, log.log.head());
        assert_eq!(body.recipient.host_id, *host);
        assert_eq!((body.created_at, body.expires_at), (T0, T0 + 3_600_000));
        let sender = log.log.host("a").unwrap().host_key.clone();
        let verified = VerifiedMail::verify(&object, &sender).unwrap();
        let mut keys = SoftwareKeys::new();
        keys.insert_x25519(KeyId::new("enc"), &secret(&format!("{host} enc")));
        let EnvelopePlain::Request { message: sent } =
            unseal_envelope(&keys, &KeyId::new("enc"), &verified).unwrap()
        else {
            panic!("not a request");
        };
        assert_eq!(sent.sender, "host:a");
        assert_eq!(sent.message_id, message.message_id);
        assert_eq!(sent.context, message.context);
        assert_eq!(sent.from_session, None);
        assert_eq!(sent.recipients, part.recipients);
        assert!(sent.valid_from_host("a"));
        assert_eq!(
            sent.recipients.iter().filter(|r| r == &recipient).count(),
            1
        );
    }
    // Accepting again changes no byte: sealed once.
    let before = engine_bytes(&store, "b", &message.message_id);
    commit(&store, &log, ME, &message, &part).unwrap();
    assert_eq!(engine_bytes(&store, "b", &message.message_id), before);
}

/// A target that can't be sealed to now has its row refused with why;
/// this host no longer signing refuses them all.
#[test]
fn a_target_that_cant_be_sealed_to_is_refused_with_why() {
    let (_dir, store) = store();
    let mut log = list();
    let p = plan(&log.log, ME, &["atem:b".into(), "atem:c".into()], false).unwrap();
    let part = RemotePart::of(&p, "acct");
    log.append(
        MAC,
        atem_client::membership::entry::Action::RemoveHost {
            host_id: "c".into(),
        },
    );
    let message = local(vec![]);
    commit(&store, &log, ME, &message, &part).unwrap();
    let rows = rows_of(&store, &message.message_id);
    assert_eq!(rows[0].1, "ready");
    assert_eq!(
        rows[1],
        (
            "c".into(),
            "refused".into(),
            None,
            "host c is no longer a current host at trust generation 1".into()
        )
    );
    let stale = Me {
        host_trust_gen: 2,
        ..ME
    };
    let message = local(vec![]);
    commit(&store, &log, stale, &message, &part).unwrap();
    assert!(
        rows_of(&store, &message.message_id)
            .iter()
            .all(|r| r.1 == "refused" && r.3.contains("trust generation 2")),
        "{:?}",
        rows_of(&store, &message.message_id)
    );
}

/// While its context publishes a row is `publishing`; a publication
/// refused or expired takes its rows with it, in the same write.
#[test]
fn publishing_rows_follow_their_publication() {
    let (_dir, store) = store();
    let log = list();
    let p = plan(&log.log, ME, &["atem:b".into()], false).unwrap();
    let part = RemotePart::of(&p, "acct");
    for (state, detail) in [
        ("refused", "context changed"),
        ("expired", "expired before context publication"),
    ] {
        let message = local(vec![]);
        let tx = store.db.unchecked_transaction().unwrap();
        tx.execute(
            "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
            VALUES(?1,'{}','publishing','',0,0)",
            [&message.message_id],
        )
        .unwrap();
        reserve(&tx, &message.message_id, &part, T0).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            rows_of(&store, &message.message_id),
            [("b".into(), "publishing".into(), None, PUBLISHING.into())]
        );
        store
            .db
            .execute(
                "UPDATE outbox SET state=?2, detail=?3 WHERE message_id=?1",
                [&message.message_id, state, detail],
            )
            .unwrap();
        assert_eq!(
            rows_of(&store, &message.message_id),
            [("b".into(), state.into(), None, detail.into())]
        );
    }
}

/// The engine moves a request's row: stored `sent` (and stays so when
/// stored again), refused with the Station's code, expired; the results
/// back accept it, settling its engine row.
#[test]
fn the_engine_moves_the_rows_and_acceptance_settles_them() {
    let (_dir, store) = store();
    let log = list();
    let p = plan(&log.log, ME, &["atem:b".into(), "atem:c".into()], false).unwrap();
    let part = RemotePart::of(&p, "acct");
    let message = local(vec![]);
    commit(&store, &log, ME, &message, &part).unwrap();
    let (b, _) = engine_bytes(&store, "b", &message.message_id);
    let (c, _) = engine_bytes(&store, "c", &message.message_id);
    let states = || -> Vec<(String, Option<String>)> {
        rows_of(&store, &message.message_id)
            .into_iter()
            .map(|r| (r.1, r.2))
            .collect()
    };
    outbox::stored(&store, b, T0).unwrap();
    outbox::refused(&store, c, PutRefusal::Quota, T0, outbox::tests::AT).unwrap();
    assert_eq!(
        states(),
        [
            ("sent".into(), None),
            ("ready".into(), Some("quota".into()))
        ]
    );
    outbox::stored(&store, b, T0 + outbox::RESEND_MS).unwrap();
    // `forbidden` waits for a later link or a moved list (ruling R41).
    outbox::refused(&store, c, PutRefusal::Forbidden, T0, outbox::tests::AT).unwrap();
    assert_eq!(
        rows_of(&store, &message.message_id)[1],
        (
            "c".into(),
            "ready".into(),
            Some("forbidden".into()),
            "the Station refused it (forbidden); put again on a later link or once the device list moves".into()
        )
    );
    outbox::refused(&store, c, PutRefusal::IdReused, T0, outbox::tests::AT).unwrap();
    assert_eq!(
        states(),
        [
            ("sent".into(), None),
            ("refused".into(), Some("id_reused".into()))
        ]
    );
    let tx = store.db.unchecked_transaction().unwrap();
    assert!(accepted(&tx, &message.message_id, "b").unwrap());
    assert!(
        !accepted(&tx, &message.message_id, "c").unwrap(),
        "refused stays refused"
    );
    tx.commit().unwrap();
    assert_eq!(states()[0].0, "accepted");
    assert_eq!(
        outbox::row_state(&store.db, b).unwrap().unwrap().state,
        "done"
    );
    // Expiry, for one never accepted.
    let other = local(vec![]);
    commit(&store, &log, ME, &other, &part).unwrap();
    outbox::expire(&store, other.expires_at).unwrap();
    assert!(
        rows_of(&store, &other.message_id)
            .iter()
            .all(|r| r.1 == "expired")
    );
}

/// A Station refusal of a resend says only that this copy wasn't stored
/// again (review M2): a `sent` row stays `sent`, the code recorded, and
/// the results back may still accept it; a Station `expired` on a stored
/// object is the row's expiry. Each state says what it is (review L2).
#[test]
fn a_refused_resend_keeps_a_sent_row_and_each_state_says_why() {
    let (_dir, store) = store();
    let log = list();
    let p = plan(&log.log, ME, &["atem:b".into(), "atem:c".into()], false).unwrap();
    let part = RemotePart::of(&p, "acct");
    let message = local(vec![]);
    commit(&store, &log, ME, &message, &part).unwrap();
    let (b, _) = engine_bytes(&store, "b", &message.message_id);
    let (c, _) = engine_bytes(&store, "c", &message.message_id);
    let row = |host: &str| {
        rows_of(&store, &message.message_id)
            .into_iter()
            .find(|r| r.0 == host)
            .unwrap()
    };
    outbox::refused(&store, b, PutRefusal::Quota, T0, outbox::tests::AT).unwrap();
    assert_eq!(
        row("b").3,
        "the Station's quota is full; put again after a backoff"
    );
    for n in [b, c] {
        outbox::stored(&store, n, T0).unwrap();
    }
    assert_eq!(
        row("b"),
        (
            "b".into(),
            "sent".into(),
            None,
            "stored in the host's mailbox; put again every 10 minutes until accepted".into()
        )
    );
    outbox::refused(
        &store,
        b,
        PutRefusal::IdReused,
        T0 + outbox::RESEND_MS,
        outbox::tests::AT,
    )
    .unwrap();
    assert_eq!(
        row("b"),
        (
            "b".into(),
            "sent".into(),
            Some("id_reused".into()),
            "stored in the host's mailbox; the Station refused a later copy (id_reused)".into()
        )
    );
    let tx = store.db.unchecked_transaction().unwrap();
    assert!(accepted(&tx, &message.message_id, "b").unwrap());
    tx.commit().unwrap();
    assert_eq!(row("b").1, "accepted");
    outbox::refused(
        &store,
        c,
        PutRefusal::Expired,
        T0 + outbox::RESEND_MS,
        outbox::tests::AT,
    )
    .unwrap();
    assert_eq!(
        row("c"),
        (
            "c".into(),
            "expired".into(),
            Some("expired".into()),
            "expired before it was accepted".into()
        )
    );
    // Never stored: refused, with the code.
    let other = local(vec![]);
    commit(&store, &log, ME, &other, &part).unwrap();
    let (n, _) = engine_bytes(&store, "b", &other.message_id);
    outbox::refused(&store, n, PutRefusal::IdReused, T0, outbox::tests::AT).unwrap();
    assert_eq!(
        rows_of(&store, &other.message_id)[0],
        (
            "b".into(),
            "refused".into(),
            Some("id_reused".into()),
            "the Station refused it (id_reused)".into()
        )
    );
}
