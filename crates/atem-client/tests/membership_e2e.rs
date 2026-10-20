//! Local end-to-end tests of the membership log through the public API only:
//! simulated devices (a Mac, a phone, an iPad, a bot) hold their own
//! `SoftwareKeys`, sign entries, publish them through a fake relay's
//! compare-and-swap and carry suffixes to host-side verifiers that run on
//! injected host clocks.
mod support;

use atem_client::backup::{BackupKey, KBackupEnvelope};
use atem_client::backup_writer::{BackupJob, BackupWriter, PutReply, Step};
use atem_client::encoding::Hash32;
use atem_client::kit::RecoveryKit;
use atem_client::membership::publish::{Published, Publisher};
use atem_client::membership::{
    Action, Admission, Check, Conflict, Effect, Entry, EvidenceReason, Head, HostRecord, Invalid,
    KitMode, Member, MemberKind, Membership, RECOVERY_SIGNER, RECOVERY_WAIT_MS, RecoveryState,
    Role, RolesChange, Scope, Stop, draft_on, sign_entry,
};
use atem_client::restore::{HostHead, restore};
use atem_client::{Alg, KeyId, KeyProvider, PublicKey, SignedObject, SoftwareKeys};
use support::{Clock, FakeRelay, RelayAppend};
use zeroize::Zeroizing;

const ACCOUNT: &str = "acct-e2e";
const T0: u64 = 1_800_000_000_000;

/// One simulated device: its own keys, its verified log, one append in flight.
struct Device {
    id: String,
    keys: SoftwareKeys,
    log: Membership,
    publisher: Publisher,
    clock: Clock,
}

fn auth() -> KeyId {
    KeyId::new("auth")
}

fn native_member(id: &str, keys: &mut SoftwareKeys, roles: &[Role]) -> Member {
    let auth_key = keys.generate(auth(), Alg::P256).unwrap();
    let enc_key = keys.generate(KeyId::new("enc"), Alg::X25519).unwrap();
    Member {
        device_id: id.into(),
        auth_key,
        kind: MemberKind::Native {
            enc_key,
            roles: roles.iter().copied().collect(),
        },
    }
}

const MANAGER: [Role; 3] = [Role::Control, Role::Manage, Role::View];

/// The Mac creates the account's log: a self-signed genesis naming the kit.
fn genesis(kit: &RecoveryKit) -> (Device, Entry, Member) {
    let mut keys = SoftwareKeys::new();
    let member = native_member("dev-mac", &mut keys, &MANAGER);
    let body = draft_on(
        ACCOUNT,
        &Hash32([0; 32]),
        1,
        &Hash32([0; 32]),
        "dev-mac",
        T0,
        &Action::Genesis {
            member: member.clone(),
            recovery_key: kit.recovery_key(),
        },
    );
    let entry = sign_entry(&keys, &auth(), body).unwrap();
    let log = Membership::from_genesis(ACCOUNT, &entry.hash(), entry.clone()).unwrap();
    let mac = Device {
        id: "dev-mac".into(),
        keys,
        log,
        publisher: Publisher::new(),
        clock: Clock::at(T0),
    };
    (mac, entry, member)
}

/// A device that joins: its keys, and the log it fetched and verified from
/// the relay (pinned at the genesis it was told).
fn join(id: &str, relay: &FakeRelay, genesis: &Hash32, keys: SoftwareKeys) -> Device {
    let entries: Vec<Entry> = relay
        .log
        .iter()
        .map(|o| Entry::parse(o.clone()).unwrap())
        .collect();
    let clock = Clock::at(T0);
    let log = Membership::verify_chain(ACCOUNT, genesis, &entries, &clock.now)
        .unwrap()
        .membership;
    Device {
        id: id.into(),
        keys,
        log,
        publisher: Publisher::new(),
        clock,
    }
}

impl Device {
    /// Prepares, signs and publishes one entry with the relay's CAS.
    fn publish(&mut self, relay: &mut FakeRelay, action: &Action) -> Published {
        let body = self.log.draft(&self.id, self.clock.now.wall_ms, action);
        self.publisher.prepare(&self.log, body).unwrap();
        let (entry, expected) = {
            self.publisher.sign(&self.keys, &auth(), None).unwrap();
            let (e, h) = self.publisher.outstanding().unwrap();
            (e.object().clone(), h)
        };
        let answer = relay.append(&entry, expected);
        self.publisher
            .reply(answer.reply(), &mut self.log, &self.clock.now)
            .unwrap()
    }

    /// Fetches what the relay has beyond its head.
    fn sync(&mut self, relay: &FakeRelay) {
        let rest = relay.after(self.log.head().seq);
        let eval = self.log.evaluate_objects(&rest, &self.clock.now);
        assert_eq!(eval.stop, None);
        self.log = eval.next;
    }

    /// The suffix a host at `head` needs.
    fn suffix(&self, head: Head) -> Vec<SignedObject> {
        self.log.entries()[head.seq as usize..]
            .iter()
            .map(|e| e.object().clone())
            .collect()
    }
}

/// A host: pinned at pairing, then fed carriages on its own clock.
struct Host {
    m: Membership,
    clock: Clock,
}

impl Host {
    fn pin(relay: &FakeRelay, genesis: &Hash32, upto: u64) -> Host {
        let clock = Clock::at(T0 + 1_000);
        let entries: Vec<Entry> = relay.log[..upto as usize]
            .iter()
            .map(|o| Entry::parse(o.clone()).unwrap())
            .collect();
        let m = Membership::verify_chain(ACCOUNT, genesis, &entries, &clock.now)
            .unwrap()
            .membership;
        Host { m, clock }
    }

    /// Applies a carriage (as the broker pass would, then commits) and
    /// returns the carrier's admission and the stop.
    fn carry(&mut self, carrier: &str, entries: &[SignedObject]) -> (Admission, Option<Stop>) {
        let eval = self.m.evaluate_objects(entries, &self.clock.now);
        let admission = eval.admission(carrier, false, &self.clock.now);
        let stop = eval.stop.clone();
        self.m = eval.next;
        (admission, stop)
    }

    fn advance(&mut self, ms: u64) -> Vec<Effect> {
        self.clock.advance(ms);
        self.m.advance(&self.clock.now)
    }
}

fn admitted(admission: &Admission) -> bool {
    matches!(admission, Admission::Member { .. })
}

fn kit(seed: u8) -> RecoveryKit {
    // Bound to its genesis only after the genesis exists; the derivations
    // don't depend on the binding.
    RecoveryKit::make(&[seed; 32], ACCOUNT, Hash32([0; 32]))
}

/// Mac, host, phone (manager), iPad (manager), bot (service): the shared
/// setup of several tests.
struct World {
    relay: FakeRelay,
    genesis: Hash32,
    mac: Device,
    phone: Device,
    ipad: Device,
    bot_key: PublicKey,
    kit: RecoveryKit,
}

fn world() -> World {
    let first_kit = kit(7);
    let (mut mac, genesis_entry, _) = genesis(&first_kit);
    let genesis = genesis_entry.hash();
    let kit = RecoveryKit::make(&[7; 32], ACCOUNT, genesis);
    let mut relay = FakeRelay::with_log(vec![genesis_entry.object().clone()]);

    let mut host_keys = SoftwareKeys::new();
    let host_key = host_keys
        .generate(KeyId::new("host"), Alg::Ed25519)
        .unwrap();
    let add_host = Action::AddHost {
        host: HostRecord {
            host_id: "host-a".into(),
            host_trust_gen: 1,
            host_key,
        },
    };
    assert!(matches!(
        mac.publish(&mut relay, &add_host),
        Published::Committed(_)
    ));

    let mut phone_keys = SoftwareKeys::new();
    let phone_member = native_member("dev-phone", &mut phone_keys, &MANAGER);
    assert!(matches!(
        mac.publish(
            &mut relay,
            &Action::Add {
                member: phone_member
            }
        ),
        Published::Committed(_)
    ));
    let mut ipad_keys = SoftwareKeys::new();
    let ipad_member = native_member("dev-ipad", &mut ipad_keys, &MANAGER);
    assert!(matches!(
        mac.publish(
            &mut relay,
            &Action::Add {
                member: ipad_member
            }
        ),
        Published::Committed(_)
    ));
    let phone = join("dev-phone", &relay, &genesis, phone_keys);
    let ipad = join("dev-ipad", &relay, &genesis, ipad_keys);

    let mut bot_keys = SoftwareKeys::new();
    let bot_key = bot_keys.generate(auth(), Alg::Ed25519).unwrap();
    World {
        relay,
        genesis,
        mac,
        phone,
        ipad,
        bot_key,
        kit,
    }
}

/// A phone, a Mac and a bot each build and sign entries with their own keys
/// and carry suffixes to a host-side verifier, which admits members, refuses
/// strangers and never lets a service sign.
#[test]
fn devices_build_the_log_and_a_host_verifies_every_carriage() {
    let mut w = world();
    let mut host = Host::pin(&w.relay, &w.genesis, 2); // genesis + add_host

    // The phone adds the bot (a service scoped to host-a).
    w.phone.sync(&w.relay);
    let bot = Member {
        device_id: "svc-bot".into(),
        auth_key: w.bot_key.clone(),
        kind: MemberKind::Service {
            scope: Scope {
                hosts: vec!["host-a".into()],
                projects: None,
                sessions: None,
                ops: vec!["prompt".into(), "view".into()],
            },
            expires_at: T0 + 86_400_000,
        },
    };
    let committed = w.phone.publish(&mut w.relay, &Action::Add { member: bot });
    assert!(matches!(
        committed,
        Published::Committed(Head { seq: 5, .. })
    ));

    // The phone carries the suffix it has beyond the host's head.
    let (adm, stop) = host.carry("dev-phone", &w.phone.suffix(host.m.head()));
    assert_eq!(stop, None);
    assert!(admitted(&adm));
    assert_eq!(host.m.head(), w.relay.head());
    assert_eq!(
        host.m.members(),
        ["dev-ipad", "dev-mac", "dev-phone", "svc-bot"]
    );

    // The bot is admitted as a service (scope and expiry are admission's).
    let (adm, _) = host.carry("svc-bot", &[]);
    let Admission::Member { state, .. } = adm else {
        panic!("{adm:?}")
    };
    assert!(matches!(state.member.kind, MemberKind::Service { .. }));

    // A service never signs entries: its own entry is refused.
    let mut bot_keys = SoftwareKeys::new();
    bot_keys.generate(auth(), Alg::Ed25519).unwrap(); // not even its key
    let remove = host.m.draft(
        "svc-bot",
        T0,
        &Action::Remove {
            device_id: "dev-ipad".into(),
        },
    );
    let forged = sign_entry(&bot_keys, &auth(), remove).unwrap();
    assert_eq!(
        host.m.check_next(&forged),
        Check::Invalid(Invalid::SignerNotManager)
    );

    // A stranger carrying nothing gets nothing.
    assert_eq!(
        host.carry("dev-evil", &[]).0,
        Admission::Unauthorized("not a member")
    );
    // A carriage that skips an entry is refused with nothing applied.
    let before = host.m.head();
    w.mac.sync(&w.relay);
    let e6 = w.mac.publish(
        &mut w.relay,
        &Action::Remove {
            device_id: "svc-bot".into(),
        },
    );
    assert!(matches!(e6, Published::Committed(_)));
    let e7 = w.mac.publish(
        &mut w.relay,
        &Action::Remove {
            device_id: "dev-ipad".into(),
        },
    );
    assert!(matches!(e7, Published::Committed(_)));
    let gap = w.mac.suffix(before)[1..].to_vec();
    let (adm, stop) = host.carry("dev-mac", &gap);
    assert!(matches!(
        stop,
        Some(Stop::Invalid {
            index: 0,
            reason: Invalid::Gap
        })
    ));
    assert!(matches!(adm, Admission::Invalid { .. }));
    assert_eq!(host.m.head(), before);
    // The whole suffix applies; the removed bot and iPad are refused.
    host.carry("dev-mac", &w.mac.suffix(before));
    assert_eq!(host.m.head(), w.relay.head());
    assert_eq!(
        host.carry("svc-bot", &[]).0,
        Admission::Unauthorized("removed")
    );
    assert_eq!(
        host.carry("dev-ipad", &[]).0,
        Admission::Unauthorized("removed")
    );
}

/// A removed device's later (stolen-key) entry is ignored and logged, while
/// a current manager's conflicting entry freezes the host; a frozen host
/// applies nothing more and the devices see the divergence.
#[test]
fn a_removed_devices_entry_is_ignored_and_a_current_managers_conflict_freezes() {
    let mut w = world();
    let mut host = Host::pin(&w.relay, &w.genesis, 4);
    // The Mac removes the stolen iPad and the host learns it.
    let removal = w.mac.publish(
        &mut w.relay,
        &Action::Remove {
            device_id: "dev-ipad".into(),
        },
    );
    let Published::Committed(removal_head) = removal else {
        panic!()
    };
    host.carry("dev-mac", &w.mac.suffix(host.m.head()));
    assert_eq!(host.m.head(), removal_head);

    // The thief signs a sibling at the removal's seq with the iPad key (its
    // copy of the log is from before the removal).
    let thief = Action::Remove {
        device_id: "dev-phone".into(),
    };
    let body = w.ipad.log.draft("dev-ipad", T0, &thief);
    let sibling = sign_entry(&w.ipad.keys, &auth(), body).unwrap();
    let (adm, stop) = host.carry("dev-phone", &[sibling.object().clone()]);
    assert_eq!(
        stop,
        Some(Stop::Conflict {
            index: 0,
            outcome: Conflict::Ignored(EvidenceReason::SignerRemoved)
        })
    );
    assert!(admitted(&adm), "the honest carrier is admitted");
    assert!(host.m.frozen().is_none());
    assert_eq!(host.m.evidence().count, 1);
    // Beyond the head it's simply invalid.
    let body = host.m.draft("dev-ipad", T0, &thief);
    let late = sign_entry(&w.ipad.keys, &auth(), body).unwrap();
    assert_eq!(
        host.m.check_next(&late),
        Check::Invalid(Invalid::SignerNotManager)
    );

    // A relay whose CAS fails accepts the phone's sibling of the Mac's
    // next entry: both are current managers, both honest.
    w.relay.cas_broken = true;
    w.phone.sync(&w.relay);
    let tv = native_member("dev-tv", &mut SoftwareKeys::new(), &[Role::View]);
    let watch = native_member("dev-watch", &mut SoftwareKeys::new(), &[Role::View]);
    let mac_entry = w.mac.publish(&mut w.relay, &Action::Add { member: tv });
    assert!(matches!(mac_entry, Published::Committed(_)));
    let phone_entry = w
        .phone
        .publish(&mut w.relay, &Action::Add { member: watch });
    assert!(
        matches!(phone_entry, Published::Committed(_)),
        "the broken relay said 200"
    );
    // The host gets the Mac's branch first, then the phone's: freeze.
    let (adm, _) = host.carry("dev-mac", &w.mac.suffix(host.m.head()));
    assert!(admitted(&adm));
    let theirs = w.relay.siblings[0].clone();
    let (adm, stop) = host.carry("dev-phone", &[theirs]);
    assert_eq!(adm, Admission::Frozen);
    assert!(matches!(
        stop,
        Some(Stop::Conflict {
            outcome: Conflict::Freeze,
            ..
        })
    ));
    let freeze = host.m.frozen().unwrap();
    assert_eq!(freeze.ours.entry_hash().unwrap(), w.mac.log.head().hash);
    // Frozen: nothing applies, no time passes for recovery.
    assert_eq!(host.carry("dev-mac", &[]).0, Admission::Frozen);
    assert!(host.advance(RECOVERY_WAIT_MS).is_empty());
    // A device shown the other branch sees the divergence and stops signing.
    let eval = w
        .mac
        .log
        .evaluate_objects(&[w.relay.siblings[0].clone()], &w.mac.clock.now);
    assert!(matches!(
        eval.stop,
        Some(Stop::Conflict {
            outcome: Conflict::Freeze,
            ..
        })
    ));
}

/// Two honest managers append at once through a correct relay: the second
/// gets 409, discards its body, verifies the winner and rebuilds on the new
/// head; a retry of the same body is idempotent; no host ever sees a fork.
#[test]
fn honest_concurrent_appends_never_fork() {
    let mut w = world();
    w.phone.sync(&w.relay);
    let mac_first = w.mac.publish(
        &mut w.relay,
        &Action::Remove {
            device_id: "dev-ipad".into(),
        },
    );
    assert!(matches!(mac_first, Published::Committed(_)));
    // The phone still builds on the old head.
    let lost = w.phone.publish(
        &mut w.relay,
        &Action::SetRoles {
            device_id: "dev-ipad".into(),
            change: RolesChange::Native([Role::View].into()),
        },
    );
    let Published::LostRace { discarded, head } = lost else {
        panic!("{lost:?}")
    };
    assert_eq!(head, w.relay.head());
    assert_eq!(w.phone.log.head(), w.relay.head());
    // Re-check intent on the new head: the iPad is already gone.
    let body = w.phone.log.draft(
        "dev-phone",
        T0,
        &Action::SetRoles {
            device_id: "dev-ipad".into(),
            change: RolesChange::Native([Role::View].into()),
        },
    );
    let stale = sign_entry(&w.phone.keys, &auth(), body).unwrap();
    assert_eq!(
        w.phone.log.check_next(&stale),
        Check::Invalid(Invalid::NotAMember)
    );
    // Uncertain outcome: the same entry again is a 200 with the stored one.
    let stored = w.relay.log.last().unwrap().clone();
    let again = w.relay.append(
        &stored,
        Head {
            seq: 4,
            hash: w.relay.log[3].entry_hash().unwrap(),
        },
    );
    assert!(matches!(again, RelayAppend::Ok(ref o) if o.entry_hash() == stored.entry_hash()));
    // The discarded body was never carried; a host pinned earlier converges.
    let mut host = Host::pin(&w.relay, &w.genesis, 2);
    host.carry("dev-phone", &w.phone.suffix(host.m.head()));
    assert_eq!(host.m.head(), w.relay.head());
    let never_carried = discarded.signed.unwrap().hash();
    assert!(host.m.entry_by_hash(&never_carried).is_none());
    assert!(host.m.frozen().is_none());
}

/// The full recovery flow on injected host clocks: a kit-signed
/// `recovery_add` is pending 24 h, its subject has no access and its entries
/// are deferred; another manager's approval ends the wait at once; a veto
/// cancels it for good; unvetoed it takes effect after 24 h of host time,
/// and time while the host was off doesn't count.
#[test]
fn recovery_waits_24h_unless_approved_or_vetoed() {
    let mut w = world();
    let pinned = w.relay.log.len() as u64;
    let mut newmac_keys = SoftwareKeys::new();
    let newmac = native_member("dev-newmac", &mut newmac_keys, &MANAGER);
    // The restoring device signs with the kit.
    let body = w.mac.log.draft(
        RECOVERY_SIGNER,
        T0 - 3 * 86_400_000,
        &Action::RecoveryAdd { member: newmac },
    );
    let recovery = sign_entry(&w.kit, &RecoveryKit::sign_id(), body).unwrap();
    assert!(matches!(
        w.relay.append(recovery.object(), w.relay.head()),
        RelayAppend::Ok(_)
    ));
    // The subject's own later entry (removing the iPad).
    let mut subject_log = w.mac.log.clone();
    subject_log = subject_log
        .evaluate_objects(&[recovery.object().clone()], &w.mac.clock.now)
        .next;
    let body = subject_log.draft(
        "dev-newmac",
        T0,
        &Action::Remove {
            device_id: "dev-ipad".into(),
        },
    );
    let subject_entry = sign_entry(&newmac_keys, &auth(), body).unwrap();

    let fresh_host = || {
        let mut h = Host::pin(&w.relay, &w.genesis, pinned);
        let (adm, stop) = h.carry("dev-phone", &[recovery.object().clone()]);
        assert!(admitted(&adm) && stop.is_none());
        h
    };

    // Pending: no access, effective 24 h from this host's first sight
    // (the backdated signed_at counts for nothing).
    let mut host = fresh_host();
    let Admission::RecoveryPending {
        entry_hash,
        effective_at,
    } = host.carry("dev-newmac", &[]).0
    else {
        panic!()
    };
    assert_eq!(entry_hash, recovery.hash());
    assert_eq!(effective_at, host.clock.now.wall_ms + RECOVERY_WAIT_MS);
    // Its entry is deferred: the carrier is still admitted.
    let (adm, stop) = host.carry("dev-phone", &[subject_entry.object().clone()]);
    assert!(admitted(&adm));
    assert_eq!(
        stop,
        Some(Stop::Deferred {
            index: 0,
            on: recovery.hash()
        })
    );
    // Self-approval is impossible (the subject holds nothing); another
    // manager's approval ends the wait at once.
    let approve = |host: &Host, by: &Device| {
        let body = host.m.draft(
            &by.id,
            T0,
            &Action::RecoveryApprove {
                target: recovery.hash(),
            },
        );
        sign_entry(&by.keys, &auth(), body).unwrap()
    };
    let a = approve(&host, &w.phone);
    host.advance(3_600_000);
    host.carry("dev-phone", &[a.object().clone()]);
    assert_eq!(
        host.m.record(&recovery.hash()).unwrap().state(),
        RecoveryState::Active
    );
    assert!(admitted(&host.carry("dev-newmac", &[]).0));
    // Now the deferred entry applies.
    let body = host.m.draft(
        "dev-newmac",
        T0,
        &Action::Remove {
            device_id: "dev-ipad".into(),
        },
    );
    let now_valid = sign_entry(&newmac_keys, &auth(), body).unwrap();
    assert_eq!(host.m.check_next(&now_valid), Check::Valid);

    // A veto by any manager cancels it; the subject is never a member.
    let mut vetoed = fresh_host();
    let body = vetoed.m.draft(
        "dev-mac",
        T0,
        &Action::RecoveryVeto {
            target: recovery.hash(),
        },
    );
    let veto = sign_entry(&w.mac.keys, &auth(), body).unwrap();
    vetoed.carry("dev-mac", &[veto.object().clone()]);
    vetoed.advance(2 * RECOVERY_WAIT_MS);
    assert_eq!(
        vetoed.m.record(&recovery.hash()).unwrap().state(),
        RecoveryState::Cancelled
    );
    assert_eq!(
        vetoed.carry("dev-newmac", &[]).0,
        Admission::Unauthorized("not a member")
    );
    // A late approval of a cancelled entry changes nothing.
    let late = approve(&vetoed, &w.phone);
    vetoed.carry("dev-phone", &[late.object().clone()]);
    assert_eq!(
        vetoed.m.record(&recovery.hash()).unwrap().state(),
        RecoveryState::Cancelled
    );

    // Unvetoed: a forward wall jump alone doesn't end the wait; a reboot
    // loses the time the host was off; 24 h of host time does.
    let mut waiting = fresh_host();
    waiting.clock.set_wall(T0 + 10 * RECOVERY_WAIT_MS);
    assert!(waiting.m.advance(&waiting.clock.now).is_empty());
    waiting.advance(RECOVERY_WAIT_MS / 2);
    waiting.m.checkpoint(&waiting.clock.now);
    // The machine is off for a day; at start the host takes a reading.
    waiting.clock.reboot("boot-2");
    waiting
        .clock
        .set_wall(waiting.clock.now.wall_ms + RECOVERY_WAIT_MS);
    waiting.m.checkpoint(&waiting.clock.now);
    waiting.advance(RECOVERY_WAIT_MS / 2 - 1);
    assert_eq!(
        waiting.m.record(&recovery.hash()).unwrap().state(),
        RecoveryState::Pending
    );
    let effects = waiting.advance(1);
    assert!(effects.contains(&Effect::RecoveryActive {
        entry_hash: recovery.hash(),
        reason: atem_client::membership::RecoveryReason::WaitEnded,
    }));
    assert!(admitted(&waiting.carry("dev-newmac", &[]).0));
    // A veto after activation is a valid entry with no effect.
    let body = waiting.m.draft(
        "dev-mac",
        T0,
        &Action::RecoveryVeto {
            target: recovery.hash(),
        },
    );
    let late_veto = sign_entry(&w.mac.keys, &auth(), body).unwrap();
    waiting.carry("dev-mac", &[late_veto.object().clone()]);
    assert_eq!(
        waiting.m.record(&recovery.hash()).unwrap().state(),
        RecoveryState::Active
    );
    assert!(waiting.m.members().contains(&"dev-newmac"));
}

/// Kit replacement both ways: with the current kit (co-signed, in effect at
/// once; the old kit can never sign again) and without it (pending 24 h,
/// vetoable; once in effect it cancels the old kit's pending enrollment).
#[test]
fn the_kit_is_replaced_with_and_without_the_current_kit() {
    let mut w = world();
    w.phone.sync(&w.relay);
    let new_kit = RecoveryKit::make(&[9; 32], ACCOUNT, w.genesis);
    let pinned = w.relay.log.len() as u64;
    let old_kit_enrollment = |log: &Membership| {
        let mut keys = SoftwareKeys::new();
        let member = native_member("dev-thief", &mut keys, &MANAGER);
        let body = log.draft(RECOVERY_SIGNER, T0, &Action::RecoveryAdd { member });
        sign_entry(&w.kit, &RecoveryKit::sign_id(), body).unwrap()
    };

    // kit: "current": the manager signs, the current kit co-signs.
    let mut host = Host::pin(&w.relay, &w.genesis, pinned);
    let replace = Action::SetRecoveryKey {
        recovery_key: new_kit.recovery_key(),
        kit: KitMode::Current,
    };
    let body = host.m.draft("dev-phone", T0, &replace);
    let mut unsigned = Publisher::new();
    unsigned.prepare(&host.m, body.clone()).unwrap();
    // Without the kit's co-signature the same body is invalid.
    assert!(matches!(
        unsigned.sign(&w.phone.keys, &auth(), None),
        Err(atem_client::membership::publish::PublishError::Sign(
            Invalid::KitSigMissing
        ))
    ));
    let mut cosigned = Publisher::new();
    cosigned.prepare(&host.m, body).unwrap();
    let entry = cosigned
        .sign(
            &w.phone.keys,
            &auth(),
            Some((&w.kit as &dyn KeyProvider, &RecoveryKit::sign_id())),
        )
        .unwrap()
        .clone();
    host.carry("dev-phone", &[entry.object().clone()]);
    assert_eq!(*host.m.recovery_key(), new_kit.recovery_key());
    assert_eq!(host.m.retired_recovery_keys(), [w.kit.recovery_key()]);
    let old = old_kit_enrollment(&host.m);
    assert_eq!(
        host.m.check_next(&old),
        Check::Invalid(Invalid::RecoveryKeyRetired)
    );
    // The new kit enrolls (pending).
    let mut keys = SoftwareKeys::new();
    let member = native_member("dev-newmac", &mut keys, &MANAGER);
    let body = host
        .m
        .draft(RECOVERY_SIGNER, T0, &Action::RecoveryAdd { member });
    let enroll = sign_entry(&new_kit, &RecoveryKit::sign_id(), body).unwrap();
    assert_eq!(host.m.check_next(&enroll), Check::Valid);
    // The old key can't come back.
    let back = Action::SetRecoveryKey {
        recovery_key: w.kit.recovery_key(),
        kit: KitMode::Lost,
    };
    let body = host.m.draft("dev-mac", T0, &back);
    let reuse = sign_entry(&w.mac.keys, &auth(), body).unwrap();
    assert_eq!(
        host.m.check_next(&reuse),
        Check::Invalid(Invalid::RecoveryKeyReused)
    );

    // kit: "lost": no co-signature, pending; the old kit's enrollment that
    // is pending when it takes effect is cancelled (kit_replaced).
    let mut host = Host::pin(&w.relay, &w.genesis, pinned);
    let pending_old = old_kit_enrollment(&host.m);
    host.carry("dev-phone", &[pending_old.object().clone()]);
    let lost = Action::SetRecoveryKey {
        recovery_key: new_kit.recovery_key(),
        kit: KitMode::Lost,
    };
    let body = host.m.draft("dev-phone", T0, &lost);
    let lost_entry = sign_entry(&w.phone.keys, &auth(), body).unwrap();
    host.carry("dev-phone", &[lost_entry.object().clone()]);
    assert_eq!(
        host.m.record(&lost_entry.hash()).unwrap().state(),
        RecoveryState::Pending
    );
    assert_eq!(*host.m.recovery_key(), w.kit.recovery_key());
    // Its own signer can't approve it.
    let body = host.m.draft(
        "dev-phone",
        T0,
        &Action::RecoveryApprove {
            target: lost_entry.hash(),
        },
    );
    let own = sign_entry(&w.phone.keys, &auth(), body).unwrap();
    assert_eq!(
        host.m.check_next(&own),
        Check::Invalid(Invalid::SelfApproval)
    );
    // The new kit's signature is deferred until the replacement is in effect.
    let mut keys = SoftwareKeys::new();
    let member = native_member("dev-newmac", &mut keys, &MANAGER);
    let body = host
        .m
        .draft(RECOVERY_SIGNER, T0, &Action::RecoveryAdd { member });
    let early = sign_entry(&new_kit, &RecoveryKit::sign_id(), body).unwrap();
    assert_eq!(
        host.m.check_next(&early),
        Check::Deferred(lost_entry.hash())
    );
    // A vetoed copy keeps the old kit.
    let mut vetoed = Host {
        m: host.m.clone(),
        clock: host.clock.clone(),
    };
    let body = vetoed.m.draft(
        "dev-mac",
        T0,
        &Action::RecoveryVeto {
            target: lost_entry.hash(),
        },
    );
    let veto = sign_entry(&w.mac.keys, &auth(), body).unwrap();
    vetoed.carry("dev-mac", &[veto.object().clone()]);
    vetoed.advance(RECOVERY_WAIT_MS * 2);
    assert_eq!(*vetoed.m.recovery_key(), w.kit.recovery_key());
    // Unvetoed: 24 h later it's in effect and the old kit's enrollment is
    // cancelled, whatever its own wait said.
    host.advance(RECOVERY_WAIT_MS);
    assert_eq!(*host.m.recovery_key(), new_kit.recovery_key());
    let old_record = host.m.record(&pending_old.hash()).unwrap();
    assert_eq!(
        old_record.state(),
        RecoveryState::Active,
        "its wait ended first (seq order)"
    );
    // A newer old-kit enrollment arriving now is refused as retired.
    let body = host.m.draft(
        RECOVERY_SIGNER,
        T0,
        &Action::RecoveryAdd {
            member: native_member("dev-late", &mut SoftwareKeys::new(), &MANAGER),
        },
    );
    let late = sign_entry(&w.kit, &RecoveryKit::sign_id(), body).unwrap();
    assert_eq!(
        host.m.check_next(&late),
        Check::Invalid(Invalid::RecoveryKeyRetired)
    );
    // And an old-kit enrollment still pending when the replacement takes
    // effect is cancelled.
    let mut host = Host::pin(&w.relay, &w.genesis, pinned);
    let body = host.m.draft("dev-phone", T0, &lost);
    let lost_here = sign_entry(&w.phone.keys, &auth(), body).unwrap();
    let (_, stop) = host.carry("dev-phone", &[lost_here.object().clone()]);
    assert_eq!(stop, None);
    host.advance(RECOVERY_WAIT_MS / 2);
    let body = host.m.draft(
        RECOVERY_SIGNER,
        T0,
        &Action::RecoveryAdd {
            member: native_member("dev-thief2", &mut SoftwareKeys::new(), &MANAGER),
        },
    );
    let mid = sign_entry(&w.kit, &RecoveryKit::sign_id(), body).unwrap();
    host.carry("dev-phone", &[mid.object().clone()]);
    host.advance(RECOVERY_WAIT_MS / 2);
    assert_eq!(*host.m.recovery_key(), new_kit.recovery_key());
    let cancelled = host.m.record(&mid.hash()).unwrap();
    assert_eq!(cancelled.state(), RecoveryState::Cancelled);
    assert_eq!(
        cancelled.decision.as_ref().unwrap().reason,
        atem_client::membership::RecoveryReason::KitReplaced
    );
}

fn k_set(kids: &[(&str, u8)]) -> Vec<BackupKey> {
    kids.iter()
        .map(|(kid, byte)| BackupKey {
            kid: (*kid).into(),
            k: Zeroizing::new([*byte; 32]),
        })
        .collect()
}

/// Drives a writer against the fake relay until it is done or fails; a
/// competing writer occupies versions before each upload of ours.
fn write_backup(
    device: &mut Device,
    relay: &mut FakeRelay,
    keys: &[BackupKey],
    kit: &PublicKey,
    mut before_put: impl FnMut(&mut FakeRelay, u64),
) -> (BackupWriter, Step, Vec<u64>) {
    let job = BackupJob {
        kids: keys.iter().map(|k| k.kid.clone()).collect(),
        kit: kit.clone(),
        signer: device.id.clone(),
    };
    let (mut writer, mut step) = BackupWriter::start(&device.log, job);
    let mut uploads = Vec::new();
    loop {
        step = match step {
            Step::Seal { blob_version } => {
                let env = KBackupEnvelope::seal(
                    ACCOUNT,
                    device.log.genesis_hash(),
                    blob_version,
                    kit,
                    keys,
                )
                .unwrap();
                let at = device.clock.now.wall_ms;
                writer.sealed(&device.log, env, at)
            }
            Step::Put {
                blob_version,
                bytes,
            } => {
                before_put(relay, blob_version);
                uploads.push(blob_version);
                let reply = match relay.put(blob_version, &bytes) {
                    Ok(()) => PutReply::Stored,
                    Err(max_occupied) => PutReply::Occupied { max_occupied },
                };
                writer.put_reply(&device.log, reply)
            }
            Step::Append { entry, expected } => {
                let answer = relay.append(&entry, expected);
                let at = device.clock.now.wall_ms;
                let now = device.clock.now.clone();
                writer.append_reply(&mut device.log, answer.reply(), &now, at)
            }
            Step::Sign { .. } => writer.sign(&device.keys, &auth()),
            Step::Fetch { after } => {
                let (entries, more) = relay.after_page(after);
                let at = device.clock.now.wall_ms;
                let now = device.clock.now.clone();
                writer.fetched(&mut device.log, &entries, more, &now, at)
            }
            done @ (Step::Done { .. } | Step::Failed(_)) => return (writer, done, uploads),
        };
    }
}

/// K-backup allocation under repeated 409s from a simulated relay: every
/// collision moves the next version strictly above what the relay reported,
/// versions only increase in the log, a relay reporting an absurd version is
/// refused, an unrelated CAS loss keeps the envelope, and a restore opens
/// only the committed version.
#[test]
fn k_backup_allocation_survives_repeated_409s() {
    let mut w = world();
    let kit_key = w.kit.recovery_key();
    let keys = k_set(&[("b982533d", 1), ("1f2e3d4c", 2)]);
    // Another writer keeps taking the version we are about to upload.
    let (_, step, uploads) = write_backup(&mut w.mac, &mut w.relay, &keys, &kit_key, |relay, v| {
        if v < 4 {
            relay.occupy(v + 1);
            relay.occupy(v);
        }
    });
    assert_eq!(step, Step::Done { committed: 5 });
    assert_eq!(uploads, [1, 3, 5], "each 409 allocates above max_occupied");
    assert_eq!(w.mac.log.k_backup().unwrap().blob_version, 5);
    assert!(BackupWriter::may_use_k(&w.mac.log, "b982533d"));

    // A host verifying the log keeps the newest record; a stale version is
    // refused.
    let mut host = Host::pin(&w.relay, &w.genesis, 4);
    host.carry("dev-mac", &w.mac.suffix(host.m.head()));
    assert_eq!(host.m.k_backup().unwrap().blob_version, 5);
    let stale = host.m.draft(
        "dev-mac",
        T0,
        &Action::KBackup(host.m.k_backup().unwrap().clone()),
    );
    let stale = sign_entry(&w.mac.keys, &auth(), stale).unwrap();
    assert_eq!(
        host.m.check_next(&stale),
        Check::Invalid(Invalid::BlobVersionNotIncreasing)
    );

    // A relay reporting a version more than 1024 above the committed one is
    // misbehaving: the writer stops instead of jumping.
    let rotated = k_set(&[("7a3c9e10", 3), ("b982533d", 1)]);
    let (_, step, _) = write_backup(&mut w.mac, &mut w.relay, &rotated, &kit_key, |relay, v| {
        relay.occupy(v);
        relay.occupy(v + 2000);
    });
    assert!(matches!(
        step,
        Step::Failed(atem_client::backup_writer::BackupError::RelayMisbehaviour { .. })
    ));
    assert_eq!(w.mac.log.k_backup().unwrap().blob_version, 5);

    // An unrelated entry wins the CAS: the envelope is kept and only the
    // entry is rebuilt on the new head.
    let mut relay = FakeRelay::with_log(w.relay.log.clone());
    w.phone.sync(&relay);
    let mut uploaded = 0;
    let mut phone_raced = false;
    let job = BackupJob {
        kids: vec!["7a3c9e10".into(), "b982533d".into()],
        kit: kit_key.clone(),
        signer: "dev-mac".into(),
    };
    let (mut writer, mut step) = BackupWriter::start(&w.mac.log, job);
    let committed = loop {
        step = match step {
            Step::Seal { blob_version } => {
                let env =
                    KBackupEnvelope::seal(ACCOUNT, w.genesis, blob_version, &kit_key, &rotated)
                        .unwrap();
                writer.sealed(&w.mac.log, env, T0)
            }
            Step::Put {
                blob_version,
                bytes,
            } => {
                uploaded += 1;
                relay.put(blob_version, &bytes).unwrap();
                writer.put_reply(&w.mac.log, PutReply::Stored)
            }
            Step::Append { entry, expected } => {
                if !phone_raced {
                    phone_raced = true;
                    let won = w.phone.publish(
                        &mut relay,
                        &Action::Remove {
                            device_id: "dev-ipad".into(),
                        },
                    );
                    assert!(matches!(won, Published::Committed(_)));
                }
                let answer = relay.append(&entry, expected);
                let now = w.mac.clock.now.clone();
                writer.append_reply(&mut w.mac.log, answer.reply(), &now, T0)
            }
            Step::Sign { .. } => writer.sign(&w.mac.keys, &auth()),
            Step::Done { committed } => break committed,
            other => panic!("{other:?}"),
        };
    };
    assert_eq!(committed, 6);
    assert_eq!(uploaded, 1, "no new upload after an unrelated CAS loss");
    assert!(writer.discarded().is_empty());

    // A restore opens exactly the committed version with the kit.
    let entries: Vec<Entry> = relay
        .log
        .iter()
        .map(|o| Entry::parse(o.clone()).unwrap())
        .collect();
    let blob = relay.blobs[&6].clone();
    let host_head = HostHead {
        host_id: "host-a".into(),
        head: relay.head(),
    };
    let restored = restore(
        &w.kit,
        &entries,
        blob.as_bytes(),
        std::slice::from_ref(&host_head),
        &w.mac.clock.now,
    )
    .unwrap();
    assert_eq!(
        restored
            .keys
            .iter()
            .map(|k| k.kid.as_str())
            .collect::<Vec<_>>(),
        ["7a3c9e10", "b982533d"]
    );
    // An older authentic backup (version 5) isn't the one the log names.
    let older = w.relay.blobs[&5].clone();
    let refused = restore(
        &w.kit,
        &entries,
        older.as_bytes(),
        &[host_head],
        &w.mac.clock.now,
    );
    assert_eq!(refused.err().unwrap().code(), "backup_hash_mismatch");
}

/// A restore waits for a host-signed head (never an unconfirmed one),
/// refuses a log behind a host's head, then publishes a `recovery_add` on
/// the confirmed head that hosts accept as pending.
#[test]
fn a_restore_waits_for_a_host_head_and_publishes_a_pending_enrollment() {
    let mut w = world();
    let keys = k_set(&[("b982533d", 1)]);
    let kit_key = w.kit.recovery_key();
    let (_, step, _) = write_backup(&mut w.mac, &mut w.relay, &keys, &kit_key, |_, _| {});
    assert_eq!(step, Step::Done { committed: 1 });
    let mut host = Host::pin(&w.relay, &w.genesis, w.relay.log.len() as u64);
    let entries: Vec<Entry> = w
        .relay
        .log
        .iter()
        .map(|o| Entry::parse(o.clone()).unwrap())
        .collect();
    let blob = w.relay.blobs[&1].clone();
    let now = Clock::at(T0 + 5_000).now;
    // No host reachable: withheld, naming the hosts to turn on.
    let withheld = restore(&w.kit, &entries, blob.as_bytes(), &[], &now)
        .err()
        .unwrap();
    assert!(withheld.is_withheld());
    // A host signed a newer head than the relay showed: refused.
    let ahead = HostHead {
        host_id: "host-a".into(),
        head: Head {
            seq: 99,
            hash: Hash32([1; 32]),
        },
    };
    assert_eq!(
        restore(&w.kit, &entries, blob.as_bytes(), &[ahead], &now)
            .err()
            .unwrap()
            .code(),
        "log_behind_host"
    );
    // A head from a host the chain doesn't name proves nothing.
    let stranger = HostHead {
        host_id: "host-z".into(),
        head: host.m.head(),
    };
    assert!(
        restore(&w.kit, &entries, blob.as_bytes(), &[stranger], &now)
            .err()
            .unwrap()
            .is_withheld()
    );
    // Confirmed by host-a: restored, and the enrollment chains from it.
    let confirmed = HostHead {
        host_id: "host-a".into(),
        head: host.m.head(),
    };
    let restored = restore(&w.kit, &entries, blob.as_bytes(), &[confirmed], &now).unwrap();
    assert_eq!(*restored.keys[0].k, [1; 32]);
    let mut new_keys = SoftwareKeys::new();
    let member = native_member("dev-restored", &mut new_keys, &MANAGER);
    let enrollment = restored.recovery_add(&w.kit, member, now.wall_ms).unwrap();
    assert!(matches!(
        w.relay.append(enrollment.object(), restored.head),
        RelayAppend::Ok(_)
    ));
    let (adm, stop) = host.carry("dev-restored", &[enrollment.object().clone()]);
    assert_eq!(stop, None);
    assert!(matches!(adm, Admission::RecoveryPending { .. }));
    // Another kit (replaced or foreign) can't restore this account.
    let other = RecoveryKit::make(&[8; 32], ACCOUNT, w.genesis);
    let confirmed = HostHead {
        host_id: "host-a".into(),
        head: w.relay.head(),
    };
    let entries: Vec<Entry> = w
        .relay
        .log
        .iter()
        .map(|o| Entry::parse(o.clone()).unwrap())
        .collect();
    assert_eq!(
        restore(&other, &entries, blob.as_bytes(), &[confirmed], &now)
            .err()
            .unwrap()
            .code(),
        "kit_not_current"
    );
}
