//! A test account's r9 device list, built and signed with `atem-client`
//! (software keys): the Astation (Mac) genesis, this host's `add_host`,
//! a phone, a scoped bot and browser grants. Shared by the in-crate tests
//! (`#[path]`-included) and the binary tests; only `atem_client` APIs.
#![allow(dead_code)]

use atem_client::canonical::StrictValue;
use atem_client::encoding::{Hash32, b64u};
use atem_client::membership::entry::{
    Action, HostRecord, Member, MemberKind, Role, RolesChange, Scope,
};
use atem_client::membership::{Entry, HostNow, Membership, sign_entry};
use atem_client::principal::{BrowserGrant, Op};
use atem_client::{Alg, KeyId, PublicKey, SignedObject, SoftwareKeys};
use serde_json::Value;
use std::collections::BTreeSet;

pub const ACCOUNT: &str = "acct-r9";
pub const MAC: &str = "dev-mac";

/// A device list and every key behind it.
pub struct TestLog {
    pub keys: SoftwareKeys,
    pub account: String,
    pub entries: Vec<Entry>,
    pub log: Membership,
    pub now: HostNow,
}

fn now_wall() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn host_now() -> HostNow {
    HostNow {
        wall_ms: now_wall(),
        mono_ms: 1,
        boot_id: "test".into(),
    }
}

/// The P-256 public key of a software key.
fn p256_pub(secret: &[u8; 32]) -> Vec<u8> {
    let key = p256::ecdsa::SigningKey::from_bytes(secret.into()).unwrap();
    key.verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn ed_pub(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// A deterministic 32-byte secret per label (P-256 needs it below n:
/// SHA-256 outputs are, with overwhelming probability).
pub fn secret(label: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(format!("atem-r9-test-log {label}")).into()
}

pub fn auth(device: &str) -> KeyId {
    KeyId::new(format!("{device} auth"))
}

/// A native device's `enc_key` (X25519) in [`TestLog::keys`]: it opens the
/// device's sealed push hints (§R9.9).
pub fn enc(device: &str) -> KeyId {
    KeyId::new(format!("{device} enc"))
}

/// Puts `device`'s X25519 `enc_key` into `keys`: its public key.
fn enc_key(keys: &mut SoftwareKeys, device: &str) -> PublicKey {
    use atem_client::KeyProvider;
    keys.insert_x25519(enc(device), &secret(&format!("{device} enc")));
    keys.public_key(&enc(device)).unwrap()
}

impl TestLog {
    /// A list whose genesis is the Mac, its manager key the P-256
    /// `mac_secret` (Astation's ceremony identity).
    pub fn genesis(account: &str, mac_secret: &[u8; 32]) -> TestLog {
        let mut keys = SoftwareKeys::new();
        keys.insert_p256(auth(MAC), mac_secret).unwrap();
        let mac = Member {
            device_id: MAC.into(),
            auth_key: PublicKey::new(Alg::P256, &p256_pub(mac_secret)).unwrap(),
            kind: MemberKind::Native {
                enc_key: enc_key(&mut keys, MAC),
                roles: BTreeSet::from([Role::Control, Role::Manage, Role::View]),
            },
        };
        let recovery = ed_pub(&secret("recovery"));
        let action = Action::Genesis {
            member: mac,
            recovery_key: PublicKey::new(Alg::Ed25519, &recovery).unwrap(),
        };
        let body = atem_client::membership::draft_on(
            account,
            &Hash32([0; 32]),
            1,
            &Hash32([0; 32]),
            MAC,
            now_wall(),
            &action,
        );
        let genesis = sign_entry(&keys, &auth(MAC), body).unwrap();
        let now = host_now();
        let log = Membership::verify_chain(
            account,
            &genesis.hash(),
            std::slice::from_ref(&genesis),
            &now,
        )
        .unwrap()
        .membership;
        TestLog {
            keys,
            account: account.into(),
            entries: vec![genesis],
            log,
            now,
        }
    }

    pub fn genesis_hash(&self) -> Hash32 {
        self.log.genesis_hash()
    }

    fn append(&mut self, signer: &str, action: Action) -> Value {
        let body = self.log.draft(signer, now_wall(), &action);
        let entry = sign_entry(&self.keys, &auth(signer), body).unwrap();
        self.entries.push(entry.clone());
        self.log = Membership::verify_chain(
            &self.account,
            &self.genesis_hash(),
            &self.entries,
            &self.now,
        )
        .unwrap()
        .membership;
        entry.object().to_json()
    }

    pub fn add_host(&mut self, host_id: &str, host_trust_gen: u64, host_seed: &[u8; 32]) -> Value {
        self.add_host_pub(host_id, host_trust_gen, &ed_pub(host_seed))
    }

    pub fn add_host_pub(
        &mut self,
        host_id: &str,
        host_trust_gen: u64,
        host_pub: &[u8; 32],
    ) -> Value {
        let host = HostRecord {
            host_id: host_id.into(),
            host_trust_gen,
            host_key: PublicKey::new(Alg::Ed25519, host_pub).unwrap(),
        };
        self.append(MAC, Action::AddHost { host })
    }

    /// A native device with these roles (P-256 auth key, X25519 enc key).
    pub fn add_native(&mut self, device: &str, roles: &[&str]) -> Value {
        let s = secret(&format!("{device} auth"));
        self.keys.insert_p256(auth(device), &s).unwrap();
        let member = Member {
            device_id: device.into(),
            auth_key: PublicKey::new(Alg::P256, &p256_pub(&s)).unwrap(),
            kind: MemberKind::Native {
                enc_key: enc_key(&mut self.keys, device),
                roles: roles.iter().map(|r| Role::parse(r).unwrap()).collect(),
            },
        };
        self.append(MAC, Action::Add { member })
    }

    /// A scoped service (Ed25519 software key).
    pub fn add_service(
        &mut self,
        device: &str,
        hosts: &[&str],
        sessions: Option<&[&str]>,
        ops: &[&str],
        expires_at: u64,
    ) -> Value {
        self.add_service_projects(device, hosts, None, sessions, ops, expires_at)
    }

    /// [`TestLog::add_service`] with a `projects` scope (`h1.<kid>.<hash>`
    /// entries, §R9.6).
    pub fn add_service_projects(
        &mut self,
        device: &str,
        hosts: &[&str],
        projects: Option<&[&str]>,
        sessions: Option<&[&str]>,
        ops: &[&str],
        expires_at: u64,
    ) -> Value {
        let s = secret(&format!("{device} auth"));
        self.keys.insert_ed25519(auth(device), &s);
        let mut ops: Vec<String> = ops.iter().map(|o| o.to_string()).collect();
        ops.sort();
        let member = Member {
            device_id: device.into(),
            auth_key: PublicKey::new(Alg::Ed25519, &ed_pub(&s)).unwrap(),
            kind: MemberKind::Service {
                scope: Scope {
                    hosts: hosts.iter().map(|h| h.to_string()).collect(),
                    projects: projects.map(|p| {
                        let mut v: Vec<String> = p.iter().map(|x| x.to_string()).collect();
                        v.sort();
                        v
                    }),
                    sessions: sessions.map(|s| {
                        let mut v: Vec<String> = s.iter().map(|x| x.to_string()).collect();
                        v.sort();
                        v
                    }),
                    ops,
                },
                expires_at,
            },
        };
        self.append(MAC, Action::Add { member })
    }

    /// A service enrolled through the shared core's builder
    /// (`atem_client::membership::service_add`, §R9.6), its Ed25519 key in
    /// [`TestLog::keys`].
    pub fn enroll_service(
        &mut self,
        device: &str,
        scope: &atem_client::membership::ServiceScope,
        expires_at: u64,
    ) -> Value {
        let s = secret(&format!("{device} auth"));
        self.keys.insert_ed25519(auth(device), &s);
        let key = PublicKey::new(Alg::Ed25519, &ed_pub(&s)).unwrap();
        let action =
            atem_client::membership::service_add(device, key, scope, expires_at, now_wall())
                .unwrap();
        self.append(MAC, action)
    }

    /// A service `set_roles` by the Mac (the builder's
    /// `service_set_roles`): any change, widening included.
    pub fn set_service(
        &mut self,
        device: &str,
        scope: &atem_client::membership::ServiceScope,
        expires_at: u64,
    ) -> Value {
        let action =
            atem_client::membership::service_set_roles(device, scope, expires_at, now_wall())
                .unwrap();
        self.append(MAC, action)
    }

    /// A renewal by the Mac (`service_renewal`: the current scope, a later
    /// expiry).
    pub fn renew_service(&mut self, device: &str, expires_at: u64) -> Value {
        let action =
            atem_client::membership::service_renewal(&self.log, device, expires_at, now_wall())
                .unwrap();
        self.append(MAC, action)
    }

    /// A narrowing by the Mac (`service_narrowing`; `None`: the expiry
    /// unchanged).
    pub fn narrow_service(
        &mut self,
        device: &str,
        scope: &atem_client::membership::ServiceScope,
        expires_at: Option<u64>,
    ) -> Value {
        let action = atem_client::membership::service_narrowing(
            &self.log,
            device,
            scope,
            expires_at,
            now_wall(),
        )
        .unwrap();
        self.append(MAC, action)
    }

    fn native_member(&mut self, device: &str, roles: &[&str]) -> Member {
        let s = secret(&format!("{device} auth"));
        self.keys.insert_p256(auth(device), &s).unwrap();
        Member {
            device_id: device.into(),
            auth_key: PublicKey::new(Alg::P256, &p256_pub(&s)).unwrap(),
            kind: MemberKind::Native {
                enc_key: enc_key(&mut self.keys, device),
                roles: roles.iter().map(|r| Role::parse(r).unwrap()).collect(),
            },
        }
    }

    /// A `recovery_add` of a new native manager, signed by the genesis
    /// recovery key (pending 24 h on each host, §R9.5).
    pub fn recovery_add(&mut self, device: &str) -> Value {
        let member = self.native_member(device, &["control", "manage", "view"]);
        let key = KeyId::new("recovery");
        self.keys.insert_ed25519(key.clone(), &secret("recovery"));
        let body = self
            .log
            .draft("recovery", now_wall(), &Action::RecoveryAdd { member });
        let entry = sign_entry(&self.keys, &key, body).unwrap();
        self.entries.push(entry.clone());
        self.log = Membership::verify_chain(
            &self.account,
            &self.genesis_hash(),
            &self.entries,
            &self.now,
        )
        .unwrap()
        .membership;
        entry.object().to_json()
    }

    /// An entry by the Mac (a current manager) at the head's own `seq`
    /// with another body: carried to a host that holds the head, it is a
    /// conflict that freezes (§R9.4). Not appended here.
    pub fn conflicting_add(&mut self, device: &str) -> Value {
        let member = self.native_member(device, &["view"]);
        let head = self.log.head();
        let prev = self.log.entry(head.seq - 1).unwrap().hash();
        let body = atem_client::membership::draft_on(
            &self.account,
            &self.genesis_hash(),
            head.seq,
            &prev,
            MAC,
            now_wall(),
            &Action::Add { member },
        );
        sign_entry(&self.keys, &auth(MAC), body)
            .unwrap()
            .object()
            .to_json()
    }

    pub fn remove(&mut self, device: &str) -> Value {
        self.append(
            MAC,
            Action::Remove {
                device_id: device.into(),
            },
        )
    }

    pub fn set_native_roles(&mut self, device: &str, roles: &[&str]) -> Value {
        self.append(
            MAC,
            Action::SetRoles {
                device_id: device.into(),
                change: RolesChange::Native(
                    roles.iter().map(|r| Role::parse(r).unwrap()).collect(),
                ),
            },
        )
    }

    /// Every entry, wire form.
    pub fn wire(&self) -> Vec<Value> {
        self.entries.iter().map(|e| e.object().to_json()).collect()
    }

    pub fn strict(&self) -> Vec<StrictValue> {
        self.wire()
            .iter()
            .map(|v| StrictValue::parse(v.to_string().as_bytes(), usize::MAX).unwrap())
            .collect()
    }

    /// A browser grant from `issuer` for `host_id`: a fresh P-256 browser
    /// key (inserted as `"browser <grant_id>"`).
    #[allow(clippy::too_many_arguments)]
    pub fn grant(
        &mut self,
        issuer: &str,
        grant_id: &str,
        host_id: &str,
        host_trust_gen: u64,
        session_id: Option<&str>,
        ops: &[&str],
        issued_at: u64,
        expires_at: u64,
    ) -> (SignedObject, KeyId) {
        let key = KeyId::new(format!("browser {grant_id}"));
        let s = secret(&format!("browser {grant_id}"));
        self.keys.insert_p256(key.clone(), &s).unwrap();
        let browser_key = PublicKey::new(Alg::P256, &p256_pub(&s)).unwrap();
        let ops: BTreeSet<Op> = ops.iter().map(|o| Op::parse(o).unwrap()).collect();
        let body = BrowserGrant::body(
            &self.log,
            grant_id,
            issuer,
            &browser_key,
            host_id,
            host_trust_gen,
            session_id,
            &ops,
            issued_at,
            expires_at,
        );
        let grant = BrowserGrant::issue(&self.log, &self.keys, &auth(issuer), body)
            .unwrap()
            .object;
        (grant, key)
    }
}

/// `b64u` of a host channel key's public half.
pub fn host_pub_b64u(seed: &[u8; 32]) -> String {
    b64u(&ed_pub(seed))
}
