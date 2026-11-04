//! Narrow, durable return grants for explicit task results.

use super::*;
use atem_client::session::{
    host_work::{ContextKind, ContextSnapshot, WorkState},
    wire::Target,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OriginRoute {
    pub id: String,
    pub revision: u64,
    pub profile_id: String,
    pub profile_revision: u64,
    pub project: String,
    pub results: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Origin {
    pub target: Target,
    pub control_gen: u64,
    pub route: Option<OriginRoute>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReturnGrant {
    pub task_id: String,
    pub message_id: String,
    pub workflow_id: String,
    pub result_id: String,
    pub origin: Origin,
    pub recipient: Target,
    pub turn_id: Option<String>,
    pub expires_at: u64,
}

impl ReturnGrant {
    pub fn live(
        &self,
        now: u64,
        state: WorkState,
        origin: &Target,
        control: u64,
        route_valid: bool,
    ) -> bool {
        now < self.expires_at
            && !matches!(
                state,
                WorkState::Cancelled
                    | WorkState::Expired
                    | WorkState::Failed
                    | WorkState::OutcomeUnknown
            )
            && self.origin.target == *origin
            && self.origin.control_gen == control
            && route_valid
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExplicitResult {
    pub task_id: String,
    pub session_id: String,
    pub process_gen: String,
    pub turn_id: String,
    pub text: String,
    pub context: Vec<ContextSnapshot>,
}

impl ExplicitResult {
    pub fn snapshot(&self) -> ContextSnapshot {
        let text = serde_json::to_string(self).expect("serializable result");
        ContextSnapshot {
            kind: ContextKind::Result,
            id: format!("result:{}", self.task_id),
            version: 1,
            digest: atem_client::session::host_work::digest(text.as_bytes()),
            text,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResultOutcome {
    Accepted,
    Duplicate,
}

pub fn save_grant(tx: &Transaction<'_>, grant: &ReturnGrant) -> Result<()> {
    tx.execute(
        "INSERT INTO return_grants(task_id,record) VALUES(?1,?2)",
        params![grant.task_id, serde_json::to_string(grant)?],
    )?;
    Ok(())
}

pub fn grant(store: &Store, task_id: &str) -> Result<Option<ReturnGrant>> {
    store
        .db
        .query_row(
            "SELECT record FROM return_grants WHERE task_id=?1",
            [task_id],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .map(|s| Ok(serde_json::from_str(&s)?))
        .transpose()
}

pub fn accepted(store: &Store, task_id: &str) -> Result<Option<ExplicitResult>> {
    store
        .db
        .query_row(
            "SELECT envelope FROM results WHERE task_id=?1",
            [task_id],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .map(|s| Ok(serde_json::from_str(&s)?))
        .transpose()
}

pub fn accept_result(
    tx: &Transaction<'_>,
    grant: &ReturnGrant,
    reply: &ExplicitResult,
    now: u64,
) -> Result<ResultOutcome> {
    if reply.task_id != grant.task_id
        || reply.session_id != grant.recipient.session_id
        || reply.process_gen != grant.recipient.process_gen
        || grant.turn_id.as_deref() != Some(reply.turn_id.as_str())
    {
        bail!("mismatch");
    }
    let envelope = serde_json::to_string(reply)?;
    let digest = atem_client::session::host_work::digest(envelope.as_bytes());
    let old: Option<String> = tx
        .query_row(
            "SELECT digest FROM results WHERE task_id=?1",
            [&grant.task_id],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(old) = old {
        if old != digest {
            bail!("request_id_reused");
        }
        return Ok(ResultOutcome::Duplicate);
    }
    if now >= grant.expires_at {
        bail!("expired");
    }
    let open: bool = tx.query_row(
        "SELECT state='open' FROM return_grants WHERE task_id=?1",
        [&grant.task_id],
        |r| r.get(0),
    )?;
    if !open {
        bail!("no_grant");
    }
    tx.execute(
        "INSERT INTO results(task_id,digest,envelope) VALUES(?1,?2,?3)",
        params![grant.task_id, digest, envelope],
    )?;
    tx.execute(
        "UPDATE return_grants SET state='consumed' WHERE task_id=?1",
        [&grant.task_id],
    )?;
    Ok(ResultOutcome::Accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_permits_one_result_into_one_session() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let grant = grant();
        let tx = store.db.unchecked_transaction().unwrap();
        save_grant(&tx, &grant).unwrap();
        let explicit = reply(&grant, "done");
        assert_eq!(
            accept_result(&tx, &grant, &explicit, 100).unwrap(),
            ResultOutcome::Accepted
        );
        assert_eq!(
            accept_result(&tx, &grant, &explicit, 100).unwrap(),
            ResultOutcome::Duplicate
        );
        assert_eq!(
            accept_result(&tx, &grant, &reply(&grant, "different"), 100)
                .unwrap_err()
                .to_string(),
            "request_id_reused"
        );
        let mut mismatch = explicit;
        mismatch.process_gen = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            accept_result(&tx, &grant, &mismatch, 100)
                .unwrap_err()
                .to_string(),
            "mismatch"
        );
    }

    #[test]
    fn a_grant_ends_with_cancel_expiry_process_end_and_control_change() {
        let g = grant();
        assert!(g.live(
            100,
            WorkState::AwaitingResult,
            &g.origin.target,
            g.origin.control_gen,
            true
        ));
        assert!(!g.live(
            100,
            WorkState::Cancelled,
            &g.origin.target,
            g.origin.control_gen,
            true
        ));
        assert!(!g.live(
            g.expires_at,
            WorkState::AwaitingResult,
            &g.origin.target,
            g.origin.control_gen,
            true
        ));
        let mut another = g.origin.target.clone();
        another.process_gen = uuid::Uuid::new_v4().to_string();
        assert!(!g.live(
            100,
            WorkState::AwaitingResult,
            &another,
            g.origin.control_gen,
            true
        ));
        assert!(!g.live(
            100,
            WorkState::AwaitingResult,
            &g.origin.target,
            g.origin.control_gen + 1,
            true
        ));
        assert!(!g.live(
            100,
            WorkState::AwaitingResult,
            &g.origin.target,
            g.origin.control_gen,
            false
        ));
    }

    fn grant() -> ReturnGrant {
        let origin = Origin {
            target: target("ses-aaaaaaaaaaaa"),
            control_gen: 1,
            route: None,
        };
        ReturnGrant {
            task_id: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, b"task").to_string(),
            message_id: uuid::Uuid::new_v4().to_string(),
            workflow_id: uuid::Uuid::new_v4().to_string(),
            result_id: uuid::Uuid::new_v4().to_string(),
            origin,
            recipient: target("ses-bbbbbbbbbbbb"),
            turn_id: Some("turn-1".into()),
            expires_at: 10_000,
        }
    }
    fn target(session: &str) -> Target {
        Target {
            account_id: "account".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1,
            session_id: session.into(),
            process_gen: uuid::Uuid::new_v4().to_string(),
        }
    }
    fn reply(g: &ReturnGrant, text: &str) -> ExplicitResult {
        ExplicitResult {
            task_id: g.task_id.clone(),
            session_id: g.recipient.session_id.clone(),
            process_gen: g.recipient.process_gen.clone(),
            turn_id: "turn-1".into(),
            text: text.into(),
            context: vec![],
        }
    }
}
