use super::*;
use crate::chat::adapter::{ApprovalCard, ApprovalCardState};
use crate::chat::session::Origin;
use serde_json::json;

const GEN: &str = "22222222-2222-4222-8222-222222222222";
const RID: &str = "44444444-4444-4444-8444-000000000001";

fn msg(id: &str, turn: &str, role: Role, text: &str) -> ChatMessage {
    ChatMessage {
        message_id: id.into(),
        role,
        origin: (role == Role::User).then_some(Origin::Local),
        turn_id: turn.into(),
        request_id: None,
        created_at_ms: 0,
        parts: vec![Part::Text {
            id: "p1".into(),
            markdown: text.into(),
        }],
    }
}

fn card(id: &str, turn: &str) -> ChatMessage {
    ChatMessage {
        message_id: format!("approval-{id}"),
        role: Role::Assistant,
        origin: None,
        turn_id: turn.into(),
        request_id: None,
        created_at_ms: 0,
        parts: vec![Part::Approval(ApprovalCard {
            id: "approval".into(),
            approval_id: id.into(),
            tool: "Bash".into(),
            summary: "ls".into(),
            always_rules: Vec::new(),
            state: ApprovalCardState::Pending,
            rule_id: None,
            note: None,
            reason: None,
        })],
    }
}

/// `n` turns of a user and an assistant message (`m-0001`, … in turns
/// `turn-1`, …), `bytes` of text each.
fn chat_of(n: usize, bytes: usize) -> ChatSession {
    let mut chat = ChatSession::new(GEN.into(), 0);
    for t in 1..=n {
        let turn = format!("turn-{t}");
        chat.put_message(msg(
            &format!("m-{:04}", 2 * t - 1),
            &turn,
            Role::User,
            &"x".repeat(bytes),
        ));
        chat.put_message(msg(
            &format!("m-{:04}", 2 * t),
            &turn,
            Role::Assistant,
            &"x".repeat(bytes),
        ));
    }
    chat
}

fn cx<'a>(attachment: &'a str, conversation: &'a str) -> Context<'a> {
    Context {
        attachment,
        conversation,
        session: "ses-aaaaaaaaaaaa",
        process_gen: GEN,
    }
}

fn to<'a>(c: Context<'a>, page_id: Option<&'a str>, control: bool) -> PageFor<'a> {
    PageFor {
        cx: c,
        page_id,
        control,
    }
}

fn data(e: &ChatEnvelope) -> Value {
    serde_json::to_value(e).unwrap()
}

/// (message ids, the history_end's data) of a page.
fn split(page: &[ChatEnvelope]) -> (Vec<String>, Value) {
    let (end, messages) = page.split_last().unwrap();
    let ids = messages
        .iter()
        .map(|m| data(m)["messageId"].as_str().unwrap().to_string())
        .collect();
    (ids, data(end))
}

fn ids(range: std::ops::RangeInclusive<usize>) -> Vec<String> {
    range.map(|i| format!("m-{i:04}")).collect()
}

#[test]
fn a_newest_page_and_its_next_pages_go_backwards_in_bounds() {
    let chat = chat_of(60, 10);
    let key = HistoryKey::random();
    let c = cx("a1", "conv-1");
    let page = page(&chat, &key, &to(c, None, true), Select::Newest, 1).unwrap();
    let (got, end) = split(&page);
    assert_eq!(got, ids(71..=120));
    assert_eq!(end["op"], "history_end");
    assert_eq!(end["sequence"], 51);
    assert!(end.get("page_id").is_none(), "the open's page has none");
    let p = &end["page"];
    assert_eq!(p["selector"], "newest");
    assert_eq!(p["count"], 50);
    assert_eq!(p["content_bytes"], 500);
    assert_eq!(p["end"], false);
    assert_eq!(p["coverage"], "complete");
    assert_eq!(p["oldest_retained"], "m-0001");
    assert_eq!(p["truncated"], false);
    assert_eq!(p["holes"], json!([]));
    let wire: usize = page.iter().map(wire_size).sum();
    assert_eq!(p["wire_bytes"], wire, "the sum of the page's envelopes");
    // Sequences are consecutive, the messages carry history: true.
    for (k, e) in page.iter().enumerate() {
        assert_eq!(data(e)["sequence"], 1 + k as u64);
    }
    assert_eq!(data(&page[0])["history"], true);
    let next = p["next"].as_str().unwrap().to_string();
    assert!(next.len() <= 512 && is_base64url(&next));
    let more = page_fn(
        &chat,
        &key,
        &to(c, Some("p2"), true),
        Select::Next(next),
        52,
    );
    let (got, end) = split(&more.unwrap());
    assert_eq!(got, ids(21..=70));
    assert_eq!(end["page_id"], "p2");
    assert_eq!(
        end["page"]["selector"], "newest",
        "a continuation keeps its selector"
    );
    let next = end["page"]["next"].as_str().unwrap().to_string();
    let (got, end) = split(
        &page_fn(
            &chat,
            &key,
            &to(c, Some("p3"), true),
            Select::Next(next),
            103,
        )
        .unwrap(),
    );
    assert_eq!(got, ids(1..=20));
    assert_eq!(end["page"]["end"], true);
    assert!(end["page"].get("next").is_none());
}

/// `page` under another name (the test functions shadow it).
fn page_fn(
    chat: &ChatSession,
    key: &HistoryKey,
    to: &PageFor,
    select: Select,
    first_seq: u64,
) -> Result<Vec<ChatEnvelope>, Stale> {
    super::page(chat, key, to, select, first_seq)
}

#[test]
fn pages_stop_at_the_content_and_serialized_bounds() {
    // 120 KiB messages: two fit the 256 KiB content bound.
    let chat = chat_of(3, 120 * 1024);
    let key = HistoryKey::random();
    let c = cx("a1", "conv-1");
    let (got, end) = split(&page(&chat, &key, &to(c, None, true), Select::Newest, 1).unwrap());
    assert_eq!(got.len(), 2);
    assert_eq!(end["page"]["content_bytes"], 2 * 120 * 1024);
    // Control characters escape to 6 bytes: the serialized bound cuts.
    let mut chat = ChatSession::new(GEN.into(), 0);
    for n in 1..=40 {
        chat.put_message(msg(
            &format!("m-{n:04}"),
            "turn-1",
            Role::Assistant,
            &"\u{1}".repeat(6000),
        ));
    }
    let page = page(&chat, &key, &to(c, None, true), Select::Newest, 1).unwrap();
    let wire: usize = page.iter().map(wire_size).sum();
    assert!(wire <= PAGE_WIRE_BYTES, "{wire}");
    let (got, end) = split(&page);
    assert!(got.len() < 40 && got.len() * 6000 < PAGE_CONTENT_BYTES);
    assert_eq!(end["page"]["wire_bytes"], wire);
    // One more message would pass the bound.
    assert!(wire + 36_200 > PAGE_WIRE_BYTES, "{wire}");
}

#[test]
fn a_lookup_goes_forwards_through_the_turn_at_its_first_snapshot() {
    let mut chat = ChatSession::new(GEN.into(), 0);
    let mut user = msg("t9-u", "turn-9", Role::User, "go");
    user.request_id = Some(RID.into());
    user.origin = Some(Origin::Remote);
    chat.put_message(msg("m-0000", "turn-8", Role::User, "before"));
    chat.put_message(user);
    for n in 1..=60 {
        chat.put_message(msg(&format!("t9-a-{n:04}"), "turn-9", Role::Assistant, "r"));
    }
    let key = HistoryKey::random();
    let c = cx("a1", "conv-1");
    let first = page(
        &chat,
        &key,
        &to(c, Some("p1"), true),
        Select::Request(RID.into()),
        5,
    )
    .unwrap();
    let (got, end) = split(&first);
    assert_eq!(got.len(), 50);
    assert_eq!(got[0], "t9-u");
    assert_eq!(end["page"]["selector"], "request_id");
    assert_eq!(end["page"]["coverage"], "complete");
    // Later messages of the turn arrive live, not in the lookup.
    chat.put_message(msg("t9-a-0061", "turn-9", Role::Assistant, "late"));
    let next = end["page"]["next"].as_str().unwrap().to_string();
    let (got, end) = split(
        &page(
            &chat,
            &key,
            &to(c, Some("p1-2"), true),
            Select::Next(next),
            56,
        )
        .unwrap(),
    );
    assert_eq!(got.first().unwrap(), "t9-a-0050");
    assert_eq!(got.last().unwrap(), "t9-a-0060");
    assert_eq!(end["page"]["end"], true);
    assert_eq!(end["page"]["selector"], "request_id");
    // By turn id: the same turn, nothing of another.
    let (got, _) = split(
        &page(
            &chat,
            &key,
            &to(c, Some("t"), true),
            Select::Turn("turn-8".into()),
            1,
        )
        .unwrap(),
    );
    assert_eq!(got, ["m-0000"]);
    // Nothing retained: an empty page, unavailable, not an error.
    for select in [
        Select::Turn("turn-1".into()),
        Select::Request("44444444-4444-4444-8444-000000000009".into()),
    ] {
        let (got, end) = split(&page(&chat, &key, &to(c, Some("x"), true), select, 1).unwrap());
        assert!(got.is_empty());
        assert_eq!(end["page"]["count"], 0);
        assert_eq!(end["page"]["end"], true);
        assert_eq!(end["page"]["coverage"], "unavailable");
    }
}

#[test]
fn a_next_token_is_bound_to_its_context_snapshot_and_run() {
    let mut chat = chat_of(40, 1);
    let key = HistoryKey::random();
    let c = cx("a1", "conv-1");
    let (_, end) = split(&page(&chat, &key, &to(c, None, true), Select::Newest, 1).unwrap());
    let token = end["page"]["next"].as_str().unwrap().to_string();
    let next = |chat: &ChatSession, key: &HistoryKey, c: Context, token: &str| {
        page(
            chat,
            key,
            &to(c, Some("p"), true),
            Select::Next(token.into()),
            60,
        )
    };
    assert!(next(&chat, &key, c, &token).is_ok());
    // Another attachment, conversation, session or process; another run's
    // key; an altered token.
    let other = Context {
        session: "ses-bbbbbbbbbbbb",
        ..c
    };
    let process = Context {
        process_gen: "22222222-2222-4222-8222-222222222223",
        ..c
    };
    for c2 in [cx("a2", "conv-1"), cx("a1", "conv-2"), other, process] {
        assert_eq!(next(&chat, &key, c2, &token), Err(Stale));
    }
    assert_eq!(next(&chat, &HistoryKey::random(), c, &token), Err(Stale));
    let mut altered = token.clone().into_bytes();
    altered[3] = if altered[3] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        next(&chat, &key, c, &String::from_utf8(altered).unwrap()),
        Err(Stale)
    );
    assert_eq!(next(&chat, &key, c, &format!("{token}x")), Err(Stale));
    // A reload: another snapshot.
    let mut reloaded = chat_of(40, 1);
    let all: Vec<ChatMessage> = reloaded.retained().cloned().collect();
    reloaded.reload(all);
    assert_eq!(next(&reloaded, &key, c, &token), Err(Stale));
    // Its continuation point evicted.
    chat.evict(30);
    assert_eq!(next(&chat, &key, c, &token), Err(Stale));
}

#[test]
fn a_before_no_longer_retained_is_stale() {
    let mut chat = chat_of(3, 1);
    let key = HistoryKey::random();
    let c = cx("a1", "conv-1");
    let before = |chat: &ChatSession, id: &str| {
        page(
            chat,
            &key,
            &to(c, Some("p"), true),
            Select::Before(id.into()),
            1,
        )
    };
    let (got, end) = split(&before(&chat, "m-0003").unwrap());
    assert_eq!(got, ids(1..=2));
    assert_eq!(end["page"]["selector"], "before");
    chat.evict(3);
    assert_eq!(before(&chat, "m-0003"), Err(Stale));
    assert_eq!(before(&chat, "m-9999"), Err(Stale));
}

#[test]
fn coverage_shows_truncation_and_holes() {
    let mut chat = chat_of(5, 1);
    let key = HistoryKey::random();
    let c = cx("a1", "conv-1");
    chat.evict(3);
    let (got, end) = split(&page(&chat, &key, &to(c, None, true), Select::Newest, 1).unwrap());
    assert_eq!(got, ids(4..=10));
    let p = &end["page"];
    assert_eq!(
        (p["truncated"].clone(), p["oldest_retained"].clone()),
        (json!(true), json!("m-0004"))
    );
    assert_eq!(p["coverage"], "partial");
    // turn-2 lost m-0003: partial; turn-3 is whole; turn-1 is gone.
    let turn = |chat: &ChatSession, t: &str| {
        let (_, end) = split(
            &page(
                chat,
                &key,
                &to(c, Some("t"), true),
                Select::Turn(t.into()),
                1,
            )
            .unwrap(),
        );
        end["page"]["coverage"].clone()
    };
    assert_eq!(turn(&chat, "turn-2"), "partial");
    assert_eq!(turn(&chat, "turn-3"), "complete");
    assert_eq!(turn(&chat, "turn-1"), "unavailable");
    // A hole after m-0006 (inside turn-3's neighbourhood).
    assert!(chat.add_hole(Some("m-0006"), Some("m-0007"), Some(2)));
    assert_eq!(turn(&chat, "turn-3"), "partial");
    assert_eq!(turn(&chat, "turn-4"), "partial");
    assert_eq!(turn(&chat, "turn-5"), "complete");
    let (_, end) = split(&page(&chat, &key, &to(c, None, true), Select::Newest, 1).unwrap());
    assert_eq!(
        end["page"]["holes"],
        json!([{"after_message_id": "m-0006", "before_message_id": "m-0007", "count": 2}])
    );
    // A page without the hole's newer neighbour doesn't list it.
    let (_, end) = split(
        &page(
            &chat,
            &key,
            &to(c, Some("b"), true),
            Select::Before("m-0006".into()),
            1,
        )
        .unwrap(),
    );
    assert_eq!(end["page"]["holes"], json!([]));
    // A hole older than what is retained is truncation.
    chat.evict(3);
    assert!(chat.holes().is_empty());
    assert!(!chat.add_hole(Some("m-0001"), Some("m-0008"), None));
}

#[test]
fn a_page_lists_at_most_16_holes() {
    let mut chat = chat_of(20, 1);
    for n in 1..=20 {
        chat.add_hole(
            Some(&format!("m-{:04}", 2 * n - 1)),
            Some(&format!("m-{:04}", 2 * n)),
            None,
        );
    }
    let key = HistoryKey::random();
    let (_, end) = split(
        &page(
            &chat,
            &key,
            &to(cx("a", "c"), None, true),
            Select::Newest,
            1,
        )
        .unwrap(),
    );
    assert_eq!(end["page"]["holes"].as_array().unwrap().len(), 16);
    assert_eq!(end["page"]["holes_more"], true);
    assert!(
        end["page"]["holes"][0].get("count").is_none(),
        "count only when known"
    );
}

#[test]
fn cards_are_left_out_for_a_view_only_attachment_and_dont_count() {
    let mut chat = ChatSession::new(GEN.into(), 0);
    chat.put_message(msg("m-0001", "turn-1", Role::User, "hi"));
    for n in 0..60 {
        chat.put_card(card(&format!("a{n}"), "turn-1"));
    }
    let key = HistoryKey::random();
    let (got, end) = split(
        &page(
            &chat,
            &key,
            &to(cx("a", "c"), None, false),
            Select::Newest,
            1,
        )
        .unwrap(),
    );
    assert_eq!(got, ["m-0001"]);
    assert_eq!(end["page"]["end"], true);
    let (got, _) = split(
        &page(
            &chat,
            &key,
            &to(cx("a", "c"), None, true),
            Select::Newest,
            1,
        )
        .unwrap(),
    );
    assert_eq!(got.len(), 50);
}

#[test]
fn history_requests_follow_the_field_rules() {
    let base = json!({"v": 1, "op": "history", "conversationId": "c", "agentId": "ses-aaaaaaaaaaaa",
                      "generation": GEN, "page_id": "p1"});
    let with = |extra: Value| {
        let mut d = base.clone();
        d.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        d
    };
    assert_eq!(
        parse_request(&with(json!({"turn_id": "turn-1"})))
            .unwrap()
            .select,
        Select::Turn("turn-1".into())
    );
    assert_eq!(
        parse_request(&with(json!({"request_id": RID})))
            .unwrap()
            .select,
        Select::Request(RID.into())
    );
    for bad in [
        json!({}),
        json!({"before": "m-1", "turn_id": "t"}),
        json!({"before": "m-1", "next": "abc"}),
        json!({"request_id": "not-a-uuid"}),
        json!({"request_id": "44444444-4444-4444-8444-00000000000A"}),
        json!({"turn_id": "t".repeat(129)}),
        json!({"turn_id": ""}),
        json!({"before": "m 1"}),
        json!({"next": "x".repeat(513)}),
        json!({"next": "not base64url!"}),
        json!({"before": 5}),
    ] {
        assert_eq!(
            parse_request(&with(bad.clone())),
            Err(Some("p1".into())),
            "{bad}"
        );
    }
    let mut d = with(json!({"turn_id": "t"}));
    d["page_id"] = json!("this page id has spaces");
    assert_eq!(parse_request(&d), Err(None));
    d["page_id"] = json!("p".repeat(65));
    assert_eq!(parse_request(&d), Err(None));
    let mut d = with(json!({"turn_id": "t"}));
    d.as_object_mut().unwrap().remove("generation");
    assert_eq!(parse_request(&d), Err(Some("p1".into())));
}

fn opening<'a>(conversation: &'a str, attachment: &'a str, status: &'a Status) -> Opening<'a> {
    Opening {
        conversation,
        agent: "ses-aaaaaaaaaaaa",
        attachment,
        control: true,
        status,
        unavailable: &[],
        rules: &[],
    }
}

#[test]
fn conversations_page_in_their_stream_and_answer_errors_there() {
    let chat = chat_of(2, 1);
    let key = HistoryKey::random();
    let status = chat.status().clone();
    let mut convs = Conversations::default();
    let opened = convs.open(&chat, &key, &opening("conv-1", "a1", &status));
    let ops: Vec<String> = opened.iter().map(|e| e.op.clone()).collect();
    assert_eq!(
        ops,
        [
            "opened",
            "message",
            "message",
            "message",
            "message",
            "history_end"
        ]
    );
    fn call<'a>(d: &'a Value, attachment: &'static str, now_ms: u64) -> HistoryCall<'a> {
        HistoryCall {
            data: d,
            conversation: "conv-1",
            agent: "ses-aaaaaaaaaaaa",
            attachment,
            control: true,
            now_ms,
        }
    }
    let req = |extra: Value| {
        let mut d = json!({"generation": GEN, "page_id": "p1"});
        d.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        d
    };
    // An invalid request: a sequenced error with its page id.
    let bad = req(json!({}));
    let out = convs.history(&chat, &key, &call(&bad, "a1", 0));
    assert_eq!(
        data(&out[0]),
        json!({"v": 1, "op": "error", "conversationId": "conv-1", "agentId": "ses-aaaaaaaaaaaa",
               "generation": GEN, "sequence": 6, "code": "invalid_request",
               "text": INVALID_TEXT, "page_id": "p1"})
    );
    // Another attachment's conversation: stale_target, unsequenced.
    let ok = req(json!({"turn_id": "turn-1"}));
    let out = convs.history(&chat, &key, &call(&ok, "a2", 0));
    assert_eq!(data(&out[0])["code"], "stale_target");
    assert!(data(&out[0]).get("sequence").is_none());
    // Another generation: stale_target.
    let mut other = ok.clone();
    other["generation"] = json!("22222222-2222-4222-8222-222222222223");
    let out = convs.history(&chat, &key, &call(&other, "a1", 0));
    assert_eq!(data(&out[0])["code"], "stale_target");
    assert_eq!(data(&out[0])["sequence"], 7);
    // A page, then at most 8 a second (invalid ones don't count).
    let out = convs.history(&chat, &key, &call(&ok, "a1", 0));
    assert_eq!(data(&out[0])["sequence"], 8);
    assert_eq!(data(out.last().unwrap())["op"], "history_end");
    for _ in 0..7 {
        let out = convs.history(&chat, &key, &call(&ok, "a1", 500));
        assert_eq!(data(out.last().unwrap())["op"], "history_end");
    }
    let out = convs.history(&chat, &key, &call(&ok, "a1", 999));
    assert_eq!(data(&out[0])["code"], "busy");
    let out = convs.history(&chat, &key, &call(&ok, "a1", 1000));
    assert_eq!(data(out.last().unwrap())["op"], "history_end");
    // Another attachment can't close it.
    assert!(!convs.close("conv-1", "a2"));
    assert!(convs.close("conv-1", "a1"));
}

#[test]
fn a_ninth_conversation_closes_the_oldest_with_its_reason() {
    let chat = chat_of(1, 1);
    let key = HistoryKey::random();
    let status = chat.status().clone();
    let mut convs = Conversations::default();
    for n in 1..=8 {
        let out = convs.open(&chat, &key, &opening(&format!("conv-{n}"), "a1", &status));
        assert_eq!(out[0].op, "opened");
    }
    let out = convs.open(&chat, &key, &opening("conv-9", "a1", &status));
    assert_eq!(
        data(&out[0]),
        json!({"v": 1, "op": "close", "conversationId": "conv-1",
               "agentId": "ses-aaaaaaaaaaaa", "reason": "evicted"})
    );
    assert_eq!(out[1].op, "opened");
    assert_eq!(convs.map.len(), 8);
}

#[test]
fn turn_replies_are_partial_with_a_hole_in_the_turn() {
    let mut chat = ChatSession::new(GEN.into(), 0);
    chat.put_message(msg("t7-u", "t7", Role::User, "go"));
    chat.put_message(msg("t7-a1", "t7", Role::Assistant, "a"));
    chat.put_message(msg("t7-a2", "t7", Role::Assistant, "b"));
    let r = turn_replies(&chat, "t7", "t7-u");
    assert_eq!((r.ids.len(), r.coverage), (2, Coverage::Complete));
    chat.add_hole(Some("t7-a1"), Some("t7-a2"), None);
    assert_eq!(
        turn_replies(&chat, "t7", "t7-u").coverage,
        Coverage::Partial
    );
}
