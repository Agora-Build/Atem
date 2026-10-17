#!/usr/bin/python3 -I
# Stand-in for the Codex TUI in Atem's Codex chat tests. Like Codex it runs
# every command of $CODEX_HOME/hooks.json (the entries Atem installed, through
# `sh -c`) for each lifecycle event, and writes the rollout
# $CODEX_HOME/sessions/2026/10/17/rollout-2026-10-17T00-00-00-<session>.jsonl
# as Codex 0.162.1 does (designs/fixtures/codex-hooks/README.md): nothing
# before the first prompt (SessionStart is lazy), then per turn
# task_started, UserPromptSubmit, the UserMessage item, ... task_complete.
#
# Terminal input: typed text, or a bracketed paste, goes into the composer;
# Enter submits it as a prompt ("/new": a new session and rollout, its
# SessionStart at the next prompt, as Codex does); a lone Esc interrupts the
# running turn (Interrupt hook, turn_aborted).
# Control files in $FAKE_DIR (written by the test):
#   complete       the running turn answers "reply <n>" and ends
#   ask-<n>.json   a tool call needing approval ({tool_name, tool_input}):
#                  PreToolUse, then the PermissionRequest hook runs with it;
#                  allowed: PostToolUse and a CommandExecution item
#   deaf           Esc is ignored (the turn goes on)
#   exit           the agent exits (SessionEnd)
# What it saw, in $FAKE_DIR/events: "started", "new <session>",
# "prompt <turn> <text>",
# "completed <turn>", "interrupted <turn>", "asked <n>", "answer <n> <behavior>".
import json, os, select, subprocess, sys, time, tty, uuid

ctl = os.environ["FAKE_DIR"]
os.makedirs(ctl, exist_ok=True)
events = open(os.path.join(ctl, "events"), "a", buffering=1)
home = os.environ["CODEX_HOME"]
try:
    hooks = json.load(open(os.path.join(home, "hooks.json")))["hooks"]
except Exception:
    hooks = {}
try:
    tty.setraw(0)
except Exception:
    pass

day = os.path.join(home, "sessions", "2026", "10", "17")
os.makedirs(day, exist_ok=True)


def new_session():
    global session, rollout, ordinal, started
    session = str(uuid.uuid4())
    rollout = os.path.join(day, "rollout-2026-10-17T00-00-00-%s.jsonl" % session)
    ordinal = 0
    started = False


new_session()


def commands(event):
    return [h["command"] for group in hooks.get(event, []) for h in group["hooks"]]


def payload(event, extra):
    p = {"session_id": session, "transcript_path": rollout, "cwd": os.getcwd(),
         "hook_event_name": event, "model": "fake"}
    p.update(extra)
    return p


def fire(event, extra=None):
    for command in commands(event):
        subprocess.run(["sh", "-c", command], input=json.dumps(payload(event, extra or {})).encode(),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def record(kind, body):
    global ordinal
    ordinal += 1
    now = time.time()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % (int(now * 1000) % 1000)
    with open(rollout, "a") as f:
        f.write(json.dumps({"timestamp": stamp, "ordinal": ordinal, "type": kind, "payload": body}) + "\n")


def item(turn, it):
    ms = int(time.time() * 1000)
    record("event_msg", {"type": "item_completed", "thread_id": session, "turn_id": turn, "item": it,
                         "started_at_ms": ms, "completed_at_ms": ms})


turn, n_turns = None, 0


def submit(text):
    global started, turn, n_turns
    if not started:
        started = True
        fire("SessionStart", {"source": "startup"})
    n_turns += 1
    turn = "turn-%d" % n_turns
    record("event_msg", {"type": "task_started", "turn_id": turn,
                         "turn_attribution": {"turn_id": turn, "turn_trigger": "user"}})
    fire("UserPromptSubmit", {"turn_id": turn, "prompt": text, "permission_mode": "default"})
    item(turn, {"type": "UserMessage", "id": "user-%d" % n_turns,
                "content": [{"type": "text", "text": text, "text_elements": []}]})
    events.write("prompt %s %s\n" % (turn, text))


def end(aborted):
    global turn
    if aborted:
        fire("Interrupt", {"turn_id": turn})
        record("event_msg", {"type": "turn_aborted", "turn_id": turn, "reason": "interrupted"})
        events.write("interrupted %s\n" % turn)
    else:
        n = turn.split("-")[1]
        item(turn, {"type": "AgentMessage", "id": "msg-%s" % n,
                    "content": [{"type": "Text", "text": "reply %s" % n}], "phase": "final_answer"})
        fire("Stop", {"turn_id": turn, "stop_hook_active": False, "last_assistant_message": "reply %s" % n})
        record("event_msg", {"type": "task_complete", "turn_id": turn, "last_agent_message": "reply %s" % n})
        events.write("completed %s\n" % turn)
    turn = None


events.write("started\n")
os.write(1, b"READY\r\n")
START, END = b"\x1b[200~", b"\x1b[201~"
buf, composer = b"", b""
asks = {}
while True:
    ready, _, _ = select.select([0], [], [], 0.02)
    if ready:
        data = os.read(0, 65536)
        if not data:
            break
        buf += data
    while buf:
        if buf.startswith(START):
            e = buf.find(END)
            if e < 0:
                break
            composer += buf[len(START):e]
            buf = buf[e + len(END):]
        elif buf.startswith(b"\x1b"):
            if len(buf) > 1 and START.startswith(buf):
                break  # the rest of a paste start follows
            buf = buf[1:]
            if turn and not os.path.exists(os.path.join(ctl, "deaf")):
                end(True)
        elif buf[:1] in (b"\r", b"\n"):
            buf = buf[1:]
            if composer.strip():
                text = composer.decode("utf-8", "replace")
                composer = b""
                if text == "/new":
                    new_session()
                    events.write("new %s\n" % session)
                elif turn is None:
                    submit(text)
        else:
            composer += buf[:1]
            buf = buf[1:]
    if os.path.exists(os.path.join(ctl, "exit")):
        break
    complete = os.path.join(ctl, "complete")
    if turn and os.path.exists(complete):
        os.remove(complete)
        end(False)
    for name in sorted(os.listdir(ctl)):
        if name.startswith("ask-") and name.endswith(".json"):
            n = int(name[4:-5])
            if n in asks:
                continue
            request = json.load(open(os.path.join(ctl, name)))
            fire("PreToolUse", dict(request, turn_id=turn, tool_use_id="exec-%d" % n))
            command = commands("PermissionRequest")[0]
            proc = subprocess.Popen(["sh", "-c", command], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL)
            proc.stdin.write(json.dumps(payload("PermissionRequest", dict(request, turn_id=turn))).encode())
            proc.stdin.close()
            asks[n] = {"proc": proc, "request": request, "done": False}
            events.write("asked %d\n" % n)
    for n, ask in asks.items():
        if ask["done"] or ask["proc"].poll() is None:
            continue
        ask["done"] = True
        out = ask["proc"].stdout.read().decode("utf-8", "replace")
        behavior = "none"
        if out.strip():
            behavior = json.loads(out)["hookSpecificOutput"]["decision"].get("behavior", "none")
        events.write("answer %d %s\n" % (n, behavior))
        if behavior == "allow" and turn:
            request = ask["request"]
            fire("PostToolUse", dict(request, turn_id=turn, tool_use_id="exec-%d" % n, tool_response="ok"))
            item(turn, {"type": "CommandExecution", "id": "exec-%d" % n,
                        "command": ["/bin/bash", "-lc", request["tool_input"]["command"]],
                        "status": "completed", "aggregated_output": "ok", "exit_code": 0})
fire("SessionEnd", {"reason": "other"})
