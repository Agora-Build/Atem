#!/usr/bin/python3 -I
# Stand-in for Claude Code and Codex in Atem's approval tests. It runs the
# REAL PermissionRequest hook command it was given -- Claude: from the
# --settings file Atem wrote; Codex: $FAKE_CODEX_HOOK, the command Atem
# merges into ~/.codex/hooks.json -- and acts on the hook's answer the way the
# agent does.
#
# Control files in $FAKE_DIR (written by the test):
#   ask-<n>.json        a tool call needing permission ({tool_name, tool_input,
#                       permission_suggestions?, quiet?}): the hook runs with it
#                       (quiet: no tool_use entry in the transcript, so a chat
#                       the shared fixtures model gets no extra message)
#   terminal-yes-<n>    the user allows it in the agent's own dialog (Claude:
#                       the tool runs, PostToolUse fires)
#   terminal-no-<n>     the user refuses it in the dialog (Claude writes its
#                       rejection tool_result; the turn is interrupted)
#   kill-<n>            the hook is killed (the prompt was interrupted)
#   stop-<n>            the hook is stopped (SIGSTOP): it never takes a decision
#   exit                the agent exits
#   transcript-<n>.jsonl  transcript entries (one JSON object per line), appended
#                       to the transcript as they are, in order of n from 1, with
#                       no hook: what a conversation already held, or content
#                       arriving that the shared fixtures name (event
#                       "transcribed <n>")
# What it saw, in $FAKE_DIR: input (every byte its terminal delivered),
# events (one line per thing it did: "started", "input <bytes>", "asked <n>", "answer <n>
# <allow|deny|none> <message>", "ran <n>", "refused <n>", "completed <turn>",
# "winch", "signal <n> worker_alive=<bool>"), answer-<n>.json (the hook's raw
# output).
# With --settings each bracketed paste is a prompt (chat hooks and a
# transcript as Claude Code writes them); a turn ends when $FAKE_DIR/complete
# appears.
import json, os, select, signal, subprocess, sys, time, tty

args = sys.argv[1:]
settings = session = None
i = 0
while i < len(args):
    if args[i] == "--settings":
        settings = args[i + 1]; i += 1
    elif args[i] == "--session-id":
        session = args[i + 1]; i += 1
    i += 1
ctl = os.environ["FAKE_DIR"]
os.makedirs(ctl, exist_ok=True)
log_in = open(os.path.join(ctl, "input"), "ab", buffering=0)
events = open(os.path.join(ctl, "events"), "a", buffering=1)
parent = os.getppid()
asks = {}  # n -> {"proc", "request", "done"}
def end_hooks():
    """Hooks still running end with the agent, as Claude and Codex end
    theirs: a stopped one (stop-<n>) is woken to take its SIGTERM, never left
    stopped behind."""
    for ask in asks.values():
        if ask["proc"].poll() is None:
            for sig in (signal.SIGTERM, signal.SIGCONT):
                try:
                    ask["proc"].send_signal(sig)
                except Exception:
                    pass
def ended(signum, frame):
    time.sleep(0.1)
    events.write("signal %d worker_alive=%s\n" % (signum, os.getppid() == parent))
    end_hooks()
    os._exit(0)
signal.signal(signal.SIGHUP, ended)
signal.signal(signal.SIGTERM, ended)
signal.signal(signal.SIGWINCH, lambda signum, frame: events.write("winch\n"))
try:
    tty.setraw(0)
except Exception:
    pass

hooks = json.load(open(settings))["hooks"] if settings else {}
def commands(event):
    return [h["command"] for group in hooks.get(event, []) for h in group["hooks"]]
permission = commands("PermissionRequest")[0] if settings else os.environ.get("FAKE_CODEX_HOOK")
session = session or "fake-session"
transcript = None
if settings:
    transcript = os.path.join(os.path.dirname(os.path.dirname(settings)), "transcripts", session + ".jsonl")
    os.makedirs(os.path.dirname(transcript), exist_ok=True)
    open(transcript, "a").close()

def fire(event, payload):
    payload = dict(payload, hook_event_name=event, session_id=session)
    for command in commands(event):
        subprocess.run(["sh", "-c", command], input=json.dumps(payload).encode(), check=False)

def log(record):
    if transcript:
        now = time.time()
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % (int(now * 1000) % 1000)
        record.setdefault("timestamp", stamp)
        with open(transcript, "a") as f:
            f.write(json.dumps(record) + "\n")

REJECTED = ("The user doesn't want to proceed with this tool use. The tool use was rejected "
            "(eg. if it was a file edit, the new_string was NOT written to the file). STOP what "
            "you are doing and wait for the user to tell you how to proceed.")

def tool_result(n, text, error):
    log({"type": "user", "uuid": "r-%d" % n, "promptId": turn_id(),
         "message": {"role": "user", "content": [
             {"type": "tool_result", "tool_use_id": "toolu-%d" % n, "content": text, "is_error": error}]}})

turns, n_turns = [], 0
def turn_id():
    return turns[0] if turns else "turn-0"

fire("SessionStart", {"transcript_path": transcript, "source": "startup"})
events.write("started\n")
os.write(1, b"READY\r\n")

def answered(n, ask):
    """The hook ended: what it answered, and what the agent does about it."""
    if ask["done"] or ask["proc"].poll() is None:
        return
    request = ask["request"]
    tool = {"tool_name": request["tool_name"], "tool_input": request["tool_input"]}
    ask["done"] = True
    out = ask["proc"].stdout.read().decode("utf-8", "replace")
    with open(os.path.join(ctl, "answer-%d.json" % n), "w") as f:
        f.write(out)
    decision = {}
    if out.strip():
        decision = json.loads(out)["hookSpecificOutput"]["decision"]
    behavior = decision.get("behavior", "none")
    message = decision.get("message", "")
    events.write("answer %d %s %s\n" % (n, behavior, message))
    if behavior == "allow":
        fire("PostToolUse", dict(tool, tool_response={"stdout": "ok"}))
        tool_result(n, "ok", False)
    elif behavior == "deny":
        # Claude Code writes the hook's message as it is (checked live).
        tool_result(n, message, True)

transcribed = 0
START, END = b"\x1b[200~", b"\x1b[201~\r"
buf = b""
while True:
    ready, _, _ = select.select([0], [], [], 0.02)
    if ready:
        # Hooks that ended before this input arrived are logged first, so
        # the events show which came first.
        for n, ask in asks.items():
            answered(n, ask)
        data = os.read(0, 65536)
        if not data:
            break
        log_in.write(data)
        events.write("input %d\n" % len(data))
        buf += data
        while settings:
            s = buf.find(START)
            e = buf.find(END, s + 1) if s >= 0 else -1
            if e < 0:
                break
            text = buf[s + len(START):e].decode("utf-8", "replace")
            buf = buf[e + len(END):]
            n_turns += 1
            turn = "turn-%d" % n_turns
            fire("UserPromptSubmit", {"prompt": text, "prompt_id": turn})
            log({"type": "user", "uuid": "u-%d" % n_turns, "promptId": turn,
                 "message": {"role": "user", "content": text}})
            turns.append(turn)
    if os.path.exists(os.path.join(ctl, "exit")):
        break
    scripted = os.path.join(ctl, "transcript-%d.jsonl" % (transcribed + 1))
    if transcript and os.path.exists(scripted):
        transcribed += 1
        for line in open(scripted):
            if line.strip():
                log(json.loads(line))
        events.write("transcribed %d\n" % transcribed)
    complete = os.path.join(ctl, "complete")
    if turns and os.path.exists(complete):
        os.remove(complete)
        turn = turns.pop(0)
        log({"type": "assistant", "uuid": "a-" + turn, "promptId": turn,
             "message": {"id": "msg-" + turn, "role": "assistant",
                         "content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn"}})
        fire("Stop", {})
        events.write("completed %s\n" % turn)
    for name in sorted(os.listdir(ctl)):
        if name.startswith("ask-") and name.endswith(".json"):
            n = int(name[4:-5])
            if n in asks:
                continue
            request = json.load(open(os.path.join(ctl, name)))
            quiet = request.pop("quiet", False)
            if not quiet:
                log({"type": "assistant", "uuid": "t-%d" % n, "promptId": turn_id(),
                     "message": {"id": "msg-t-%d" % n, "role": "assistant", "content": [
                         {"type": "tool_use", "id": "toolu-%d" % n, "name": request["tool_name"],
                          "input": request["tool_input"]}], "stop_reason": "tool_use"}})
            payload = dict(request, hook_event_name="PermissionRequest", session_id=session)
            proc = subprocess.Popen(["sh", "-c", permission], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            proc.stdin.write(json.dumps(payload).encode())
            proc.stdin.close()
            asks[n] = {"proc": proc, "request": request, "done": False}
            events.write("asked %d\n" % n)
    for n, ask in asks.items():
        request = ask["request"]
        tool = {"tool_name": request["tool_name"], "tool_input": request["tool_input"]}
        for what in ("terminal-yes", "terminal-no", "kill", "stop"):
            path = os.path.join(ctl, "%s-%d" % (what, n))
            if not os.path.exists(path):
                continue
            os.remove(path)
            if what == "terminal-yes":
                fire("PostToolUse", dict(tool, tool_response={"stdout": "ok"}))
                tool_result(n, "ok", False)
                events.write("ran %d\n" % n)
            elif what == "terminal-no":
                tool_result(n, REJECTED, True)
                log({"type": "user", "uuid": "i-%d" % n, "promptId": turn_id(), "message": {
                    "role": "user", "content": [{"type": "text", "text": "[Request interrupted by user for tool use]"}]}})
                events.write("refused %d\n" % n)
            elif what == "kill":
                ask["proc"].kill()
            else:
                ask["proc"].send_signal(signal.SIGSTOP)
                events.write("stopped %d\n" % n)
        answered(n, ask)
end_hooks()
