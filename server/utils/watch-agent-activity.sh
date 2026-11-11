#!/usr/bin/env bash
# ==============================================================================
#  UNIFIED ANTIGRAVITY AGENT & SUBAGENT LIVE MONITOR (Zed IDE — Alt+4)
#  Single unified stream that watches in real time:
#    1. Main Agent conversation transcript.jsonl   -> labeled [AGENT    <id>]
#    2. Delegated Subagents (via invoke_subagent)  -> labeled [SUBAGENT <id>]
#    3. Inter-agent messages (send_message / handoffs)
#    4. Active background task logs (task-*.log)   -> labeled [AGENT/SUBAGENT <id>] [BG-LOG]
#
#  Usage:
#    watch-agent                  # Watch all active Agent & Subagent activity
#    watch-agent <conv-id>        # Watch a specific conversation/subagent ID
# ==============================================================================
set -u

BRAIN_DIR="${HOME}/.gemini/antigravity-cli/brain"
TARGET_ARG="${1:-all}"

# Ensure any previous zedCheck / watch-agent instance is terminated so lines never print twice
if [ -f /tmp/zedCheck.pid ]; then
    OLD_PID="$(cat /tmp/zedCheck.pid 2>/dev/null || true)"
    if [ -n "$OLD_PID" ] && [ "$OLD_PID" != "$$" ]; then
        kill "$OLD_PID" 2>/dev/null || true
    fi
fi

# Set terminal session title to zedCheck and record active session PID + TTY
printf "\033]0;zedCheck\007"
echo "$$" > /tmp/zedCheck.pid
tty 2>/dev/null > /tmp/zedCheck.tty || true

PYTHON_BIN="$(command -v python3 || echo /usr/bin/python3)"
exec -a zedCheck "$PYTHON_BIN" - "$BRAIN_DIR" "$TARGET_ARG" "zedCheck" <<'PY'
import sys, os, glob, json, time, re, shutil, textwrap, subprocess
from datetime import datetime

# Terminate any other duplicate zedCheck / antigravity-cli/brain watcher processes
my_pid = os.getpid()
try:
    ps_lines = subprocess.check_output(["ps", "-eo", "pid,args"], text=True).splitlines()
    for pl in ps_lines:
        parts = pl.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            pid_val = int(parts[0])
            if pid_val != my_pid and "antigravity-cli/brain" in parts[1] and "zedCheck" in parts[1]:
                try:
                    os.kill(pid_val, 15)
                except Exception:
                    pass
except Exception:
    pass

brain_dir = sys.argv[1]
target_arg = sys.argv[2] if len(sys.argv) > 2 else "all"
target_conv = target_arg if (target_arg not in ("all", "--subagents-only") and not target_arg.startswith("-")) else None

C_RESET  = "\033[0m"
C_BOLD   = "\033[1m"
C_DIM    = "\033[2m"
C_CYAN   = "\033[36m"
C_GREEN  = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE   = "\033[34m"
C_MAG    = "\033[35m"
C_RED    = "\033[31m"

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07")

def get_term_cols():
    for fd in (1, 0, 2):
        try:
            c = os.get_terminal_size(fd).columns
            if c and c > 20:
                return c
        except Exception:
            pass
    return shutil.get_terminal_size((100, 24)).columns

def rule_line(ch="-"):
    cols = get_term_cols()
    return ch * max(40, min(92, cols - 2))

def ts():
    return datetime.now().strftime("%H:%M:%S")

def all_transcripts():
    files = glob.glob(os.path.join(brain_dir, "*", ".system_generated", "logs", "transcript.jsonl"))
    files.sort(key=os.path.getmtime, reverse=True)
    return files

print("\033[2J\033[H\033]0;zedCheck\007", end="", flush=True)
print(rule_line("="), flush=True)
try:
    with open("/tmp/zedCheck.pid", "w", encoding="utf-8") as pf:
        pf.write(str(os.getpid()))
except Exception:
    pass
print(f"{C_BOLD}{C_CYAN}  ANTIGRAVITY UNIFIED AGENT & SUBAGENT LIVE MONITOR [Session: zedCheck]{C_RESET}", flush=True)
print(f"  Badges: {C_BOLD}{C_CYAN}[AGENT]{C_RESET} = Main Agent | {C_BOLD}{C_MAG}[SUBAGENT]{C_RESET} = Delegated Subagent", flush=True)
print(rule_line("="), flush=True)

t_files = all_transcripts()
if not t_files:
    print(f"{C_YELLOW}  [STANDBY] Waiting for first Antigravity conversation in {brain_dir}...{C_RESET}", flush=True)
    while not t_files:
        time.sleep(3.0)
        t_files = all_transcripts()
    print(f"{C_GREEN}  [CONNECTED] Detected active Antigravity conversation — streaming live activity...{C_RESET}", flush=True)

# Map of conv_id -> metadata: {"role": str, "is_subagent": bool, "parent": str|None}
conv_meta = {}
# Map of (conv_id, step_index) -> (status, line_len)
seen_steps = {}
# Map of (conv_id, step_index) -> set of already-printed sub-parts ("input", "thinking", ("tool", i), "content", "bgtask")
seen_parts = {}
# Map of task_log_path -> byte_offset
task_offsets = {}

def discover_subagents_from_transcript(t_path, parent_id):
    """Scan a transcript for invoke_subagent calls and tool results to label child conversations."""
    pending_roles = []
    try:
        with open(t_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                for tc in (obj.get("tool_calls") or []):
                    tname = tc.get("name") or tc.get("tool_name") or ""
                    if tname == "invoke_subagent":
                        args = tc.get("arguments") or tc.get("args") or {}
                        if isinstance(args, str):
                            try:
                                args = json.loads(args)
                            except Exception:
                                args = {}
                        role = args.get("Role") or args.get("TypeName") or "Subagent"
                        pending_roles.append(role)
                content = obj.get("content") or ""
                if pending_roles and ("conversationId" in content or "Subagent" in content or "subagent" in content):
                    for m in UUID_RE.findall(content):
                        if m != parent_id and m not in conv_meta:
                            role_label = pending_roles.pop(0)
                            conv_meta[m] = {
                                "role": role_label,
                                "is_subagent": True,
                                "parent": parent_id,
                            }
                            if not pending_roles:
                                break
    except Exception:
        pass

primary_t = t_files[0]
primary_conv_dir = os.path.dirname(os.path.dirname(os.path.dirname(primary_t)))
primary_id = os.path.basename(primary_conv_dir)

if target_conv:
    primary_id = target_conv
    conv_meta[primary_id] = {"role": "Agent", "is_subagent": False, "parent": None}
else:
    conv_meta[primary_id] = {"role": "Agent", "is_subagent": False, "parent": None}

# Scan recent transcripts to link parent <-> subagent relationships
for tf in t_files[:12]:
    cid = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(tf))))
    discover_subagents_from_transcript(tf, cid)

print(f"  Active Agent : {C_BOLD}{C_CYAN}{primary_id[:18]}{C_RESET}", flush=True)
sub_list = [f"{cid[:8]} ({m['role']})" for cid, m in conv_meta.items() if m.get("is_subagent") and m.get("parent") == primary_id]
if sub_list:
    print(f"  Subagents    : {C_MAG}{', '.join(sub_list[:3])}{C_RESET}", flush=True)
else:
    print(f"  Subagents    : {C_DIM}None yet (auto-attaches on invoke_subagent){C_RESET}", flush=True)
print(rule_line("-"), flush=True)

def visual_len(s):
    plain = ANSI_RE.sub("", s or "")
    w = 0
    for ch in plain:
        cp = ord(ch)
        if cp in (0xFE0F, 0x200D):
            continue
        w += 2 if cp > 0x1F000 or cp in (0x2699, 0x2705, 0x23F3, 0x23F8) else 1
    return w

def badge_for(conv_id, compact=False):
    meta = conv_meta.get(conv_id, {})
    if compact:
        short = conv_id[:4]
        if meta.get("is_subagent"):
            return f"{C_BOLD}{C_MAG}[SUB {short}]{C_RESET}"
        return f"{C_BOLD}{C_CYAN}[AGY {short}]{C_RESET}"
    short = conv_id[:8]
    if meta.get("is_subagent"):
        return f"{C_BOLD}{C_MAG}[SUBAGENT {short}]{C_RESET}"
    return f"{C_BOLD}{C_CYAN}[AGENT    {short}]{C_RESET}"

def make_prefix(conv_id, idx, color, icon_label_wide, icon_label_compact):
    cols = get_term_cols()
    label = (icon_label_compact if cols < 85 else icon_label_wide).strip()
    b = badge_for(conv_id, compact=(cols < 85))
    return f"[{ts()}] {b} [S{idx}] {color}{label}{C_RESET}:"

def print_wrapped(prefix, msg_text, color_cont=""):
    """
    Print `prefix` header on its own line, then print `msg_text` starting on a new line
    from the left margin (2-space indent) wrapped across the full terminal width (`cols - 4`),
    so messages never start from the middle of the terminal or split into two columns.
    """
    cols = get_term_cols()
    indent_str = "  "
    avail = max(24, cols - len(indent_str) - 2)

    print(prefix, flush=True)

    # Normalize message into single-line clean text and cap overly long multi-paragraph dumps
    clean_text = " ".join(ln.strip() for ln in (msg_text or "").splitlines() if ln.strip())
    if len(clean_text) > 320:
        clean_text = clean_text[:317] + "..."
    if not clean_text:
        return

    wrapped = textwrap.wrap(clean_text, width=avail, break_long_words=True, break_on_hyphens=False)
    if not wrapped:
        wrapped = [clean_text[:avail]]
    for line_part in wrapped:
        print(f"{indent_str}{color_cont}{line_part}{C_RESET if color_cont else ''}", flush=True)

def format_step(conv_id, obj):
    meta = conv_meta.get(conv_id, {})
    is_sub = meta.get("is_subagent", False)
    role_prefix = f"[{meta.get('role', 'Subagent')}] " if is_sub and meta.get("role") else ""

    idx = obj.get("step_index", "?")
    stype = obj.get("type", "")
    source = obj.get("source", "")
    content = (obj.get("content") or "").strip()
    thinking = (obj.get("thinking") or "").strip()
    tcalls = obj.get("tool_calls") or []
    parts_done = seen_parts.setdefault((conv_id, idx), set())

    if stype in ("USER_INPUT", "SYSTEM_MESSAGE"):
        if "input" in parts_done:
            return
        parts_done.add("input")
        if "<SYSTEM_MESSAGE>" in content and "Task id" in content:
            prefix = make_prefix(conv_id, idx, f"{C_BOLD}{C_GREEN}", "🔔 BG TASK DONE    ", "🔔 BG DONE ")
            print_wrapped(prefix, "Background command finished -> resumed")
        elif "subagent" in content.lower() or "conversationId" in content:
            first = content.replace("<SYSTEM_MESSAGE>", "").replace("</SYSTEM_MESSAGE>", "").strip().splitlines()[0] if content else ""
            prefix = make_prefix(conv_id, idx, f"{C_BOLD}{C_MAG}", "🤝 SUBAGENT MSG    ", "🤝 SUB MSG ")
            print_wrapped(prefix, first)
        else:
            clean = content.split("<ADDITIONAL_METADATA>")[0].replace("<USER_REQUEST>", "").replace("</USER_REQUEST>", "").strip()
            clean_lines = [ln.strip() for ln in clean.splitlines() if ln.strip()]
            user_msg = " ".join(clean_lines) if clean_lines else ""
            lbl_w = "🎯 SUBAGENT PROMPT " if is_sub else "👤 USER INPUT      "
            lbl_c = "🎯 PROMPT  " if is_sub else "👤 INPUT   "
            prefix = make_prefix(conv_id, idx, f"{C_BOLD}{C_BLUE}", lbl_w, lbl_c)
            print_wrapped(prefix, f"{role_prefix}{user_msg}")

    elif stype == "PLANNER_RESPONSE":
        if thinking and "thinking" not in parts_done:
            parts_done.add("thinking")
            first_t = " ".join(ln.strip() for ln in thinking.splitlines() if ln.strip())
            prefix = make_prefix(conv_id, idx, C_MAG, "🧠 THINKING        ", "🧠 THINK   ")
            print_wrapped(prefix, f"{role_prefix}{first_t}")
        for tc_i, tc in enumerate(tcalls):
            tc_key = f"tool_{tc_i}"
            if tc_key in parts_done:
                continue
            parts_done.add(tc_key)
            tname = tc.get("name") or tc.get("tool_name") or "tool"
            args = tc.get("arguments") or tc.get("args") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            if tname == "invoke_subagent":
                role = args.get("Role") or "Subagent"
                t_type = args.get("TypeName") or "self"
                prompt_preview = " ".join(ln.strip() for ln in (args.get("Prompt") or "").strip().splitlines() if ln.strip())
                prefix = make_prefix(conv_id, idx, f"{C_BOLD}{C_MAG}", "🚀 SPAWN SUBAGENT  ", "🚀 SPAWN   ")
                print_wrapped(prefix, f"{role} (type={t_type}) — {prompt_preview}")
            elif tname == "send_message":
                rcpt = (args.get("Recipient") or "")[:8]
                msg = " ".join(ln.strip() for ln in (args.get("Message") or "").splitlines() if ln.strip())
                prefix = make_prefix(conv_id, idx, C_MAG, "📨 SEND MESSAGE    ", "📨 MSG     ")
                print_wrapped(prefix, f"-> {rcpt} ({msg})")
            else:
                summary = args.get("toolSummary") or args.get("Path") or args.get("Action") or args.get("query") or ""
                prefix = make_prefix(conv_id, idx, C_YELLOW, "⚙️  TOOL CALL       ", "⚙️  TOOL    ")
                tool_text = f'{tname} ("{summary}")' if summary else f'{tname} ()'
                print_wrapped(prefix, tool_text)
        if content and "content" not in parts_done:
            parts_done.add("content")
            first_c = content.splitlines()[0]
            lbl_w = "🏁 SUBAGENT DONE   " if is_sub else "✅ AGENT REPLY     "
            lbl_c = "🏁 SUB DONE" if is_sub else "✅ REPLY   "
            prefix = make_prefix(conv_id, idx, C_GREEN, lbl_w, lbl_c)
            print_wrapped(prefix, f"{role_prefix}{first_c}")
            if not is_sub:
                idle_pfx = make_prefix(conv_id, idx, f"{C_BOLD}{C_CYAN}", "⏸️  STATE           ", "⏸️  STATE   ")
                print_wrapped(idle_pfx, "IDLE — Waiting for user input")
            print(rule_line("-"), flush=True)

    elif "TOOL" in stype or source == "TOOL" or stype == "GENERIC":
        if "running as a background task" in content and "bgtask" not in parts_done:
            parts_done.add("bgtask")
            prefix = make_prefix(conv_id, idx, C_YELLOW, "⏳ BG TASK STARTED ", "⏳ BG START")
            print_wrapped(prefix, "Streaming live log lines below...")

# Seed initial steps from primary conversation (last 5 steps) and any known subagents
initial_convs = [primary_id] + [cid for cid, m in conv_meta.items() if cid != primary_id and m.get("parent") == primary_id]
for cid in initial_convs:
    tp = os.path.join(brain_dir, cid, ".system_generated", "logs", "transcript.jsonl")
    if not os.path.exists(tp):
        continue
    try:
        with open(tp, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        for l in lines[:-5]:
            try:
                o = json.loads(l)
                sidx = o.get("step_index")
                seen_steps[(cid, sidx)] = (o.get("status"), len(l))
                seen_parts[(cid, sidx)] = {"input", "thinking", "content", "bgtask"} | {f"tool_{i}" for i in range(len(o.get("tool_calls") or []))}
            except Exception:
                pass
        for l in lines[-5:]:
            try:
                o = json.loads(l)
                sidx = o.get("step_index")
                seen_steps[(cid, sidx)] = (o.get("status"), len(l))
                format_step(cid, o)
            except Exception:
                pass
    except Exception:
        pass
    # Seed existing task logs to end of file so we only stream new lines
    for tl in glob.glob(os.path.join(brain_dir, cid, ".system_generated", "tasks", "task-*.log")):
        try:
            task_offsets[tl] = os.path.getsize(tl)
        except Exception:
            pass

startup_mtime = time.time()

while True:
    try:
        current_files = all_transcripts()
        # First pass: discover any newly invoked subagents across active transcripts
        for tp in current_files[:8]:
            cdir = os.path.dirname(os.path.dirname(os.path.dirname(tp)))
            cid = os.path.basename(cdir)
            discover_subagents_from_transcript(tp, cid)

        # Second pass: stream new steps and background task logs
        for tp in current_files[:8]:
            try:
                mtime = os.path.getmtime(tp)
            except Exception:
                continue
            cdir = os.path.dirname(os.path.dirname(os.path.dirname(tp)))
            cid = os.path.basename(cdir)
            if target_conv and cid != target_conv:
                continue
            if cid not in conv_meta and mtime < startup_mtime - 5:
                continue

            if cid not in conv_meta:
                # Not registered via invoke_subagent -> new top-level AGENT session started in Zed
                conv_meta[cid] = {"role": "Agent", "is_subagent": False, "parent": None}
                print(f"\n  [{ts()}] {C_BOLD}{C_CYAN}[AGENT    {cid[:8]}]{C_RESET} 🔗 Attached to new main Agent session: {cid}", flush=True)

            try:
                with open(tp, "r", encoding="utf-8", errors="replace") as f:
                    for l in f:
                        try:
                            o = json.loads(l)
                            sidx = o.get("step_index")
                            key = (o.get("status"), len(l))
                            if seen_steps.get((cid, sidx)) != key:
                                seen_steps[(cid, sidx)] = key
                                format_step(cid, o)
                        except Exception:
                            pass
            except Exception:
                pass

            # Stream any active background task logs for this conversation/subagent
            for tl in glob.glob(os.path.join(cdir, ".system_generated", "tasks", "task-*.log")):
                try:
                    sz = os.path.getsize(tl)
                    prev = task_offsets.get(tl, 0)
                    if tl not in task_offsets:
                        task_offsets[tl] = 0
                        prev = 0
                        prefix_open = make_prefix(cid, "BG", C_YELLOW, "📂 STREAMING LOG   ", "📂 BG LOG  ")
                        print_wrapped(prefix_open, os.path.basename(tl))
                    if sz > prev:
                        with open(tl, "r", encoding="utf-8", errors="replace") as tf:
                            tf.seek(prev)
                            chunk = tf.read()
                            task_offsets[tl] = tf.tell()
                        for tline in chunk.splitlines():
                            tline_s = tline.strip()
                            if tline_s:
                                prefix = make_prefix(cid, "BG", C_DIM, "📄 TASK OUTPUT     ", "📄 OUTPUT  ")
                                print_wrapped(prefix, tline_s)
                except Exception:
                    pass

        time.sleep(0.4)
    except KeyboardInterrupt:
        print(f"\n{C_CYAN}Stopped Unified Agent & Subagent Monitor.{C_RESET}", flush=True)
        break
PY
