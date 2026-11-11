# Project Rules & AI Engineering Standards (`/home/krithika/workspace/Cathy_Angular_Portfolio`)

These rules govern all development, documentation, Knowledge Graph / GraphRAG indexing, PII guardrails, and multi-agent collaboration within the `Cathy_Angular_Portfolio` Single-Repository AI Workspace (`/home/krithika/workspace/Cathy_Angular_Portfolio`).

- **Workspace Mode**: Single-Repository Mode (`.kg_project_config.json` -> `"single_repo_mode": true`)
- **Git Remote (`origin`)**: `(configure via `git remote add origin <url>`)` (default branch: `main`)
- **MCP GraphRAG Middleware**: `http://192.168.1.181:8000/mcp` (5-node HA pool)
- **PostgreSQL `pgvector` Table**: `kg_vectors_cathy_angular_portfolio` (`192.168.1.155:30432`)

---

## 1. Mandatory Pre-Query, Subagent & Post-Update Rules (CRITICAL)

### 1.0 `zedCheck` Terminal Session & `watch-agent` Pre-Query Rule (Zed IDE)
> **RULE: Every time a query is done in Zed, check if the terminal session `zedCheck` is active; if `zedCheck` is not active, start the `zedCheck` terminal session and start `watch-agent` (`/home/krithika/workspace/Cathy_Angular_Portfolio/server/utils/watch-agent-activity.sh`), and then continue with the Zed operations.**

- `ensure_zedcheck_session()` in `knowledge_graph/query_kg.py` runs automatically on every query and launches `server/utils/watch-agent-activity.sh` (or `.zed/watch-agent-activity.sh`).
- Configured in `.zed/tasks.json` as `"label": "zedCheck"` (`Alt+4`).

### 1.1 Pre-Flight Knowledge Graph & MCP GraphRAG Query Rule
> **RULE: Before modifying code or architecture, query the local Knowledge Graph and 2-Stage GPU GraphRAG (`MiniLM` + `GNN`) to retrieve minimal, token-pruned context.**

```bash
# Query 2-Stage GPU GraphRAG via MCP Middleware
python3 /home/krithika/workspace/Cathy_Angular_Portfolio/knowledge_graph/query_kg.py --mcp-query "<topic>"

# Search local SQLite/JSON Knowledge Graph (#1, #2, #3...)
python3 /home/krithika/workspace/Cathy_Angular_Portfolio/knowledge_graph/query_kg.py "<term>" /s
```

### 1.2 Multi-Subagent Parallel Task Coordination (`invoke_subagent`)
> **RULE: Whenever a user requirement spans multiple independent files, modules, or phases (e.g., Backend API + Frontend UI + CLI/Tests), the Lead Agent SHOULD split the work into parallel subagents (`invoke_subagent` with disjoint file ownership), coordinate their results, and run a single unified `--pre-commit-hook` and `--commit-push` at the end.**

- Assign strict, non-overlapping file ownership to each subagent.
- Subagents must NOT run `git commit` or `--commit-push` independently; the Lead Coordinator runs a single unified `--pre-commit-hook` and `--commit-push` after all subagents finish.

### 1.3 Single-Pass Pre-Commit Verification (`--pre-commit-hook`)
> **RULE: After completing code and documentation edits, run `--pre-commit-hook` ONCE (never chain `--update` and `--pre-commit-hook`).**

```bash
python3 /home/krithika/workspace/Cathy_Angular_Portfolio/knowledge_graph/query_kg.py --pre-commit-hook
```
This single idempotent pass automatically:
1. Synchronizes `man/` / `docs/` indexes (`repo.md`, `global.md`, `knowledge_graph.*`).
2. Delta-syncs AST/code vectors to PostgreSQL `pgvector` (`kg_vectors_cathy_angular_portfolio`).
3. Runs the Delta-Only UTF-8 Mojibake Audit & Fix (`--mojibake-fix`).
4. Runs the Delta-Only Security Vulnerability Scanner (`SEC001`–`SEC006`, `--vuln-scan`).

### 1.4 2-Stage PII & Secrets Redaction Guardrail (`--pii-scan`)
> **RULE: Never commit hardcoded credentials, API keys, private keys, or unredacted PII.**

```bash
python3 /home/krithika/workspace/Cathy_Angular_Portfolio/knowledge_graph/query_kg.py --pii-scan "<text>"
```

### 1.5 Single-Repository Git Commit & Push Workflow (`--commit-push`)
> **RULE: Prompt the user ONCE at the start of the conversation via `ask_question` to authorize committing and pushing to `origin/main`, and maintain that setting for the conversation.**

- In Single-Repository Mode, `--commit-push` runs a clean 3-step workflow:
  1. `[1/3] [GIT ADD]` — Stage all changes in `/home/krithika/workspace/Cathy_Angular_Portfolio`.
  2. `[2/3] [GIT COMMIT]` — Commit changes (verifying `.git/kg_precommit_verified`).
  3. `[3/3] [GIT PUSH]` — Push to `origin/main` (or commit locally with full KG/MCP/PII verification if no remote is configured yet).
- **Note**: Single-Repository projects NEVER execute the 5-node cluster SSH `git pull` or 5-node HA portal restart (those apply exclusively to the master cluster repository `/home/sanjay/container/kubernetes`).

### 1.6 Python-Only Code Edits Rule
- Perform all programmatic file edits using Python (`/usr/bin/python3`) or native IDE edit tools — never PowerShell.
