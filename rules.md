# Project Rules & AI Agent Operational Guidelines (`Cathy_Angular_Portfolio`)

## 1. Repository Scope & Single-Repo Isolation
- **Project Root**: `/home/krithika/workspace/Cathy_Angular_Portfolio`
- **Primary Developer**: `Krithika`
- **Git Remote (`origin`)**: `https://github.com/cathynagarajan/Cathy_Angular_Portfolio.git` (Branch: `main`)
- **PostgreSQL `pgvector` Table**: `kg_vectors_cathy_angular_portfolio` (`192.168.1.155:30432` / database `vectordb`)
- **Single-Repo Mode (`single_repo_mode: true`)**: This repository is an independent project workspace. It does **NOT** synchronize with the 5-node Kubernetes cluster infrastructure git loop (`tower`, `spark1`, `spark2`, `agx`, `nano`). All `git commit` and `git push` operations apply exclusively to this project's own Git remote.

---

## 2. Mandatory Pre-Task & Post-Task Knowledge Graph (`query_kg.py`) Workflow
1. **Query Knowledge Graph First**:
   - Before scanning the filesystem with `grep` or `find`, query the local Knowledge Graph or the `cluster-graphrag` MCP tool (`kg_rag_query` with `repo="cathy_angular_portfolio"`):
     ```bash
     python3 /home/krithika/workspace/Cathy_Angular_Portfolio/knowledge_graph/query_kg.py --search "<symbol_or_topic>"
     ```
2. **Pre-Commit Knowledge Graph & Documentation Sync**:
   - Before committing code changes, run:
     ```bash
     python3 /home/krithika/workspace/Cathy_Angular_Portfolio/knowledge_graph/query_kg.py --pre-commit-hook
     ```
   - This automatically rebuilds `knowledge_graph.json`, `knowledge_graph.db`, `KNOWLEDGE_GRAPH.md`, `knowledge_graph.html`, and `repo.md`, and incrementally syncs changed embeddings to `kg_vectors_cathy_angular_portfolio` via the 5-node GPU pool.
3. **Single-Repo Commit & Push**:
   - To commit and push changes to this project's Git remote (`origin main`):
     ```bash
     python3 /home/krithika/workspace/Cathy_Angular_Portfolio/knowledge_graph/query_kg.py --commit-push "Describe your change"
     ```

---

## 3. Multi-Subagent Parallel Coordination (`zedCheck` / `watch-agent-activity.sh`)
- **Parallel Subagent Execution**: When a task spans multiple independent files or subsystems (e.g., backend API + frontend UI + unit tests), decompose the work and invoke parallel subagents (`invoke_subagent`) with strict file-ownership boundaries so they never edit the same file simultaneously.
- **Live Subagent & Tool Telemetry (`zedCheck`)**:
  - Run the **`zedCheck`** task in Zed (`Ctrl+Shift+P` -> `task: spawn` -> `zedCheck`) or execute:
    ```bash
    bash /home/krithika/workspace/Cathy_Angular_Portfolio/server/utils/watch-agent-activity.sh
    ```
  - This displays a real-time split-screen dashboard of the main Antigravity (`agy`) agent, all active parallel subagents, and live MCP/GPU calls.

---

## 4. Shared 5-Node Cluster GPU Pool (`use-gpu`) & MCP Services
- **5-Node GPU Pool CLI (`/usr/local/bin/use-gpu`)**:
  - Check live GPU status: `use-gpu status`
  - Dispatch workloads to specific cluster GPUs: `use-gpu spark1 <cmd>`, `use-gpu spark2 <cmd>`, `use-gpu agx <cmd>`, `use-gpu mac <cmd>`, `use-gpu nano <cmd>`
- **Cluster GraphRAG MCP Server (`cluster-graphrag`)**:
  - Lazy-loaded tools in `~/.gemini/antigravity-cli/mcp/cluster-graphrag/`:
    - `kg_rag_query` (pass `repo: "cathy_angular_portfolio"`)
    - `kg_rag_upsert` (pass `repo: "cathy_angular_portfolio"`)
    - `kg_gpu_pool_status` (pass `repo: "cathy_angular_portfolio"`)
    - `kg_webhook_sync` (pass `repo: "cathy_angular_portfolio"`)
    - `kg_pii_guardrail_scan`
