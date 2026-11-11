# Repository Top-Level Parent Folders Processed by Knowledge Graph (`repo.md`)

This file maintains the authoritative inventory of all **top-level parent folders** in `/home/krithika/workspace/Cathy_Angular_Portfolio` that are scanned, parsed, and indexed by [`knowledge_graph/query_kg.py`](knowledge_graph/query_kg.py).

- **Repository Root**: `/home/krithika/workspace/Cathy_Angular_Portfolio`
- **Top-Level Parent Folders Processed**: `0` (plus repository root `.` files)
- **Total Indexed Files**: `24`
- **Total Knowledge Graph Nodes**: `262`

---

## 1. Top-Level Parent Folders Processed by Knowledge Graph

| # | Top-Level Parent Folder | Absolute Path | Indexed Files | Extracted KG Nodes | Key Subfolders | Description & Scope |
| :---: | :--- | :--- | :---: | :---: | :--- | :--- |

### Repository Root (`.` Top-Level Files)

| Location | Absolute Path | Indexed Root Files | Extracted KG Nodes | Description |
| :--- | :--- | :---: | :---: | :--- |
| `.` (Root Files) | `/home/krithika/workspace/Cathy_Angular_Portfolio/` | `24` | `262` | Repository root configuration, rules, and entrypoints (`network_config.json`, `rules.md`, `resources.md`, `repo.md`, `global.md`, `CLAUDE.md`, `README.md`, `query_kg.py`) |

---

## 2. Entity Breakdown by Top-Level Parent Folder

| Top-Level Parent Folder | Extracted Entity Types (`type: count`) |
| :--- | :--- |
| `.` (Root Files) | `config_file`: 2, `document_file`: 14, `document_section`: 78, `image_document`: 8, `topic_entity`: 160 |

---

## 3. Excluded Top-Level & Generated Directories

The following directories are intentionally excluded from Knowledge Graph source indexing to avoid recursion, virtual-environment bloat, or binary cache scanning:

| Excluded Directory | Reason |
| :--- | :--- |
| `.git/` | Git version control internals |
| `.mypy_cache/` | Mypy type-checking cache |
| `.pytest_cache/` | Pytest execution cache |
| `.venv/` | Python virtual environment |
| `__pycache__/` | Compiled Python bytecode cache |
| `jvm/` | Extracted SAPJVM runtime binary archive |
| `knowledge-graph/` | Legacy Knowledge Graph directory alias |
| `management_venv/` | Python virtual environment for cluster-management |
| `node_modules/` | Node.js dependency directory |
| `pgvector_repo/` | External cloned pgvector source repository |
| `retire/` | Archived/retired node scripts preserved for reference |
| `venv/` | Python virtual environment |
| `wheels/` | Pre-built Python binary wheel archive |

---

## 4. Synchronization Rule

Whenever a top-level folder is added, renamed, or removed in `/home/krithika/workspace/Cathy_Angular_Portfolio`, running:
```bash
python3 /home/krithika/workspace/Cathy_Angular_Portfolio/knowledge_graph/query_kg.py --update
```
automatically updates `repo.md` alongside the Knowledge Graph stores.
