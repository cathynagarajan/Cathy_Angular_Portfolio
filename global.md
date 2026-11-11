# Global Knowledge Graph Installations (`global.md`)

<!-- GLOBAL_KG_INSTALLATIONS: ["/home/sanjay.linux/container/kubernetes", "/home/krithika/workspace/Cathy_Angular_Portfolio"] -->

This file maintains all repository/project locations where the `knowledge_graph/` folder and [`query_kg.py`](knowledge_graph/query_kg.py) are installed.

- **Primary (Master) Location**: `/home/sanjay/container/kubernetes`
- **Total Registered Installations**: `2`

---

## 1. Installed Knowledge Graph Locations

| # | Target Folder (Repository Root) | Knowledge Graph Folder | CLI Script | Root Wrapper | Role | Status |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `/home/sanjay.linux/container/kubernetes` | `/home/sanjay.linux/container/kubernetes/knowledge_graph` | `/home/sanjay.linux/container/kubernetes/knowledge_graph/query_kg.py` | `/home/sanjay.linux/container/kubernetes/query_kg.py` | Primary (Master) | Pending Sync |
| 2 | `/home/krithika/workspace/Cathy_Angular_Portfolio` | `/home/krithika/workspace/Cathy_Angular_Portfolio/knowledge_graph` | `/home/krithika/workspace/Cathy_Angular_Portfolio/knowledge_graph/query_kg.py` | `/home/krithika/workspace/Cathy_Angular_Portfolio/query_kg.py` | Installed Target | Active |

---

## 2. Installing `query_kg.py` to a New Folder (`/install <folder>`)

To install the Knowledge Graph system onto a new target project folder, run:
```bash
python3 /home/sanjay/container/kubernetes/knowledge_graph/query_kg.py /install /path/to/target_folder
```
This automatically:
1. Creates `/path/to/target_folder/knowledge_graph/` and `/path/to/target_folder/knowledge_graph/Files/.gitkeep`.
2. Installs `knowledge_graph/query_kg.py` and the root wrapper `query_kg.py` into `/path/to/target_folder`.
3. Builds the initial Knowledge Graph (`knowledge_graph.json`, `knowledge_graph.db`, `KNOWLEDGE_GRAPH.md`, `knowledge_graph.html`, and `repo.md`) in the target folder.
4. Registers `/path/to/target_folder` in `global.md` and synchronizes `global.md` across all registered installations.

---

## 3. Automatic Global Synchronization Rule

> **RULE: Anytime an update is made to `query_kg.py`, all folders listed in `global.md` MUST be updated.**

- Running `python3 /home/sanjay/container/kubernetes/knowledge_graph/query_kg.py --update` (or `--sync-global`) automatically checks the SHA-256 of `query_kg.py` against every installation in `global.md`, propagates the updated `query_kg.py` and `global.md`, and refreshes each target folder's Knowledge Graph.
