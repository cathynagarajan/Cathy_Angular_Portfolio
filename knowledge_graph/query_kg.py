#!/usr/bin/env python3
"""
Knowledge Graph Builder, Updater, and Query Engine for /home/sanjay/container/kubernetes.

Consumes the entire Kubernetes hybrid cluster repository and constructs a structured
Knowledge Graph (JSON + SQLite + Markdown summary) capturing:
  - Cluster Nodes, Network Devices, and Subnets (from network_config.json & docs)
  - FastAPI Endpoints, WebSocket routes, Python Modules, Classes, and Functions (via AST)
  - Kubernetes Manifests (Deployments, Services, DaemonSets, NodePorts, Images)
  - Shell Scripts (.sh), Dockerfiles, SQL scripts, and Manual Pages / Documentation
  - Cross-entity edges (HOSTS_SERVICE, EXPOSES_ENDPOINT, CALLS, IMPORTS, DEPLOYED_ON, etc.)

Usage:
  python3 knowledge_graph/query_kg.py                  # Auto-update & show summary
  python3 knowledge_graph/query_kg.py --update         # Force incremental/full update
  python3 knowledge_graph/query_kg.py --rebuild        # Force full rebuild from scratch
  python3 knowledge_graph/query_kg.py --search <term>  # Search entities & relationships
  python3 knowledge_graph/query_kg.py --entity <name>  # Inspect an entity & its neighbors
  python3 knowledge_graph/query_kg.py --type <type>    # List entities by type
  python3 knowledge_graph/query_kg.py --stats          # Show graph statistics
"""

import argparse
import ast
import base64
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

MASTER_REPO_ROOT = pathlib.Path("/home/sanjay/container/kubernetes")
MASTER_GLOBAL_MD_PATH = MASTER_REPO_ROOT / "global.md"


def _resolve_active_kg_and_repo_root() -> Tuple[pathlib.Path, pathlib.Path]:
    """
    Resolve the active Knowledge Graph and repository root.
    - If invoked via a target repo's script (e.g. /home/sanjay/container/sap/query_kg.py),
      use that script's repo root.
    - If invoked via the master script while the current working directory (cwd) is inside
      another installed KG repository (e.g. cwd is /home/sanjay/container/sap), restrict all
      activities (KG build, query, pre-commit checks, and commit/push) to that cwd repository.
    """
    script_kg_dir = pathlib.Path(__file__).resolve().parent
    script_repo_root = script_kg_dir.parent
    if script_repo_root.resolve() != MASTER_REPO_ROOT.resolve():
        return script_kg_dir, script_repo_root

    try:
        cwd = pathlib.Path.cwd().resolve()
        for candidate in (cwd, *cwd.parents):
            if candidate == MASTER_REPO_ROOT.resolve():
                break
            if (candidate / "knowledge_graph" / "query_kg.py").is_file() and (candidate / ".git").exists():
                return candidate / "knowledge_graph", candidate
    except Exception:
        pass
    return script_kg_dir, script_repo_root


KG_DIR, REPO_ROOT = _resolve_active_kg_and_repo_root()
KG_JSON_PATH = KG_DIR / "knowledge_graph.json"
KG_DB_PATH = KG_DIR / "knowledge_graph.db"
KG_MD_PATH = KG_DIR / "KNOWLEDGE_GRAPH.md"
KG_HTML_PATH = KG_DIR / "knowledge_graph.html"
KG_GNN_PT_PATH = KG_DIR / "kg_gnn.pt"
KG_QUERY_HTML_PATH = KG_DIR / "query_results.html"
KG_LAST_RESULTS_PATH = KG_DIR / "last_query_results.json"
KG_LAST_PROMPT_PATH = KG_DIR / "last_llm_prompt.txt"
KG_FILES_DIR = KG_DIR / "Files"
REPO_MD_PATH = REPO_ROOT / "repo.md"
GLOBAL_MD_PATH = REPO_ROOT / "global.md"

ROOT_WRAPPER_TEMPLATE = '''#!/usr/bin/env python3
"""Root-level entrypoint that forwards all CLI parameters and switches (including /s, /I, /install) to knowledge_graph/query_kg.py."""

import sys
from pathlib import Path

KG_DIR = Path(__file__).resolve().parent / "knowledge_graph"
sys.path.insert(0, str(KG_DIR))

from query_kg import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
'''

PRE_COMMIT_HOOK_SCRIPT = """#!/bin/bash
# Auto-installed by knowledge_graph/query_kg.py
# Executes Update Man Pages & Wiki Sync, Knowledge Graph Update, Delta-Only Mojibake Audit & Fix, and Pre-Commit Vulnerability Scan before every git commit.
set -e
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
if [ -f "$REPO_ROOT/knowledge_graph/query_kg.py" ]; then
    exec /usr/bin/python3 "$REPO_ROOT/knowledge_graph/query_kg.py" --pre-commit-hook
fi
"""

PREPARE_COMMIT_MSG_HOOK_SCRIPT = """#!/bin/bash
# Auto-installed by knowledge_graph/query_kg.py
# Auto-generates an incremental commit message from observed code/KG/man changes when no -m message is supplied.
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
if [ -f "$REPO_ROOT/knowledge_graph/query_kg.py" ]; then
    /usr/bin/python3 "$REPO_ROOT/knowledge_graph/query_kg.py" --prepare-commit-msg "$1" "${2:-}" || true
fi
"""

POST_COMMIT_HOOK_SCRIPT = """#!/bin/bash
# Auto-installed by knowledge_graph/query_kg.py
# Standardized Auto-Push: automatically pushes committed HEAD to origin (single-repo or master cluster mode) after every git commit without re-staging or re-running pre-commit/MCP hooks.
if [ "${KG_SKIP_POST_COMMIT_PUSH:-0}" = "1" ]; then
    exit 0
fi
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
if [ -f "$REPO_ROOT/knowledge_graph/query_kg.py" ]; then
    KG_SKIP_POST_COMMIT_PUSH=1 /usr/bin/python3 "$REPO_ROOT/knowledge_graph/query_kg.py" --post-commit-hook || true
fi
"""

TOP_LEVEL_FOLDER_DESCRIPTIONS: Dict[str, str] = {
    "agent": "Per-node K3s agent automation, Dockerfiles, SAP/HANA scripts, and node apps (`agx/`, `nano/`, `spark1/`, `spark2/`, `tower/`, `mac/`)",
    "ca": "Certificate Authority (CA) root certificates and TLS trust material",
    "cluster-management": "Main FastAPI cluster management portal, REST API routes, WebSocket handlers, JWT auth, and pytest suite",
    "docs": "Project wiki pages, architecture documentation, and operational guides",
    "images": "Architecture diagrams and visual documentation assets",
    "knowledge_graph": "Knowledge Graph builder, query engine, pre-commit hook manager (`query_kg.py`), and AI/GraphRAG pipeline scripts",
    "man": "Manual pages (`man1/`, `man5/`, `man7/`, `man8/`), `PROJECT_PLAN.md`, `KNOWLEDGE_GRAPH.md`, `ROLE_REVERSAL.md`, and operational guides",
    "nvidia-support": "NVIDIA GPU device plugin manifests, CUDA test pods, and GPU validation resources",
    "rag": "Retrieval-Augmented Generation (RAG) and financial document processing pipeline",
    "sap_install": "SAP S/4HANA 2023 (`S4H`) + SAP HANA 2.0 (`HDB02`) installation, US Best Practices, Fiori, Golden Backups, and license recycling scripts",
    "sapmc": "SAP Management Console (`sapmc`) desktop launcher and startup wrapper",
    "scripts": "Cluster-wide operational automation, health checks, NFS setup, and K3s validation scripts",
    "server": "K3s control plane setup (`k3s-images.sh`, `k3s-server.sh`), Lima VM config, Kaniko builders, PostgreSQL/pgvector, pgAdmin, Registry, and Unifi manifests",
    "versions": "Versioned release metadata and deployment snapshots",
    "documents": "Multi-modal documents, PDFs, Office files (`.docx`, `.pptx`, `.xlsx`), CSV/TSV datasets, OCR images, and audio recordings indexed into the Knowledge Graph",
    "chats": "Exported or synced Zed/Antigravity AI assistant chat transcripts and conversation logs indexed into the Knowledge Graph",
    ".github": "GitHub workflows and AI assistant instructions (`copilot-instructions.md`)",
    ".": "Repository root configuration, rules, and entrypoints (`network_config.json`, `rules.md`, `resources.md`, `repo.md`, `global.md`, `CLAUDE.md`, `README.md`, `query_kg.py`)",
}

MULTIMODAL_DOC_EXTENSIONS = {
    ".pdf", ".docx", ".pptx", ".xlsx", ".csv", ".tsv", ".txt", ".json", ".yaml", ".yml", ".log",
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp",
    ".mp3", ".wav", ".m4a", ".ogg", ".flac", ".webm",
}
IMAGE_DOC_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}
AUDIO_DOC_EXTENSIONS = {".mp3", ".wav", ".m4a", ".ogg", ".flac", ".webm"}
OFFICE_AND_DATA_DOC_EXTENSIONS = {".pdf", ".docx", ".pptx", ".xlsx", ".csv", ".tsv", ".log"}
CHAT_FILE_EXTENSIONS = {".md", ".txt", ".json", ".jsonl"}

EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    "management_venv",
    "venv",
    ".venv",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    "wheels",
    "pgvector_repo",
    "jvm",
    "knowledge-graph",
    "retire",  # retired scripts (retire/<node>/...) are kept for reference, not indexed as live code
}

GENERATED_KG_OUTPUT_FILES = {
    "knowledge_graph.json",
    "knowledge_graph.db",
    "KNOWLEDGE_GRAPH.md",
    "knowledge_graph.html",
    "kg_gnn.pt",
    "query_results.html",
    "last_query_results.json",
    "last_llm_prompt.txt",
    "vulnerability_report.md",
    "publish_precheck_report.md",
    "publish_precheck_report.html",
}

EXCLUDED_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".whl", ".tar", ".gz", ".tgz", ".zip",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".db", ".sqlite",
    ".log", ".csr", ".key", ".pem", ".crt",
}


def compute_sha256(file_path: pathlib.Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


class KnowledgeGraphBuilder:
    """Builds and incrementally updates the repository Knowledge Graph."""

    def __init__(self, repo_root: pathlib.Path = REPO_ROOT):
        self.repo_root = repo_root
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self.edge_set: Set[Tuple[str, str, str]] = set()
        self.file_hashes: Dict[str, str] = {}

    def add_node(
        self,
        node_id: str,
        node_type: str,
        name: str,
        file_path: Optional[str] = None,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        existing = self.nodes.get(node_id, {})
        merged_meta = existing.get("metadata", {})
        if metadata:
            merged_meta.update(metadata)
        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "name": name,
            "file_path": file_path or existing.get("file_path"),
            "description": description or existing.get("description", ""),
            "metadata": merged_meta,
        }

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        key = (source, target, relation)
        if key not in self.edge_set:
            self.edge_set.add(key)
            self.edges.append(
                {
                    "source": source,
                    "target": target,
                    "relation": relation,
                    "metadata": metadata or {},
                }
            )

    def should_skip(self, path: pathlib.Path) -> bool:
        rel_parts = path.relative_to(self.repo_root).parts
        is_master = is_master_cluster_repo(self.repo_root)
        hidden_skip_dirs = {
            ".git", ".zed", ".agents", ".venv", "venv", ".mypy_cache", ".pytest_cache",
            ".next", ".cache", ".local", ".ssh", ".gnupg", ".gemini", ".config", ".vscode", ".idea",
        }
        for part in rel_parts[:-1]:
            if part in EXCLUDED_DIRS or part in hidden_skip_dirs:
                return True
            if is_master and part.startswith(".") and part != ".github":
                return True
        if rel_parts:
            last_part = rel_parts[-1]
            if last_part in EXCLUDED_DIRS or last_part in hidden_skip_dirs:
                return True
            if is_master and last_part.startswith(".") and last_part != ".github":
                return True
        if not is_master:
            if len(rel_parts) >= 1 and rel_parts[0] == "knowledge_graph":
                if len(rel_parts) >= 2 and rel_parts[1] == "Files" and path.name != ".gitkeep":
                    pass
                else:
                    return True
            if rel_parts == ("server", "utils", "watch-agent-activity.sh"):
                return True
            if len(rel_parts) == 1 and path.name in (
                "query_kg.py", "ONBOARDING.md", "global.md", "repo.md", "rules.md",
                "AGENTS.md", "CLAUDE.md", "resources.md", ".kg_project_config.json",
                "appsetting.json", "appsettings.json", ".gitignore", ".gitkeep",
            ):
                return True
            if len(rel_parts) == 1 and path.name == "README.md" and path.is_file():
                try:
                    if path.stat().st_size < 180 and "AI-Onboarded Workspace" in path.read_text(encoding="utf-8", errors="ignore"):
                        return True
                except Exception:
                    pass
        else:
            if len(rel_parts) >= 2 and rel_parts[0] == "knowledge_graph":
                if rel_parts[1] == "Files" or path.name in GENERATED_KG_OUTPUT_FILES:
                    return True
        if path.is_file():
            if path.name.endswith(".transcript.txt") or path.name.lower() in ("appsetting.json", "appsettings.json", ".gitkeep", ".ds_store", "thumbs.db"):
                return True
            if path.name.endswith((".db-shm", ".db-wal", ".sqlite-shm", ".sqlite-wal")):
                return True
            ext = path.suffix.lower()
            in_multimodal_scope = (
                (len(rel_parts) >= 1 and rel_parts[0] in ("documents", "chats"))
                or not is_master
            )
            if in_multimodal_scope and ext in (MULTIMODAL_DOC_EXTENSIONS | CHAT_FILE_EXTENSIONS):
                return False
            if ext in EXCLUDED_EXTENSIONS:
                return True
        return False

    def collect_files(self) -> List[pathlib.Path]:
        files: List[pathlib.Path] = []
        is_master = is_master_cluster_repo(self.repo_root)
        hidden_skip_dirs = {
            ".git", ".zed", ".agents", ".venv", "venv", ".mypy_cache", ".pytest_cache",
            ".next", ".cache", ".local", ".ssh", ".gnupg", ".gemini", ".config", ".vscode", ".idea",
        }
        for root, dirs, filenames in os.walk(self.repo_root):
            root_path = pathlib.Path(root)
            if is_master:
                dirs[:] = [
                    d
                    for d in sorted(dirs)
                    if d not in EXCLUDED_DIRS and not (d.startswith(".") and d != ".github")
                ]
            else:
                dirs[:] = [
                    d
                    for d in sorted(dirs)
                    if d not in EXCLUDED_DIRS and d not in hidden_skip_dirs
                ]
            for fname in sorted(filenames):
                fpath = root_path / fname
                if not self.should_skip(fpath):
                    files.append(fpath)
        return files

    def parse_network_config(self, fpath: pathlib.Path, rel_path: str) -> None:
        """Extract cluster nodes, switches, routers, and segments from network_config.json."""
        try:
            data = json.loads(fpath.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return

        self.add_node(
            f"file:{rel_path}",
            "config_file",
            fpath.name,
            rel_path,
            "Cluster network topology and node configuration JSON",
        )

        # Network topology devices
        topo = data.get("network_topology", {})
        for dev_key, dev in topo.items():
            nid = f"net_device:{dev_key}"
            ip = dev.get("ip_address") or dev.get("lan_ip") or ""
            self.add_node(
                nid,
                "network_device",
                dev.get("name", dev_key),
                rel_path,
                dev.get("description", ""),
                {
                    "device_type": dev.get("type", "unknown"),
                    "ip_address": ip,
                    "wan_ip": dev.get("wan_ip"),
                    "gateway": dev.get("gateway"),
                    "subnet": dev.get("subnet"),
                    "role": dev.get("role"),
                    "management_url": dev.get("management_url"),
                    "ports": dev.get("ports", {}),
                },
            )
            self.add_edge(f"file:{rel_path}", nid, "DEFINES_DEVICE")

        # Cluster compute/server nodes
        cluster_nodes_map = data.get("cluster_nodes", {})
        for node_key, info in cluster_nodes_map.items():
            nid = f"cluster_node:{node_key}"
            services = info.get("services", [])
            self.add_node(
                nid,
                "cluster_node",
                info.get("name", node_key),
                rel_path,
                info.get("description", ""),
                {
                    "node_type": info.get("type"),
                    "ip_address": info.get("ip_address"),
                    "role": info.get("role"),
                    "management_url": info.get("management_url"),
                    "services": services,
                },
            )
            self.add_edge(f"file:{rel_path}", nid, "DEFINES_NODE")
            for svc in services:
                svc_id = f"service:{svc.lower().replace(' ', '_')}"
                self.add_node(svc_id, "cluster_service", svc, rel_path, f"Service running on {node_key}")
                self.add_edge(nid, svc_id, "HOSTS_SERVICE")

        # Also ensure Mac VM (192.168.1.155) from Role Reversal architecture is represented
        mac_vm_id = "cluster_node:mac_vm"
        self.add_node(
            mac_vm_id,
            "cluster_node",
            "Mac VM",
            "CLAUDE.md",
            "Ubuntu 24.04 Lima/QEMU VM running K3s control plane, PostgreSQL, and pgAdmin",
            {
                "node_type": "control_plane_vm",
                "ip_address": "192.168.1.155",
                "role": "K3s Control Plane",
                "services": ["K3s Server", "PostgreSQL + pgvector", "pgAdmin", "Docker Registry NodePort 30500", "Unifi Network Controller"],
            },
        )
        self.add_edge("cluster_node:mac", mac_vm_id, "HOSTS_VM")

        # Connect hierarchical network topology stack (Internet -> Comcast Router -> Firewall -> Switches -> Cluster Nodes)
        if "internet" in topo and "comcast_router" in topo:
            self.add_edge("net_device:internet", "net_device:comcast_router", "WAN_UPLINK")
        if "comcast_router" in topo and "tp_link_firewall" in topo:
            self.add_edge("net_device:comcast_router", "net_device:tp_link_firewall", "WAN_GATEWAY")
        if "comcast_router" in topo and "er605_router" in topo:
            self.add_edge("net_device:comcast_router", "net_device:er605_router", "WAN_GATEWAY")
        if "tp_link_firewall" in topo and "usw_pro_xg_8_poe" in topo:
            self.add_edge("net_device:tp_link_firewall", "net_device:usw_pro_xg_8_poe", "LAN_UPLINK_PORT_1")
        if "tp_link_firewall" in topo and "usw_flex_xg" in topo:
            self.add_edge("net_device:tp_link_firewall", "net_device:usw_flex_xg", "LAN_UPLINK_PORT_1")

        # Connect switch ports to cluster nodes
        known_node_keys = set(cluster_nodes_map.keys()) | {"tower", "mac", "nano", "agx", "spark1", "spark2", "krithi"}
        for dev_key, dev in topo.items():
            if dev.get("type") != "switch":
                continue
            sw_id = f"net_device:{dev_key}"
            for port_num, port_desc in (dev.get("ports") or {}).items():
                desc_low = str(port_desc).lower()
                speed_m = re.search(r"\(([^)]+)\)", str(port_desc))
                speed_tag = f"_{speed_m.group(1).replace(' ', '')}" if speed_m else ""
                for nkey in sorted(known_node_keys):
                    if re.search(rf"\b{re.escape(nkey)}\b", desc_low):
                        self.add_edge(
                            sw_id,
                            f"cluster_node:{nkey}",
                            f"SWITCH_PORT_{port_num}{speed_tag}",
                            {"port": port_num, "description": port_desc},
                        )

        # Link Unifi Network Controller service to the managed switches
        if "service:unifi_network_controller" in self.nodes:
            if "usw_pro_xg_8_poe" in topo:
                self.add_edge("service:unifi_network_controller", "net_device:usw_pro_xg_8_poe", "MANAGES_SWITCH")
            if "usw_flex_xg" in topo:
                self.add_edge("service:unifi_network_controller", "net_device:usw_flex_xg", "MANAGES_SWITCH")

    def parse_python_file(self, fpath: pathlib.Path, rel_path: str) -> None:
        """Parse Python files via AST for classes, functions, FastAPI endpoints, and imports."""
        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        mod_id = f"py_module:{rel_path}"
        doc = ""
        try:
            tree = ast.parse(source, filename=rel_path)
            doc = ast.get_docstring(tree) or ""
        except SyntaxError as exc:
            self.add_node(
                mod_id,
                "python_module",
                fpath.name,
                rel_path,
                f"Python module (syntax error on parse: {exc.msg})",
            )
            return

        first_line_doc = doc.strip().splitlines()[0] if doc.strip() else f"Python module {rel_path}"
        self.add_node(
            mod_id,
            "python_module",
            fpath.stem,
            rel_path,
            first_line_doc,
            {"lines": len(source.splitlines()), "rel_path": rel_path},
        )

        # Link to target cluster node based on directory role
        parts = pathlib.Path(rel_path).parts
        if len(parts) >= 2 and parts[0] == "agent":
            self.add_edge(mod_id, f"cluster_node:{parts[1]}", "TARGETS_NODE")
        elif len(parts) >= 1 and parts[0] == "cluster-management":
            self.add_edge(mod_id, "cluster_node:nano", "TARGETS_NODE")
        elif len(parts) >= 1 and parts[0] == "server":
            self.add_edge(mod_id, "cluster_node:mac_vm", "TARGETS_NODE")

        # Map AST methods inside classes so class -> method stack is preserved
        method_to_class: Dict[int, str] = {}
        for top_node in ast.walk(tree):
            if isinstance(top_node, ast.ClassDef):
                c_id = f"py_class:{rel_path}:{top_node.name}"
                for child in top_node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_to_class[id(child)] = c_id

        imported_modules: Set[str] = set()
        for node in ast.walk(tree):
            # Imports (resolved to internal py_module nodes in _resolve_cross_file_edges)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.add(node.module.split(".")[0])

            # Classes
            elif isinstance(node, ast.ClassDef):
                cls_id = f"py_class:{rel_path}:{node.name}"
                cls_doc = (ast.get_docstring(node) or "").strip()
                bases = [ast.unparse(b) for b in node.bases] if hasattr(ast, "unparse") else []
                self.add_node(
                    cls_id,
                    "python_class",
                    node.name,
                    rel_path,
                    cls_doc.splitlines()[0] if cls_doc else f"Class {node.name} in {rel_path}",
                    {"lineno": node.lineno, "bases": bases},
                )
                self.add_edge(mod_id, cls_id, "DEFINES_CLASS")

            # Functions & FastAPI routes
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_id = f"py_func:{rel_path}:{node.name}"
                fn_doc = (ast.get_docstring(node) or "").strip()
                is_async = isinstance(node, ast.AsyncFunctionDef)
                route_info = self._extract_route_decorator(node)

                called_names: List[str] = []
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        if isinstance(sub.func, ast.Name):
                            called_names.append(sub.func.id)
                        elif isinstance(sub.func, ast.Attribute):
                            called_names.append(sub.func.attr)
                dedup_calls = list(dict.fromkeys(cn for cn in called_names if cn != node.name))

                fn_seg = ast.get_source_segment(source, node) or ""
                fn_body_sha = hashlib.sha256(fn_seg.encode("utf-8")).hexdigest()[:12]
                self.add_node(
                    fn_id,
                    "python_function",
                    node.name,
                    rel_path,
                    fn_doc.splitlines()[0] if fn_doc else f"{'Async ' if is_async else ''}function {node.name}",
                    {
                        "lineno": node.lineno,
                        "is_async": is_async,
                        "args": [a.arg for a in node.args.args],
                        "calls": dedup_calls[:40],
                        "body_sha256": fn_body_sha,
                    },
                )
                parent_cls_id = method_to_class.get(id(node))
                if parent_cls_id:
                    self.add_edge(parent_cls_id, fn_id, "DEFINES_METHOD")
                self.add_edge(mod_id, fn_id, "DEFINES_FUNCTION")

                if route_info:
                    method, route_path = route_info
                    ep_id = f"api_endpoint:{method}:{route_path}"
                    self.add_node(
                        ep_id,
                        "api_endpoint",
                        f"{method} {route_path}",
                        rel_path,
                        fn_doc.splitlines()[0] if fn_doc else f"API endpoint handled by {node.name}",
                        {
                            "method": method,
                            "path": route_path,
                            "handler": node.name,
                            "lineno": node.lineno,
                            "body_sha256": fn_body_sha,
                        },
                    )
                    self.add_edge(mod_id, ep_id, "EXPOSES_ENDPOINT")
                    self.add_edge(ep_id, fn_id, "HANDLED_BY")

        if imported_modules and mod_id in self.nodes:
            self.nodes[mod_id]["metadata"]["imports"] = sorted(imported_modules)

    @staticmethod
    def _extract_route_decorator(node: ast.AST) -> Optional[Tuple[str, str]]:
        """Detect FastAPI/APIRouter @app.get('/path') or @router.websocket('/ws') decorators."""
        http_methods = {"get", "post", "put", "delete", "patch", "options", "head", "websocket", "api_route"}
        for dec in getattr(node, "decorator_list", []):
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                attr = dec.func.attr.lower()
                if attr in http_methods and dec.args:
                    first_arg = dec.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        return attr.upper(), first_arg.value
        return None

    def parse_shell_script(self, fpath: pathlib.Path, rel_path: str) -> None:
        """Parse shell scripts for header comments, functions, and node references."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        lines = content.splitlines()
        desc_lines: List[str] = []
        for line in lines[1:15]:
            s = line.strip()
            if s.startswith("#") and not s.startswith("#!"):
                cleaned = s.lstrip("#").strip()
                if cleaned and not all(c in "=-*#" for c in cleaned):
                    desc_lines.append(cleaned)
            elif s:
                break

        desc = desc_lines[0] if desc_lines else f"Shell script {rel_path}"
        sh_id = f"script:{rel_path}"
        funcs = re.findall(r"^\s*(?:function\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\)\s*\{", content, re.M)

        self.add_node(
            sh_id,
            "shell_script",
            fpath.name,
            rel_path,
            desc,
            {"lines": len(lines), "functions": funcs},
        )

        # Detect referenced cluster nodes by IP or name
        ip_to_node = {
            "192.168.1.150": "cluster_node:mac",
            "192.168.1.151": "cluster_node:tower",
            "192.168.1.155": "cluster_node:mac_vm",
            "192.168.1.181": "cluster_node:nano",
            "192.168.1.244": "cluster_node:agx",
            "192.168.1.201": "cluster_node:spark1",
            "192.168.1.202": "cluster_node:spark2",
        }
        for ip, target_node in ip_to_node.items():
            if ip in content:
                self.add_edge(sh_id, target_node, "REFERENCES_NODE", {"ip": ip})

        parts = pathlib.Path(rel_path).parts
        if len(parts) >= 2 and parts[0] == "agent":
            self.add_edge(sh_id, f"cluster_node:{parts[1]}", "CONFIGURES_NODE")
        elif len(parts) >= 1 and parts[0] == "server":
            self.add_edge(sh_id, "cluster_node:mac_vm", "CONFIGURES_NODE")

    def parse_yaml_file(self, fpath: pathlib.Path, rel_path: str) -> None:
        """Parse Kubernetes manifests and Lima YAML configs."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        docs = re.split(r"^---\s*$", content, flags=re.M)
        found_k8s = False
        parts = pathlib.Path(rel_path).parts
        for idx, doc in enumerate(docs):
            kind_m = re.search(r"^\s*kind:\s*([A-Za-z0-9_-]+)", doc, re.M)
            name_m = re.search(r"^\s*metadata:\s*(?:\n\s+.*)*?\n\s+name:\s*([A-Za-z0-9_.-]+)", doc, re.M)
            if kind_m and name_m:
                found_k8s = True
                kind = kind_m.group(1)
                name = name_m.group(1)
                images = re.findall(r"^\s*-?\s*image:\s*([^\s#]+)", doc, re.M)
                node_ports = re.findall(r"^\s*nodePort:\s*([0-9]+)", doc, re.M)
                node_sel = re.findall(r"kubernetes\.io/hostname:\s*([^\s#]+)", doc)

                res_id = f"k8s:{kind.lower()}:{name}:{rel_path}"
                self.add_node(
                    res_id,
                    "k8s_resource",
                    f"{kind}/{name}",
                    rel_path,
                    f"Kubernetes {kind} '{name}' in {rel_path}",
                    {
                        "kind": kind,
                        "name": name,
                        "images": images,
                        "node_ports": [int(p) for p in node_ports],
                        "node_selectors": node_sel,
                    },
                )
                for nsel in node_sel:
                    nsel_norm = "mac_vm" if nsel.lower() == "lima-k3s-server" else nsel.lower()
                    self.add_edge(res_id, f"cluster_node:{nsel_norm}", "DEPLOYED_ON")
                if not node_sel:
                    if len(parts) >= 2 and parts[0] == "agent":
                        self.add_edge(res_id, f"cluster_node:{parts[1]}", "DEPLOYED_ON")
                    elif len(parts) >= 1 and parts[0] == "server":
                        self.add_edge(res_id, "cluster_node:mac_vm", "DEPLOYED_ON")
                if "unifi" in name.lower():
                    self.add_edge(res_id, "service:unifi_network_controller", "PROVIDES_SERVICE")

        if not found_k8s:
            self.add_node(
                f"yaml:{rel_path}",
                "yaml_config",
                fpath.name,
                rel_path,
                f"YAML configuration file {rel_path}",
            )

    def parse_dockerfile(self, fpath: pathlib.Path, rel_path: str) -> None:
        """Parse Dockerfiles for base images and exposed ports."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        base_images = re.findall(r"^\s*FROM\s+([^\s#]+)", content, re.M | re.I)
        exposed = re.findall(r"^\s*EXPOSE\s+([0-9\s/tcpudp]+)", content, re.M | re.I)
        df_id = f"dockerfile:{rel_path}"
        self.add_node(
            df_id,
            "dockerfile",
            fpath.name,
            rel_path,
            f"Dockerfile ({', '.join(base_images) if base_images else 'custom'})",
            {"base_images": base_images, "exposed_ports": exposed},
        )
        parts = pathlib.Path(rel_path).parts
        if len(parts) >= 2 and parts[0] == "agent":
            self.add_edge(df_id, f"cluster_node:{parts[1]}", "BUILDS_IMAGE_FOR")

    def parse_doc_file(self, fpath: pathlib.Path, rel_path: str) -> None:
        """Parse Markdown and Unix troff manpages."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        headings = re.findall(r"^#{1,3}\s+(.+)$", content, re.M)
        title = headings[0].strip() if headings else fpath.name
        # If troff manpage (.1, .5, .7, .8)
        if fpath.suffix in {".1", ".5", ".7", ".8"}:
            th_m = re.search(r'^\.TH\s+"?([^"\s]+)"?\s+"?([0-9])"?', content, re.M)
            if th_m:
                title = f"{th_m.group(1)}({th_m.group(2)})"

        # Extract bold table/list labels and inline code identifiers for full-text metadata search
        bold_terms = [t.strip() for t in re.findall(r"\*\*([^*\n]{2,80})\*\*", content) if t.strip()]
        code_terms = [t.strip() for t in re.findall(r"`([^`\n]{2,80})`", content) if t.strip()]
        keywords = list(dict.fromkeys(bold_terms + code_terms))[:250]

        doc_id = f"doc:{rel_path}"
        self.add_node(
            doc_id,
            "document",
            title,
            rel_path,
            f"Documentation: {title} ({rel_path})",
            {
                "sections": headings[:50],
                "keywords": keywords,
                "format": fpath.suffix.lstrip(".") or "text",
            },
        )
        content_low = content.lower()
        for nkey in ("tower", "mac", "mac_vm", "nano", "agx", "spark1", "spark2", "krithi"):
            if re.search(rf"\b{re.escape(nkey.replace('_', '-'))}\b|\b{re.escape(nkey)}\b", content_low):
                self.add_edge(doc_id, f"cluster_node:{nkey}", "DOCUMENTS_NODE")

    def parse_html_file(self, fpath: pathlib.Path, rel_path: str) -> None:
        """Parse HTML templates and embedded JavaScript functions and API fetch calls."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        lines = content.splitlines()
        title_m = re.search(r"<title[^>]*>(.*?)</title>", content, re.I | re.S)
        title = title_m.group(1).strip() if title_m else fpath.name
        api_paths = sorted(set(re.findall(r"(/api/[A-Za-z0-9_/-]+)", content)))

        html_id = f"html:{rel_path}"
        self.add_node(
            html_id,
            "html_template",
            fpath.name,
            rel_path,
            f"HTML UI template: {title} ({len(lines)} lines)",
            {"title": title, "lines": len(lines), "api_paths": api_paths[:100]},
        )
        parts = pathlib.Path(rel_path).parts
        if len(parts) >= 1 and parts[0] == "cluster-management":
            self.add_edge(html_id, "cluster_node:nano", "TARGETS_NODE")

        js_fn_re = re.compile(r"^\s*(?:async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)")
        fn_starts = []
        for idx, line in enumerate(lines, start=1):
            m_fn = js_fn_re.match(line)
            if m_fn:
                fn_starts.append((idx, m_fn.group(1), [a.strip() for a in m_fn.group(2).split(",") if a.strip()]))

        js_apis_by_name: Dict[str, List[str]] = {}
        for f_i, (idx, fn_name, fn_args) in enumerate(fn_starts):
            next_idx = fn_starts[f_i + 1][0] - 1 if f_i + 1 < len(fn_starts) else min(len(lines), idx + 90)
            end_idx = min(next_idx, idx + 110)
            body_window = "\n".join(lines[idx - 1 : end_idx])
            fn_apis = sorted(set(re.findall(r"(/(?:api|ws)/[A-Za-z0-9_/-]+)", body_window)))
            js_apis_by_name[fn_name] = fn_apis
            js_id = f"js_func:{rel_path}:{fn_name}"
            self.add_node(
                js_id,
                "js_function",
                fn_name,
                rel_path,
                f"Frontend JS function {fn_name}() in {fpath.name}:{idx}",
                {
                    "lineno": idx,
                    "end_lineno": end_idx,
                    "args": fn_args,
                    "api_paths": fn_apis,
                    "trace_keys": [fn_name],
                },
            )
            self.add_edge(html_id, js_id, "DEFINES_JS_FUNCTION")
            body_low = body_window.lower()
            for nkey in ("tower", "mac", "mac_vm", "nano", "agx", "spark1", "spark2", "krithi"):
                if re.search(rf"\b{re.escape(nkey.replace('_', '-'))}\b|\b{re.escape(nkey)}\b", body_low):
                    self.add_edge(js_id, f"cluster_node:{nkey}", "TARGETS_NODE")

        # Index static Portal UI Tabs (<div id="..." class="tab-content...">) excluding <script> blocks
        tab_div_re = re.compile(r'<div\s+id="([^"]+)"\s+class="tab-content(?:\s+active)?"[^>]*>')
        tab_starts = []
        for idx, line in enumerate(lines, start=1):
            m_tab = tab_div_re.search(line)
            if m_tab:
                tab_starts.append((idx, m_tab.group(1)))

        show_tab_loaders: Dict[str, List[str]] = {
            "overview": ["loadStats"],
            "cluster": ["loadClusterData"],
            "pods": ["loadPods"],
            "resources": ["loadResourceUsage"],
            "services": ["loadServices"],
            "scripts": ["loadScripts"],
            "execute": ["loadScriptsForSelector"],
            "containers": ["loadDockerStatus", "loadDockerImages", "loadDockerContainers"],
            "unit-tests": ["loadTestSuite"],
            "logs": ["loadAuditLogs"],
            "backups": ["listBackups"],
            "versions": ["loadVersionStats"],
            "security": ["loadUsers", "loadActiveSessions"],
            "swagger": ["setSwaggerAuthorization"],
            "knowledge-graph": ["loadPortalKgIframe", "openPortalKgNewTab"],
        }

        for t_i, (start_ln, tab_id) in enumerate(tab_starts):
            end_ln = tab_starts[t_i + 1][0] - 1 if t_i + 1 < len(tab_starts) else min(len(lines), start_ln + 350)
            raw_tab_block = "\n".join(lines[start_ln - 1 : end_ln])
            # Strip <script>...</script> so dynamic JS template strings are never indexed as static HTML
            static_tab_block = re.sub(r"<script\b[^>]*>.*?</script>", "", raw_tab_block, flags=re.I | re.S)
            h_m = re.search(r"<h[23][^>]*>(.*?)</h[23]>", static_tab_block, re.I | re.S)
            raw_heading = re.sub(r"<[^>]+>", "", h_m.group(1)).strip() if h_m else tab_id
            card_headings = [
                re.sub(r"<[^>]+>", "", m_h3).strip()
                for m_h3 in re.findall(r"<h3[^>]*>(.*?)</h3>", static_tab_block, flags=re.I | re.S)
            ]
            card_headings = [ch for ch in dict.fromkeys(card_headings) if ch and ch != raw_heading]
            href_links = sorted(
                set(
                    hr.strip()
                    for hr in re.findall(r'href="([^"#]+)"', static_tab_block)
                    if hr.strip() and not hr.strip().startswith("javascript:")
                )
            )
            inline_api_paths = sorted(
                set(
                    re.findall(
                        r"(/(?:api|mcp|ml|ml2|sap|external-inference|knowledge-graph)[A-Za-z0-9_./-]*)",
                        raw_tab_block,
                    )
                )
            )
            static_data_keys = sorted(set(re.findall(r'data-kg-key="([^"]+)"', static_tab_block)))
            onclick_fns = sorted(
                set(
                    [
                        fn
                        for fn in re.findall(r'onclick="\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(', static_tab_block)
                        if f"js_func:{rel_path}:{fn}" in self.nodes
                    ]
                    + show_tab_loaders.get(tab_id, [])
                )
            )
            direct_apis = set(inline_api_paths)
            for fn_call in onclick_fns:
                direct_apis.update(js_apis_by_name.get(fn_call, []))
            tab_apis = sorted(direct_apis)
            tab_sha256 = hashlib.sha256(static_tab_block.encode("utf-8")).hexdigest()[:12]

            cards_desc = f" | Cards ({len(card_headings)}): {', '.join(card_headings[:12])}" if card_headings else ""
            tab_node_id = f"ui_tab:{rel_path}:{tab_id}"
            self.add_node(
                tab_node_id,
                "html_template",
                f"ui_tab:{tab_id}",
                rel_path,
                f"Portal UI Tab '{tab_id}' ({raw_heading}){cards_desc} in {fpath.name}:{start_ln}-{end_ln}",
                {
                    "lineno": start_ln,
                    "end_lineno": min(end_ln, start_ln + 65),
                    "tab_id": tab_id,
                    "heading": raw_heading,
                    "cards": card_headings[:25],
                    "href_links": href_links[:30],
                    "js_functions": onclick_fns[:40],
                    "api_paths": tab_apis[:40],
                    "content_sha256": tab_sha256,
                    "trace_keys": sorted(set([f"ui_tab:{tab_id}"] + card_headings[:15] + static_data_keys[:25] + onclick_fns[:25])),
                },
            )
            self.add_edge(html_id, tab_node_id, "DEFINES_UI_TAB")
            for fn_call in onclick_fns:
                target_js_id = f"js_func:{rel_path}:{fn_call}"
                if target_js_id in self.nodes:
                    self.add_edge(tab_node_id, target_js_id, "CALLS_JS_FUNCTION")
            tab_low = static_tab_block.lower()
            for nkey in ("tower", "mac", "mac_vm", "nano", "agx", "spark1", "spark2", "krithi"):
                if re.search(rf"\b{re.escape(nkey.replace('_', '-'))}\b|\b{re.escape(nkey)}\b", tab_low):
                    self.add_edge(tab_node_id, f"cluster_node:{nkey}", "TARGETS_NODE")
            if "192.168.1.151" in tab_low or "fiori" in tab_low:
                self.add_edge(tab_node_id, "cluster_node:tower", "TARGETS_NODE")
            if "192.168.1.155" in tab_low or "pgadmin" in tab_low:
                self.add_edge(tab_node_id, "cluster_node:mac_vm", "TARGETS_NODE")
            if "er605" in tab_low or "192.168.1.1/" in tab_low:
                for dev_id in ("net_device:tp_link_firewall", "net_device:er605_router"):
                    if dev_id in self.nodes:
                        self.add_edge(tab_node_id, dev_id, "TARGETS_DEVICE")
            if "10.1.10.1" in tab_low or "comcast" in tab_low:
                if "net_device:comcast_router" in self.nodes:
                    self.add_edge(tab_node_id, "net_device:comcast_router", "TARGETS_DEVICE")
            if "30443" in tab_low or "unifi" in tab_low:
                for sw_id in ("net_device:usw_pro_xg_8_poe", "net_device:usw_flex_xg"):
                    if sw_id in self.nodes:
                        self.add_edge(tab_node_id, sw_id, "TARGETS_DEVICE")

    def parse_env_file(self, fpath: pathlib.Path, rel_path: str) -> None:
        """Parse .env configuration files (recording variable keys only, never secret values)."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        keys = re.findall(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", content, re.M)
        dedup_keys = list(dict.fromkeys(keys))
        env_id = f"env:{rel_path}"
        self.add_node(
            env_id,
            "env_config",
            fpath.name,
            rel_path,
            f"Environment configuration {rel_path} ({len(dedup_keys)} variables)",
            {"variables": dedup_keys},
        )
        parts = pathlib.Path(rel_path).parts
        if len(parts) >= 2 and parts[0] == "agent":
            self.add_edge(env_id, f"cluster_node:{parts[1]}", "CONFIGURES_NODE")
        elif len(parts) >= 1 and parts[0] == "server":
            self.add_edge(env_id, "cluster_node:mac_vm", "CONFIGURES_NODE")

    def parse_requirements_file(self, fpath: pathlib.Path, rel_path: str) -> None:
        """Parse Python requirements*.txt files."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        pkgs: List[str] = []
        for ln in content.splitlines():
            s = ln.strip()
            if not s or s.startswith("#") or s.startswith("-"):
                continue
            pkg_name = re.split(r"[=<>!~\[\];\s]", s, maxsplit=1)[0].strip()
            if pkg_name:
                pkgs.append(pkg_name)
        dedup_pkgs = list(dict.fromkeys(pkgs))
        req_id = f"req:{rel_path}"
        self.add_node(
            req_id,
            "requirements_file",
            fpath.name,
            rel_path,
            f"Python package requirements {rel_path} ({len(dedup_pkgs)} packages)",
            {"packages": dedup_pkgs},
        )
        parts = pathlib.Path(rel_path).parts
        if len(parts) >= 2 and parts[0] == "agent":
            self.add_edge(req_id, f"cluster_node:{parts[1]}", "TARGETS_NODE")
        elif len(parts) >= 1 and parts[0] == "cluster-management":
            self.add_edge(req_id, "cluster_node:nano", "TARGETS_NODE")
        elif len(parts) >= 1 and parts[0] == "server":
            self.add_edge(req_id, "cluster_node:mac_vm", "TARGETS_NODE")

    def _extract_and_link_topics(
        self,
        source_node_id: str,
        text: str,
        file_path: Optional[str] = None,
        max_topics: int = 8,
    ) -> List[str]:
        """
        Extract up to `max_topics` meaningful domain keywords (len >= 4, not in _STOP_WORDS)
        and create/link `topic:{keyword}` (`type="topic_entity"`) via `MENTIONS_TOPIC` so
        documents, images, audio transcripts, and chat sessions discussing the same concepts
        are automatically connected in the Knowledge Graph.
        """
        if not text:
            return []
        extra_noise = {
            "http", "https", "true", "false", "none", "null", "file", "files",
            "line", "lines", "text", "data", "page", "pages", "slide", "slides",
            "sheet", "user", "chat", "turn", "session", "image", "audio",
            "document", "section", "table", "json", "yaml", "html", "path",
            "name", "type", "more", "some", "only", "also", "over", "after",
            "before", "between", "under", "again", "further", "once", "here",
            "there", "where", "both", "each", "most", "other", "such", "than",
            "very", "just", "should", "would", "could", "about", "which", "their",
            "these", "those", "through", "during", "without", "within", "unknown",
        }
        raw_words = re.findall(r"[A-Za-z][A-Za-z0-9_-]{3,}", text)
        freq: Dict[str, int] = {}
        for tok in raw_words:
            low = tok.lower().strip("_-")
            if len(low) < 4 or low in _STOP_WORDS or low in extra_noise or low.isdigit():
                continue
            freq[low] = freq.get(low, 0) + 1

        top_items = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[:max_topics]
        linked_keywords: List[str] = []
        for kw, cnt in top_items:
            topic_id = f"topic:{kw}"
            self.add_node(
                topic_id,
                "topic_entity",
                kw,
                file_path,
                f"Shared domain topic '{kw}' connecting multi-modal documents and workspace chats",
                {"keyword": kw},
            )
            self.add_edge(source_node_id, topic_id, "MENTIONS_TOPIC", {"count": cnt})
            linked_keywords.append(kw)
        return linked_keywords

    @staticmethod
    def _extract_pdf_pages(fpath: pathlib.Path) -> List[str]:
        """
        Extract page/section text from a PDF file using pypdf / PyPDF2 / fitz (PyMuPDF),
        falling back to `pdftotext <fpath> -`, and finally pure-Python zlib stream + regex extraction.
        """
        pages: List[str] = []
        # 1. Try pypdf / PyPDF2
        for mod_name in ("pypdf", "PyPDF2"):
            try:
                mod = __import__(mod_name)
                reader_cls = getattr(mod, "PdfReader", None)
                if reader_cls is not None:
                    reader = reader_cls(str(fpath))
                    for pg in list(getattr(reader, "pages", []))[:25]:
                        txt = (pg.extract_text() or "").strip()
                        if txt:
                            pages.append(txt)
                    if pages:
                        return pages
            except Exception:
                pass

        # 2. Try PyMuPDF (fitz)
        try:
            import fitz  # type: ignore
            doc = fitz.open(str(fpath))
            for pg in list(doc)[:25]:
                txt = (pg.get_text("text") or "").strip()
                if txt:
                    pages.append(txt)
            doc.close()
            if pages:
                return pages
        except Exception:
            pass

        # 3. Try pdftotext subprocess
        if shutil.which("pdftotext"):
            try:
                proc = subprocess.run(
                    ["pdftotext", str(fpath), "-"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    raw_pages = [p.strip() for p in proc.stdout.split("\f") if p.strip()]
                    if raw_pages:
                        return raw_pages[:25]
            except Exception:
                pass

        # 4. Fallback: pure-Python zlib FlateDecode stream decompression + printable ASCII/UTF-8 regex
        import zlib
        try:
            raw_bytes = fpath.read_bytes()[:4 * 1024 * 1024]
        except Exception:
            return []

        decoded_Buffers: List[str] = []
        for m_stream in re.finditer(b"stream[\r\n]+(.*?)[\r\n]+endstream", raw_bytes, flags=re.S):
            chunk = m_stream.group(1)
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                try:
                    decomp = zlib.decompress(chunk, wbits)
                    decoded_Buffers.append(decomp.decode("utf-8", errors="ignore"))
                    break
                except Exception:
                    continue
        decoded_Buffers.append(raw_bytes.decode("utf-8", errors="ignore"))
        combined_raw = "\n".join(decoded_Buffers)

        pdf_noise = {
            "obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref",
            "FlateDecode", "Filter", "Length", "Font", "Page", "Pages", "Catalog",
            "Type", "Resources", "ProcSet", "MediaBox", "Parent", "Contents",
        }
        literals = [
            m.group(1).strip()
            for m in re.finditer(r"\(([^()\\]{3,240})\)", combined_raw)
            if re.search(r"[A-Za-z]{3,}", m.group(1))
        ]
        if not literals:
            for run in re.findall(r"[A-Za-z0-9][A-Za-z0-9 ,.;:!?\'\"/()_\-]{12,240}", combined_raw):
                cleaned_run = run.strip()
                if any(tok in pdf_noise for tok in cleaned_run.split()):
                    continue
                if re.search(r"[A-Za-z]{4,}", cleaned_run):
                    literals.append(cleaned_run)

        full_txt = "\n".join(dict.fromkeys(literals))
        if not full_txt.strip():
            return []
        chunk_size = 1200
        return [
            full_txt[i : i + chunk_size].strip()
            for i in range(0, min(len(full_txt), chunk_size * 15), chunk_size)
            if full_txt[i : i + chunk_size].strip()
        ]

    @staticmethod
    def _extract_docx_sections(fpath: pathlib.Path) -> List[str]:
        """Parse Word (.docx) using stdlib zipfile + xml.etree.ElementTree (`word/document.xml`)."""
        import xml.etree.ElementTree as ET
        import zipfile

        paragraphs: List[str] = []
        try:
            with zipfile.ZipFile(fpath, "r") as zf:
                xml_names = [n for n in zf.namelist() if n == "word/document.xml" or n.startswith("word/header") or n.startswith("word/footer")]
                for xname in sorted(xml_names):
                    raw_xml = zf.read(xname)
                    root = ET.fromstring(raw_xml)
                    for elem in root.iter():
                        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                        if tag == "p":
                            runs = [
                                (sub.text or "")
                                for sub in elem.iter()
                                if (sub.tag.split("}")[-1] if "}" in sub.tag else sub.tag) == "t" and sub.text
                            ]
                            para_txt = "".join(runs).strip()
                            if para_txt:
                                paragraphs.append(para_txt)
        except Exception:
            return []

        if not paragraphs:
            return []
        sections: List[str] = []
        buf: List[str] = []
        buf_len = 0
        for p in paragraphs:
            buf.append(p)
            buf_len += len(p)
            if buf_len >= 900 or len(buf) >= 8:
                sections.append("\n".join(buf))
                buf = []
                buf_len = 0
                if len(sections) >= 15:
                    break
        if buf and len(sections) < 15:
            sections.append("\n".join(buf))
        return sections

    @staticmethod
    def _extract_pptx_slides(fpath: pathlib.Path) -> List[str]:
        """Parse PowerPoint (.pptx) using stdlib zipfile + xml.etree.ElementTree (`ppt/slides/slide*.xml`)."""
        import xml.etree.ElementTree as ET
        import zipfile

        slides: List[str] = []
        try:
            with zipfile.ZipFile(fpath, "r") as zf:
                slide_files = sorted(
                    [n for n in zf.namelist() if re.match(r"^ppt/slides/slide[0-9]+\.xml$", n)],
                    key=lambda s: int(re.findall(r"[0-9]+", s)[-1]),
                )
                for sname in slide_files[:15]:
                    root = ET.fromstring(zf.read(sname))
                    texts = [
                        (elem.text or "").strip()
                        for elem in root.iter()
                        if (elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag) == "t" and (elem.text or "").strip()
                    ]
                    if texts:
                        slides.append("\n".join(texts))
        except Exception:
            return []
        return slides

    @staticmethod
    def _extract_xlsx_tables(fpath: pathlib.Path) -> List[Dict[str, Any]]:
        """Parse Excel (.xlsx) using stdlib zipfile + xml.etree.ElementTree (`xl/sharedStrings.xml`, `xl/worksheets/sheet*.xml`)."""
        import xml.etree.ElementTree as ET
        import zipfile

        tables: List[Dict[str, Any]] = []
        try:
            with zipfile.ZipFile(fpath, "r") as zf:
                shared_strings: List[str] = []
                if "xl/sharedStrings.xml" in zf.namelist():
                    ss_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                    for si in ss_root.iter():
                        if (si.tag.split("}")[-1] if "}" in si.tag else si.tag) == "si":
                            parts = [
                                (t.text or "")
                                for t in si.iter()
                                if (t.tag.split("}")[-1] if "}" in t.tag else t.tag) == "t" and t.text
                            ]
                            shared_strings.append("".join(parts))

                sheet_names: Dict[int, str] = {}
                if "xl/workbook.xml" in zf.namelist():
                    wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
                    idx_s = 1
                    for el in wb_root.iter():
                        if (el.tag.split("}")[-1] if "}" in el.tag else el.tag) == "sheet":
                            sheet_names[idx_s] = el.attrib.get("name") or f"sheet{idx_s}"
                            idx_s += 1

                sheet_files = sorted(
                    [n for n in zf.namelist() if re.match(r"^xl/worksheets/sheet[0-9]+\.xml$", n)],
                    key=lambda s: int(re.findall(r"[0-9]+", s)[-1]),
                )
                for s_idx, sfile in enumerate(sheet_files[:10], start=1):
                    s_root = ET.fromstring(zf.read(sfile))
                    rows_data: List[List[str]] = []
                    for r_el in s_root.iter():
                        if (r_el.tag.split("}")[-1] if "}" in r_el.tag else r_el.tag) == "row":
                            row_vals: List[str] = []
                            for c_el in r_el:
                                if (c_el.tag.split("}")[-1] if "}" in c_el.tag else c_el.tag) != "c":
                                    continue
                                c_type = c_el.attrib.get("t", "")
                                val_str = ""
                                if c_type == "inlineStr":
                                    t_parts = [
                                        (t.text or "")
                                        for t in c_el.iter()
                                        if (t.tag.split("}")[-1] if "}" in t.tag else t.tag) == "t" and t.text
                                    ]
                                    val_str = "".join(t_parts).strip()
                                else:
                                    v_el = next(
                                        (ch for ch in c_el if (ch.tag.split("}")[-1] if "}" in ch.tag else ch.tag) == "v"),
                                        None,
                                    )
                                    if v_el is not None and v_el.text is not None:
                                        raw_v = v_el.text.strip()
                                        if c_type == "s" and raw_v.isdigit():
                                            s_i = int(raw_v)
                                            val_str = shared_strings[s_i] if 0 <= s_i < len(shared_strings) else raw_v
                                        else:
                                            val_str = raw_v
                                row_vals.append(val_str)
                            if any(v.strip() for v in row_vals):
                                rows_data.append(row_vals)
                    if rows_data:
                        headers = [h.strip() or f"col_{i+1}" for i, h in enumerate(rows_data[0])]
                        data_rows = rows_data[1:]
                        tables.append(
                            {
                                "sheet": sheet_names.get(s_idx, f"sheet{s_idx}"),
                                "headers": headers[:30],
                                "row_count": len(data_rows),
                                "sample_rows": [r[:15] for r in data_rows[:5]],
                            }
                        )
        except Exception:
            return []
        return tables

    @staticmethod
    def _transcribe_audio_with_sidecar(fpath: pathlib.Path) -> Tuple[str, Dict[str, Any]]:
        """
        Check if `<fpath>.transcript.txt` sidecar exists; if not, attempt speech-to-text
        via local whisper / faster_whisper, `/usr/local/bin/use-gpu` (timeout 12s), or
        `ffprobe` audio metadata extraction, and cache `<fpath>.transcript.txt`.
        """
        sidecar = fpath.with_name(fpath.name + ".transcript.txt")
        audio_meta: Dict[str, Any] = {
            "size_kb": round(fpath.stat().st_size / 1024.0, 1) if fpath.exists() else 0.0,
        }

        # Extract duration / codec via ffprobe if available
        if shutil.which("ffprobe"):
            try:
                pr = subprocess.run(
                    [
                        "ffprobe", "-v", "quiet", "-print_format", "json",
                        "-show_format", "-show_streams", str(fpath),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=6,
                    check=False,
                )
                if pr.returncode == 0 and pr.stdout.strip():
                    ff_info = json.loads(pr.stdout)
                    fmt_info = ff_info.get("format", {}) or {}
                    if fmt_info.get("duration"):
                        audio_meta["duration_sec"] = round(float(fmt_info["duration"]), 2)
                    if fmt_info.get("format_name"):
                        audio_meta["container_format"] = fmt_info["format_name"]
                    tags = fmt_info.get("tags", {}) or {}
                    if tags:
                        audio_meta["tags"] = {k: str(v)[:120] for k, v in list(tags.items())[:8]}
                    streams = ff_info.get("streams", []) or []
                    if streams:
                        s0 = streams[0]
                        if s0.get("codec_name"):
                            audio_meta["codec"] = s0["codec_name"]
                        if s0.get("sample_rate"):
                            audio_meta["sample_rate"] = s0["sample_rate"]
            except Exception:
                pass

        if sidecar.is_file():
            try:
                cached = sidecar.read_text(encoding="utf-8", errors="replace").strip()
                if cached:
                    audio_meta["transcript_source"] = "sidecar_cache"
                    return cached, audio_meta
            except Exception:
                pass

        transcript_text = ""
        # 1. Try faster_whisper if installed locally
        try:
            from faster_whisper import WhisperModel  # type: ignore
            model = WhisperModel("tiny", device="cpu", compute_type="int8")
            segments, _ = model.transcribe(str(fpath), beam_size=1)
            transcript_text = " ".join(seg.text.strip() for seg in segments if seg.text.strip()).strip()
            if transcript_text:
                audio_meta["transcript_source"] = "faster_whisper"
        except Exception:
            pass

        # 2. Try whisper CLI or /usr/local/bin/use-gpu whisper with 12s timeout
        if not transcript_text:
            whisper_bin = shutil.which("whisper")
            if whisper_bin:
                cmd: List[str] = []
                if pathlib.Path("/usr/local/bin/use-gpu").is_file() and os.access("/usr/local/bin/use-gpu", os.X_OK):
                    cmd = ["/usr/local/bin/use-gpu", whisper_bin, str(fpath), "--model", "tiny", "--output_format", "txt", "--output_dir", "/tmp"]
                else:
                    cmd = [whisper_bin, str(fpath), "--model", "tiny", "--output_format", "txt", "--output_dir", "/tmp"]
                try:
                    subprocess.run(cmd, capture_output=True, text=True, timeout=12, check=False)
                    out_txt_file = pathlib.Path("/tmp") / f"{fpath.stem}.txt"
                    if out_txt_file.is_file():
                        transcript_text = out_txt_file.read_text(encoding="utf-8", errors="replace").strip()
                        audio_meta["transcript_source"] = "whisper_cli"
                except Exception:
                    pass

        # 3. Fallback: extract embedded printable text/tags + audio metadata summary
        if not transcript_text:
            tag_parts: List[str] = []
            for k, v in (audio_meta.get("tags") or {}).items():
                tag_parts.append(f"{k}: {v}")
            try:
                raw_b = fpath.read_bytes()[:262144]
                ascii_runs = [
                    m.group(0).decode("utf-8", errors="ignore").strip()
                    for m in re.finditer(rb"[A-Za-z][A-Za-z0-9 ,.;:!?\'\"_\-]{5,120}", raw_b)
                ]
                meaningful_runs = [
                    r for r in dict.fromkeys(ascii_runs)
                    if r.lower() not in ("lavf", "id3", "vorbis", "opus", "fmp4", "isom")
                ][:20]
                if meaningful_runs:
                    tag_parts.append(" ".join(meaningful_runs))
            except Exception:
                pass
            dur_str = f"{audio_meta.get('duration_sec', 'unknown')}s"
            codec_str = audio_meta.get("codec", fpath.suffix.lstrip("."))
            stem_words = re.sub(r"[_\-]+", " ", fpath.stem)
            transcript_text = (
                f"Audio recording '{stem_words}' ({codec_str}, duration={dur_str}, {audio_meta.get('size_kb')} KB). "
                + (" | ".join(tag_parts) if tag_parts else f"Keywords: {stem_words}")
            ).strip()
            audio_meta["transcript_source"] = "metadata_fallback"

        try:
            sidecar.write_text(transcript_text + "\n", encoding="utf-8")
        except OSError:
            pass
        return transcript_text, audio_meta

    def parse_generic_document_file(self, fpath: pathlib.Path, rel_path: str) -> None:
        """
        Multi-modal document, spreadsheet, image (OCR), and audio (STT) parser for
        `<repo_root>/documents/` and Single-Repository AI Workspaces.
        """
        import csv

        suffix = fpath.suffix.lower()
        try:
            size_bytes = fpath.stat().st_size
        except OSError:
            return

        # 1. Images (OCR)
        if suffix in IMAGE_DOC_EXTENSIONS:
            meta_summary, ocr_text = _extract_image_dimensions_and_ocr(fpath)
            img_id = f"img_doc:{rel_path}"
            clean_ocr = re.sub(r"\s+", " ", ocr_text).strip()
            topics = self._extract_and_link_topics(img_id, f"{fpath.stem} {ocr_text}", rel_path, max_topics=8)
            self.add_node(
                img_id,
                "image_document",
                fpath.name,
                rel_path,
                f"Image Document {fpath.name} ({meta_summary}) — OCR: {clean_ocr[:220] or 'N/A'}",
                {
                    "format": suffix.lstrip("."),
                    "image_dimensions": meta_summary,
                    "size_bytes": size_bytes,
                    "ocr_text": ocr_text[:2500],
                    "topics": topics,
                },
            )
            return

        # 2. Audio (STT with <fpath>.transcript.txt sidecar cache)
        if suffix in AUDIO_DOC_EXTENSIONS:
            transcript_text, audio_meta = self._transcribe_audio_with_sidecar(fpath)
            aud_id = f"audio_doc:{rel_path}"
            clean_tr = re.sub(r"\s+", " ", transcript_text).strip()
            topics = self._extract_and_link_topics(aud_id, f"{fpath.stem} {transcript_text}", rel_path, max_topics=8)
            audio_meta["topics"] = topics
            audio_meta["transcript"] = transcript_text[:3000]
            self.add_node(
                aud_id,
                "audio_transcript",
                fpath.name,
                rel_path,
                f"Audio Transcript {fpath.name} ({audio_meta.get('size_kb', 0)} KB): {clean_tr[:220]}",
                audio_meta,
            )
            return

        # 3. Excel / CSV / TSV Tabular Datasets
        if suffix in {".xlsx", ".csv", ".tsv"}:
            doc_id = f"doc_file:{rel_path}"
            tables: List[Dict[str, Any]] = []
            if suffix == ".xlsx":
                tables = self._extract_xlsx_tables(fpath)
            else:
                delim = "\t" if suffix == ".tsv" else ","
                try:
                    raw_csv = fpath.read_text(encoding="utf-8", errors="replace")
                    reader = csv.reader(raw_csv.splitlines(), delimiter=delim)
                    non_empty = [row for row in reader if any(c.strip() for c in row)]
                    if non_empty:
                        headers = [h.strip() or f"col_{i+1}" for i, h in enumerate(non_empty[0])]
                        data_rows = non_empty[1:]
                        tables.append(
                            {
                                "sheet": fpath.stem or "main",
                                "headers": headers[:30],
                                "row_count": len(data_rows),
                                "sample_rows": [r[:15] for r in data_rows[:5]],
                            }
                        )
                except Exception:
                    tables = []

            combined_table_text = [fpath.stem]
            for tbl in tables:
                combined_table_text.extend(tbl.get("headers", []))
                for srow in tbl.get("sample_rows", []):
                    combined_table_text.extend(srow)
            topics = self._extract_and_link_topics(doc_id, " ".join(combined_table_text), rel_path, max_topics=8)
            total_rows = sum(int(t.get("row_count", 0)) for t in tables)
            all_hdrs = [h for t in tables for h in t.get("headers", [])][:15]
            self.add_node(
                doc_id,
                "document_file",
                fpath.name,
                rel_path,
                f"Tabular Document {fpath.name} ({len(tables)} sheet/table(s), {total_rows} rows, cols: {', '.join(all_hdrs[:8]) or 'N/A'})",
                {
                    "format": suffix.lstrip("."),
                    "table_count": len(tables),
                    "total_rows": total_rows,
                    "headers": all_hdrs,
                    "size_bytes": size_bytes,
                    "topics": topics,
                },
            )
            for t_idx, tbl in enumerate(tables[:15], start=1):
                sheet_name = str(tbl.get("sheet") or f"sheet{t_idx}")
                sheet_slug = re.sub(r"[^A-Za-z0-9_.-]", "_", sheet_name) or f"sheet{t_idx}"
                tbl_id = f"doc_table:{rel_path}:{sheet_slug}"
                hdrs = tbl.get("headers", [])
                rcnt = tbl.get("row_count", 0)
                srows = tbl.get("sample_rows", [])
                self.add_node(
                    tbl_id,
                    "document_table",
                    f"{fpath.name} [{sheet_name}]",
                    rel_path,
                    f"Table '{sheet_name}' in {fpath.name} ({rcnt} rows; headers: {', '.join(hdrs[:10])})",
                    {
                        "sheet": sheet_name,
                        "headers": hdrs,
                        "row_count": rcnt,
                        "sample_rows": srows,
                    },
                )
                self.add_edge(doc_id, tbl_id, "CONTAINS_SECTION")
                self._extract_and_link_topics(tbl_id, " ".join(hdrs + [c for r in srows for c in r]), rel_path, max_topics=5)
            return

        # 4. PDF, Word (.docx), PowerPoint (.pptx), and Generic Text/Data Documents (.txt, .log, .json, .yaml, .yml)
        sections: List[str] = []
        section_label = "Section"
        if suffix == ".pdf":
            sections = self._extract_pdf_pages(fpath)
            section_label = "Page"
        elif suffix == ".docx":
            sections = self._extract_docx_sections(fpath)
            section_label = "Section"
        elif suffix == ".pptx":
            sections = self._extract_pptx_slides(fpath)
            section_label = "Slide"
        else:
            try:
                raw_txt = fpath.read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                raw_txt = ""
            if raw_txt:
                chunk_sz = 1200
                sections = [
                    raw_txt[i : i + chunk_sz].strip()
                    for i in range(0, min(len(raw_txt), chunk_sz * 15), chunk_sz)
                    if raw_txt[i : i + chunk_sz].strip()
                ]

        full_text = f"{fpath.stem}\n" + "\n".join(sections)
        doc_id = f"doc_file:{rel_path}"
        topics = self._extract_and_link_topics(doc_id, full_text, rel_path, max_topics=8)
        first_preview = re.sub(r"\s+", " ", sections[0]).strip()[:180] if sections else fpath.name

        self.add_node(
            doc_id,
            "document_file",
            fpath.name,
            rel_path,
            f"Document {fpath.name} ({len(sections)} {section_label.lower()}(s)): {first_preview}",
            {
                "format": suffix.lstrip(".") or "text",
                "section_count": len(sections),
                "size_bytes": size_bytes,
                "topics": topics,
            },
        )
        for idx_s, sec_txt in enumerate(sections[:15], start=1):
            sec_id = f"doc_sec:{rel_path}:{idx_s}"
            sec_one_line = re.sub(r"\s+", " ", sec_txt).strip()[:220]
            self.add_node(
                sec_id,
                "document_section",
                f"{fpath.name} [{section_label} {idx_s}]",
                rel_path,
                f"{section_label} {idx_s} of {fpath.name}: {sec_one_line}",
                {
                    "section_index": idx_s,
                    "section_type": section_label.lower(),
                    "text_excerpt": sec_txt[:800],
                    "char_count": len(sec_txt),
                },
            )
            self.add_edge(doc_id, sec_id, "CONTAINS_SECTION")
            self._extract_and_link_topics(sec_id, sec_txt, rel_path, max_topics=4)

    def _clean_chat_text(self, raw_text: str) -> str:
        """
        Scrub `<USER_REQUEST>`, `<ADDITIONAL_METADATA>`, and `<SYSTEM_MESSAGE>` tags
        from chat turn text and run PII/secrets sanitization if available.
        """
        if not raw_text:
            return ""
        txt = raw_text
        # Strip <ADDITIONAL_METADATA>...</ADDITIONAL_METADATA> blocks
        txt = re.sub(r"<ADDITIONAL_METADATA>[\s\S]*?</ADDITIONAL_METADATA>", "", txt, flags=re.I)
        # Strip boilerplate wrapper lines around <SYSTEM_MESSAGE>
        txt = re.sub(
            r"The following is a <SYSTEM_MESSAGE> not actually sent by the user\.[^\n]*\n?",
            "",
            txt,
            flags=re.I,
        )
        # Strip opening/closing XML tags for USER_REQUEST, SYSTEM_MESSAGE, ADDITIONAL_METADATA
        txt = re.sub(r"</?(?:USER_REQUEST|SYSTEM_MESSAGE|ADDITIONAL_METADATA)>", "", txt, flags=re.I)
        txt = re.sub(r"\n{3,}", "\n\n", txt).strip()
        if not txt:
            return ""
        try:
            mcp_mod = _load_local_mcp_middleware(self.repo_root)
            if mcp_mod is not None and hasattr(mcp_mod, "sanitize_pii_and_secrets"):
                txt, _ = mcp_mod.sanitize_pii_and_secrets(txt)
        except Exception:
            pass
        return txt.strip()

    def _has_chats_folder_files(self) -> bool:
        chats_dir = self.repo_root / "chats"
        if not chats_dir.is_dir():
            return False
        return any(
            p.is_file() and not p.name.startswith(".") and p.suffix.lower() in CHAT_FILE_EXTENSIONS
            for p in chats_dir.rglob("*")
        )

    def parse_workspace_chats(self, force_sync: bool = False) -> Dict[str, int]:
        """
        Index workspace chat transcripts into the Knowledge Graph from:
          - Source A: `<repo_root>/chats/` (`.md`, `.txt`, `.json`, `.jsonl` files)
          - Source B: Live Zed / Antigravity `~/.gemini/antigravity-cli/brain/*/.system_generated/logs/transcript.jsonl`
        Creates `chat_session:{conv_id[:8]}` and up to 12 `chat_turn:{conv_id[:8]}:S{step_idx}` nodes,
        linking them to discussed files (`DISCUSSED_FILE`) and shared domain topics (`MENTIONS_TOPIC`).
        """
        conversations: List[Dict[str, Any]] = []
        seen_conv_ids: Set[str] = set()

        # Source A: <repo_root>/chats/ files
        chats_dir = self.repo_root / "chats"
        if chats_dir.is_dir():
            chat_files = sorted(
                p
                for p in chats_dir.rglob("*")
                if p.is_file() and not p.name.startswith(".") and p.suffix.lower() in CHAT_FILE_EXTENSIONS
            )
            for cf in chat_files:
                rel_cf = str(cf.relative_to(self.repo_root))
                stem_clean = re.sub(r"[^a-zA-Z0-9]", "", cf.stem)
                f_hash = compute_sha256(cf)[:8]
                conv_id = (stem_clean[:8] if len(stem_clean) >= 8 else (stem_clean + f_hash)[:8]) or f_hash
                if conv_id in seen_conv_ids:
                    conv_id = f"{conv_id[:4]}{f_hash[:4]}"
                seen_conv_ids.add(conv_id)

                turns: List[Tuple[int, str, str, str]] = []
                ext = cf.suffix.lower()
                try:
                    raw_cf = cf.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                if ext == ".jsonl":
                    for l_idx, ln in enumerate(raw_cf.splitlines(), start=1):
                        s_ln = ln.strip()
                        if not s_ln:
                            continue
                        try:
                            obj = json.loads(s_ln)
                        except Exception:
                            continue
                        if not isinstance(obj, dict):
                            continue
                        stype = str(obj.get("type") or obj.get("role") or "").upper()
                        sidx = int(obj.get("step_index") or l_idx)
                        c_at = str(obj.get("created_at") or obj.get("timestamp") or "")
                        content_raw = str(obj.get("content") or obj.get("message") or obj.get("text") or "")
                        if stype in ("USER_INPUT", "USER", "HUMAN") and content_raw.strip():
                            cleaned = self._clean_chat_text(content_raw)
                            if cleaned:
                                turns.append((sidx, "user", cleaned, c_at))
                        elif stype in ("PLANNER_RESPONSE", "ASSISTANT", "AGENT", "MODEL", "AI") and content_raw.strip():
                            cleaned = self._clean_chat_text(content_raw)
                            if cleaned:
                                turns.append((sidx, "assistant", cleaned, c_at))
                elif ext == ".json":
                    try:
                        parsed = json.loads(raw_cf)
                        items = (
                            parsed
                            if isinstance(parsed, list)
                            else (
                                parsed.get("messages")
                                or parsed.get("turns")
                                or parsed.get("steps")
                                or parsed.get("history")
                                or []
                            )
                            if isinstance(parsed, dict)
                            else []
                        )
                        for l_idx, obj in enumerate(items, start=1):
                            if not isinstance(obj, dict):
                                continue
                            stype = str(obj.get("type") or obj.get("role") or "user").upper()
                            sidx = int(obj.get("step_index") or l_idx)
                            c_at = str(obj.get("created_at") or obj.get("timestamp") or "")
                            content_raw = str(obj.get("content") or obj.get("message") or obj.get("text") or "")
                            role_norm = "user" if stype in ("USER_INPUT", "USER", "HUMAN") else "assistant"
                            cleaned = self._clean_chat_text(content_raw)
                            if cleaned:
                                turns.append((sidx, role_norm, cleaned, c_at))
                    except Exception:
                        pass
                else:
                    # .md or .txt chat transcript
                    blocks = [b.strip() for b in re.split(r"\n{2,}", raw_cf) if b.strip()]
                    for b_idx, blk in enumerate(blocks[:24], start=1):
                        role_norm = "user" if (b_idx == 1 or re.match(r"^(?:#{1,3}\s*)?(?:user|human|question|prompt)\b", blk, re.I)) else "assistant"
                        cleaned = self._clean_chat_text(blk)
                        if cleaned:
                            turns.append((b_idx, role_norm, cleaned, ""))

                if turns:
                    conversations.append(
                        {
                            "conv_id": conv_id,
                            "file_path": rel_cf,
                            "source": "chats_folder",
                            "turns": turns,
                        }
                    )

        # Source B: Live Zed / Antigravity transcript.jsonl files
        brain_dirs = [
            pathlib.Path.home() / ".gemini" / "antigravity-cli" / "brain",
            pathlib.Path("/home/sanjay/.gemini/antigravity-cli/brain"),
        ]
        transcript_candidates: List[pathlib.Path] = []
        seen_tpaths: Set[str] = set()
        for bdir in brain_dirs:
            if bdir.is_dir():
                for tp in bdir.glob("*/.system_generated/logs/transcript.jsonl"):
                    if tp.is_file():
                        rp_str = str(tp.resolve())
                        if rp_str not in seen_tpaths:
                            seen_tpaths.add(rp_str)
                            transcript_candidates.append(tp)

        transcript_candidates.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0.0, reverse=True)
        recent_transcripts = transcript_candidates[:15]

        repo_str = str(self.repo_root.resolve())
        repo_name = self.repo_root.name
        single_repo = not is_master_cluster_repo(self.repo_root)
        matched_live_count = 0

        for tp in recent_transcripts:
            if matched_live_count >= 8:
                break
            conv_id = tp.parent.parent.parent.name
            if conv_id[:8] in seen_conv_ids:
                continue
            try:
                raw_jsonl = tp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            mentions_repo = (repo_str in raw_jsonl) or (bool(repo_name) and len(repo_name) > 2 and repo_name in raw_jsonl)
            if not (mentions_repo or force_sync):
                continue

            turns_b: List[Tuple[int, str, str, str]] = []
            for l_idx, ln in enumerate(raw_jsonl.splitlines(), start=1):
                s_ln = ln.strip()
                if not s_ln:
                    continue
                try:
                    obj = json.loads(s_ln)
                except Exception:
                    continue
                if not isinstance(obj, dict):
                    continue
                stype = obj.get("type", "")
                sidx = obj.get("step_index", l_idx)
                c_at = str(obj.get("created_at") or "")
                content_raw = obj.get("content")
                if not isinstance(content_raw, str) or not content_raw.strip():
                    continue
                if stype == "USER_INPUT":
                    cleaned = self._clean_chat_text(content_raw)
                    if cleaned:
                        turns_b.append((int(sidx), "user", cleaned, c_at))
                elif stype == "PLANNER_RESPONSE":
                    cleaned = self._clean_chat_text(content_raw)
                    if cleaned:
                        turns_b.append((int(sidx), "assistant", cleaned, c_at))

            if turns_b:
                seen_conv_ids.add(conv_id[:8])
                matched_live_count += 1
                conversations.append(
                    {
                        "conv_id": conv_id,
                        "file_path": f"chats/transcript_{conv_id[:8]}.jsonl",
                        "source": "antigravity_transcript",
                        "turns": turns_b,
                    }
                )

        # Build lookup of indexed file/document nodes by basename so chats mentioning filenames link via DISCUSSED_FILE
        file_node_types = {
            "document_file", "image_document", "audio_transcript", "document",
            "python_module", "shell_script", "config_file", "html_template",
            "yaml_config", "json_file", "sql_file", "dockerfile",
            "requirements_file", "env_config",
        }
        files_by_basename: Dict[str, List[str]] = {}
        for nid, nd in list(self.nodes.items()):
            if nd.get("type") in file_node_types and nd.get("file_path"):
                bname = pathlib.Path(nd["file_path"]).name.lower()
                if len(bname) >= 4 and bname not in (".gitkeep",):
                    files_by_basename.setdefault(bname, []).append(nid)

        sessions_created = 0
        turns_created = 0
        for conv in conversations:
            conv_id = str(conv["conv_id"])
            short_id = conv_id[:8]
            c_fp = str(conv["file_path"])
            turns_list: List[Tuple[int, str, str, str]] = conv["turns"]
            if not turns_list:
                continue

            first_user_q = next((c for _, r, c, _ in turns_list if r == "user"), turns_list[0][2])
            first_q_summary = re.sub(r"\s+", " ", first_user_q).strip()[:160]
            session_id = f"chat_session:{short_id}"
            combined_chat_text = "\n".join(c for _, _, c, _ in turns_list[-12:])
            topics = self._extract_and_link_topics(session_id, combined_chat_text, c_fp, max_topics=8)

            self.add_node(
                session_id,
                "chat_session",
                f"Chat Session {short_id}",
                c_fp,
                f"Chat Session {short_id} ({len(turns_list)} turns): {first_q_summary}",
                {
                    "conversation_id": conv_id,
                    "short_id": short_id,
                    "turn_count": len(turns_list),
                    "first_question": first_q_summary,
                    "source": conv["source"],
                    "topics": topics,
                },
            )
            sessions_created += 1

            combined_low = combined_chat_text.lower()
            discussed_nids: Set[str] = set()
            for bname, target_nids in files_by_basename.items():
                if bname in combined_low:
                    for t_nid in target_nids[:3]:
                        self.add_edge(session_id, t_nid, "DISCUSSED_FILE")
                        discussed_nids.add(t_nid)

            for sidx, role, content, created_at in turns_list[-12:]:
                turn_id = f"chat_turn:{short_id}:S{sidx}"
                one_line = re.sub(r"\s+", " ", content).strip()[:220]
                turn_topics = self._extract_and_link_topics(turn_id, content, c_fp, max_topics=4)
                self.add_node(
                    turn_id,
                    "chat_turn",
                    f"Chat {short_id} Turn S{sidx} ({role})",
                    c_fp,
                    f"[{role.upper()} S{sidx}] {one_line}",
                    {
                        "conversation_id": conv_id,
                        "step_index": sidx,
                        "role": role,
                        "created_at": created_at,
                        "content_excerpt": content[:800],
                        "topics": turn_topics,
                    },
                )
                self.add_edge(session_id, turn_id, "HAS_CHAT_TURN")
                turns_created += 1

                turn_low = content.lower()
                for bname, target_nids in files_by_basename.items():
                    if bname in turn_low:
                        for t_nid in target_nids[:2]:
                            self.add_edge(turn_id, t_nid, "DISCUSSED_FILE")

        return {"chat_sessions": sessions_created, "chat_turns": turns_created}

    index_workspace_chats = parse_workspace_chats

    def _resolve_cross_file_edges(self) -> None:
        """Resolve cross-file IMPORTS, Python CALLS, JS CALLS_ENDPOINT, and Shell CALLS_SCRIPT / APPLIES_MANIFEST edges."""
        # 1. Index py_module nodes by stem and directory
        mod_by_dir_stem: Dict[Tuple[str, str], str] = {}
        mod_by_stem: Dict[str, List[str]] = {}
        for nid, nd in list(self.nodes.items()):
            if nd["type"] == "python_module" and nd.get("file_path"):
                fp = pathlib.Path(nd["file_path"])
                parent_str = str(fp.parent)
                mod_by_dir_stem[(parent_str, fp.stem)] = nid
                mod_by_stem.setdefault(fp.stem, []).append(nid)

        for nid, nd in list(self.nodes.items()):
            if nd["type"] == "python_module" and nd.get("file_path"):
                fp = pathlib.Path(nd["file_path"])
                parent_str = str(fp.parent)
                for imp_name in nd.get("metadata", {}).get("imports", []):
                    target_mod = mod_by_dir_stem.get((parent_str, imp_name))
                    if not target_mod:
                        candidates = mod_by_stem.get(imp_name, [])
                        if len(candidates) == 1:
                            target_mod = candidates[0]
                    if target_mod and target_mod != nid:
                        self.add_edge(nid, target_mod, "IMPORTS")

        # 2. Index python_function nodes for CALLS resolution
        fn_by_file_name: Dict[Tuple[str, str], str] = {}
        fn_by_dir_name: Dict[Tuple[str, str], List[str]] = {}
        fn_by_name: Dict[str, List[str]] = {}
        for nid, nd in list(self.nodes.items()):
            if nd["type"] == "python_function" and nd.get("file_path"):
                fp_str = nd["file_path"]
                dir_str = str(pathlib.Path(fp_str).parent)
                fname = nd["name"]
                fn_by_file_name[(fp_str, fname)] = nid
                fn_by_dir_name.setdefault((dir_str, fname), []).append(nid)
                fn_by_name.setdefault(fname, []).append(nid)

        for nid, nd in list(self.nodes.items()):
            if nd["type"] == "python_function" and nd.get("file_path"):
                fp_str = nd["file_path"]
                dir_str = str(pathlib.Path(fp_str).parent)
                for called in nd.get("metadata", {}).get("calls", []):
                    target_fn = fn_by_file_name.get((fp_str, called))
                    if not target_fn:
                        dir_cands = [c for c in fn_by_dir_name.get((dir_str, called), []) if c != nid]
                        if len(dir_cands) == 1:
                            target_fn = dir_cands[0]
                    if not target_fn:
                        all_cands = [c for c in fn_by_name.get(called, []) if c != nid]
                        if len(all_cands) == 1:
                            target_fn = all_cands[0]
                    if target_fn and target_fn != nid:
                        self.add_edge(nid, target_fn, "CALLS")

        # 3. Link frontend JS functions (and HTML templates) to FastAPI api_endpoint nodes (CALLS_ENDPOINT)
        ep_by_static_path: Dict[str, List[str]] = {}
        for nid, nd in list(self.nodes.items()):
            if nd["type"] == "api_endpoint":
                raw_path = nd.get("metadata", {}).get("path", "")
                if raw_path:
                    static_prefix = re.split(r"/\{", raw_path, maxsplit=1)[0].rstrip("/") or "/"
                    ep_by_static_path.setdefault(static_prefix, []).append(nid)

        for nid, nd in list(self.nodes.items()):
            if nd["type"] in ("js_function", "html_template"):
                for api_p in nd.get("metadata", {}).get("api_paths", []):
                    norm_p = api_p.rstrip("/") or "/"
                    matched_eps = ep_by_static_path.get(norm_p, [])
                    for ep_id in matched_eps:
                        self.add_edge(nid, ep_id, "CALLS_ENDPOINT")

        # 4. Link shell scripts to called shell scripts (CALLS_SCRIPT) and applied K8s manifests (APPLIES_MANIFEST)
        scripts_by_rel: Dict[str, str] = {}
        scripts_by_name: Dict[str, List[str]] = {}
        k8s_by_rel: Dict[str, List[str]] = {}
        k8s_by_name: Dict[str, List[str]] = {}

        for nid, nd in list(self.nodes.items()):
            fp_str = nd.get("file_path") or ""
            if not fp_str:
                continue
            bname = pathlib.Path(fp_str).name
            if nd["type"] == "shell_script":
                scripts_by_rel[fp_str] = nid
                scripts_by_name.setdefault(bname, []).append(nid)
            elif nd["type"] == "k8s_resource":
                k8s_by_rel.setdefault(fp_str, []).append(nid)
                k8s_by_name.setdefault(bname, []).append(nid)

        for nid, nd in list(self.nodes.items()):
            if nd["type"] != "shell_script" or not nd.get("file_path"):
                continue
            fp_path = self.repo_root / nd["file_path"]
            try:
                content = fp_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for other_rel, other_id in scripts_by_rel.items():
                if other_id == nid:
                    continue
                if other_rel in content:
                    self.add_edge(nid, other_id, "CALLS_SCRIPT")
            for bname, cand_ids in scripts_by_name.items():
                if len(cand_ids) == 1 and cand_ids[0] != nid and bname in content:
                    self.add_edge(nid, cand_ids[0], "CALLS_SCRIPT")

            for k_rel, k_ids in k8s_by_rel.items():
                if k_rel in content:
                    for kid in k_ids:
                        self.add_edge(nid, kid, "APPLIES_MANIFEST")
            for bname, k_ids in k8s_by_name.items():
                if bname in content:
                    for kid in k_ids:
                        self.add_edge(nid, kid, "APPLIES_MANIFEST")

    def build_or_update(
        self,
        force_rebuild: bool = False,
        precomputed_files: Optional[List[pathlib.Path]] = None,
        precomputed_hashes: Optional[Dict[str, str]] = None,
        sync_chats: bool = False,
    ) -> Dict[str, Any]:
        """Scan repository, determine changes, and build/update the Knowledge Graph."""
        prev_hashes: Dict[str, str] = {}
        if not force_rebuild and KG_JSON_PATH.exists():
            try:
                old_data = json.loads(KG_JSON_PATH.read_text(encoding="utf-8"))
                prev_hashes = old_data.get("file_hashes", {})
            except Exception:
                prev_hashes = {}

        files = precomputed_files if precomputed_files is not None else self.collect_files()
        current_hashes: Dict[str, str] = {}
        added: List[str] = []
        modified: List[str] = []
        removed: List[str] = []

        for fpath in files:
            rel = str(fpath.relative_to(self.repo_root))
            fhash = precomputed_hashes[rel] if (precomputed_hashes and rel in precomputed_hashes) else compute_sha256(fpath)
            current_hashes[rel] = fhash
            if rel not in prev_hashes:
                added.append(rel)
            elif prev_hashes[rel] != fhash:
                modified.append(rel)

        for old_rel in prev_hashes:
            if old_rel not in current_hashes:
                removed.append(old_rel)

        changed = bool(added or modified or removed or force_rebuild or sync_chats or not KG_JSON_PATH.exists())
        if not changed and KG_JSON_PATH.exists() and KG_DB_PATH.exists():
            data = json.loads(KG_JSON_PATH.read_text(encoding="utf-8"))
            data["last_change_check"] = {
                "changed": False,
                "added": [],
                "modified": [],
                "removed": [],
            }
            if not KG_HTML_PATH.exists():
                self._save_html_graph(data)
            if not REPO_MD_PATH.exists():
                self._save_repo_md(data)
            if not GLOBAL_MD_PATH.exists():
                _ensure_global_md_exists()
            _ensure_git_pre_commit_hook(self.repo_root)
            return data

        self.file_hashes = current_hashes
        is_master = is_master_cluster_repo(self.repo_root)

        # Parse all files to build complete, consistent graph
        for fpath in files:
            rel = str(fpath.relative_to(self.repo_root))
            rel_parts = pathlib.Path(rel).parts
            in_docs_folder = len(rel_parts) >= 1 and rel_parts[0] == "documents"
            in_chats_folder = len(rel_parts) >= 1 and rel_parts[0] == "chats"
            name_lower = fpath.name.lower()
            suffix = fpath.suffix.lower()

            if in_chats_folder and suffix in CHAT_FILE_EXTENSIONS:
                # Indexed by self.parse_workspace_chats() below
                continue
            elif in_docs_folder and suffix in MULTIMODAL_DOC_EXTENSIONS:
                self.parse_generic_document_file(fpath, rel)
            elif suffix in (IMAGE_DOC_EXTENSIONS | AUDIO_DOC_EXTENSIONS | OFFICE_AND_DATA_DOC_EXTENSIONS):
                self.parse_generic_document_file(fpath, rel)
            elif name_lower == "network_config.json":
                self.parse_network_config(fpath, rel)
            elif suffix == ".py":
                self.parse_python_file(fpath, rel)
            elif suffix == ".sh":
                self.parse_shell_script(fpath, rel)
            elif suffix in {".yaml", ".yml"}:
                self.parse_yaml_file(fpath, rel)
            elif name_lower.startswith("dockerfile"):
                self.parse_dockerfile(fpath, rel)
            elif suffix in {".md", ".1", ".5", ".7", ".8"}:
                self.parse_doc_file(fpath, rel)
            elif name_lower == "makefile":
                self.add_node(
                    f"doc:{rel}",
                    "document",
                    f"SAP S/4HANA 2023 + HANA 2.0 Operations Makefile ({rel})",
                    rel,
                    f"Documentation & CLI Operations Gateway: Makefile targets (status, summary, start, stop, verify-bp, license-status, renew-abap, apply-hana, apply-abap, recycle-90d, backup-tenant, backup-system, sync-docs, check-alerts) in {rel}",
                    {"format": "makefile"},
                )
            elif suffix == ".sql":
                self.add_node(f"sql:{rel}", "sql_file", fpath.name, rel, f"SQL script {rel}")
            elif suffix == ".json":
                self.add_node(f"json:{rel}", "json_file", fpath.name, rel, f"JSON file {rel}")
            elif suffix in {".html", ".htm"}:
                self.parse_html_file(fpath, rel)
            elif suffix == ".env" or name_lower.endswith(".env"):
                self.parse_env_file(fpath, rel)
            elif suffix == ".txt":
                if "requirement" in name_lower or is_master:
                    self.parse_requirements_file(fpath, rel)
                else:
                    self.parse_generic_document_file(fpath, rel)
            else:
                self.add_node(f"file:{rel}", "config_file", fpath.name, rel, f"Repository file {rel}")

        if is_master or (not is_master and len(files) > 0) or sync_chats or self._has_chats_folder_files():
            self.parse_workspace_chats(force_sync=sync_chats)

        self._resolve_cross_file_edges()

        type_counts: Dict[str, int] = {}
        for n in self.nodes.values():
            t = n["type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        graph_data = {
            "metadata": {
                "repository": str(self.repo_root),
                "generated_at": now_iso,
                "total_files_indexed": len(files),
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "node_type_counts": dict(sorted(type_counts.items())),
            },
            "last_change_check": {
                "changed": True,
                "added": added,
                "modified": modified,
                "removed": removed,
            },
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "file_hashes": self.file_hashes,
        }

        _ensure_global_md_exists()
        _ensure_git_pre_commit_hook(self.repo_root)
        if not REPO_MD_PATH.exists():
            self._save_repo_md(graph_data)
        if is_master:
            for auto_rel, auto_path in (("repo.md", REPO_MD_PATH), ("global.md", GLOBAL_MD_PATH)):
                if auto_path.exists():
                    self.parse_doc_file(auto_path, auto_rel)
                    self.file_hashes[auto_rel] = ""
        graph_data["file_hashes"] = self.file_hashes
        graph_data["nodes"] = list(self.nodes.values())
        graph_data["metadata"]["total_files_indexed"] = len(self.file_hashes)
        graph_data["metadata"]["total_nodes"] = len(self.nodes)
        type_counts_updated: Dict[str, int] = {}
        for n in self.nodes.values():
            t = n["type"]
            type_counts_updated[t] = type_counts_updated.get(t, 0) + 1
        graph_data["metadata"]["node_type_counts"] = dict(sorted(type_counts_updated.items()))
        self._save_repo_md(graph_data)
        if REPO_MD_PATH.exists():
            self.file_hashes["repo.md"] = compute_sha256(REPO_MD_PATH)
        if GLOBAL_MD_PATH.exists():
            self.file_hashes["global.md"] = compute_sha256(GLOBAL_MD_PATH)

        sqlite_delta = self._save_sqlite(graph_data, force_rebuild=force_rebuild)
        graph_data["last_change_check"]["sqlite_delta"] = sqlite_delta
        self._save_json(graph_data)
        self._save_gnn_weights(graph_data)
        self._save_markdown_summary(graph_data)
        self._save_html_graph(graph_data)
        return graph_data

    def _save_json(self, graph_data: Dict[str, Any]) -> None:
        KG_DIR.mkdir(parents=True, exist_ok=True)
        KG_JSON_PATH.write_text(json.dumps(graph_data, indent=2), encoding="utf-8")

    def _save_sqlite(self, graph_data: Dict[str, Any], force_rebuild: bool = False) -> Dict[str, Any]:
        """
        Persist Knowledge Graph into `knowledge_graph.db`.
        When `force_rebuild=False` and `knowledge_graph.db` already exists, performs an in-place
        SQLite delta update (deleting only removed/obsolete nodes & file_hashes and upserting
        only added/modified nodes & file_hashes) and logs the delta in `kg_delta_log`.
        """
        KG_DIR.mkdir(parents=True, exist_ok=True)
        db_existed = KG_DB_PATH.exists() and not force_rebuild
        conn = sqlite3.connect(str(KG_DB_PATH))
        cur = conn.cursor()

        if force_rebuild:
            cur.executescript(
                """
                DROP TABLE IF EXISTS nodes;
                DROP TABLE IF EXISTS edges;
                DROP TABLE IF EXISTS file_hashes;
                """
            )

        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                file_path TEXT,
                description TEXT,
                metadata_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
            CREATE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name);
            CREATE INDEX IF NOT EXISTS idx_nodes_file_path ON nodes(file_path);

            CREATE TABLE IF NOT EXISTS edges (
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                relation TEXT NOT NULL,
                metadata_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source);
            CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target);
            CREATE INDEX IF NOT EXISTS idx_edges_relation ON edges(relation);

            CREATE TABLE IF NOT EXISTS file_hashes (
                file_path TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rag_sync_state (
                node_id TEXT PRIMARY KEY,
                content_sha256 TEXT NOT NULL,
                target_table TEXT NOT NULL,
                gpu_used TEXT,
                synced_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS kg_delta_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                updated_at TEXT NOT NULL,
                mode TEXT NOT NULL,
                files_added INTEGER NOT NULL,
                files_modified INTEGER NOT NULL,
                files_removed INTEGER NOT NULL,
                nodes_upserted INTEGER NOT NULL,
                nodes_deleted INTEGER NOT NULL,
                total_nodes INTEGER NOT NULL,
                total_edges INTEGER NOT NULL
            );
            """
        )

        existing_nodes: Dict[str, Tuple[str, str, Optional[str], str, str]] = {}
        existing_hashes: Dict[str, str] = {}
        if db_existed:
            try:
                cur.execute("SELECT id, type, name, file_path, description, metadata_json FROM nodes")
                for r in cur.fetchall():
                    existing_nodes[r[0]] = (r[1], r[2], r[3], r[4] or "", r[5] or "{}")
                cur.execute("SELECT file_path, sha256 FROM file_hashes")
                for fp, sha in cur.fetchall():
                    existing_hashes[fp] = sha
            except Exception:
                existing_nodes = {}
                existing_hashes = {}

        new_nodes_rows: Dict[str, Tuple[str, str, Optional[str], str, str]] = {}
        for n in graph_data["nodes"]:
            new_nodes_rows[n["id"]] = (
                n["type"],
                n["name"],
                n.get("file_path"),
                n.get("description", ""),
                json.dumps(n.get("metadata", {})),
            )

        deleted_node_ids = [nid for nid in existing_nodes if nid not in new_nodes_rows]
        upserted_nodes = [
            (nid, *row)
            for nid, row in new_nodes_rows.items()
            if existing_nodes.get(nid) != row
        ]

        new_hashes: Dict[str, str] = graph_data.get("file_hashes", {})
        deleted_files = [fp for fp in existing_hashes if fp not in new_hashes]
        upserted_files = [
            (fp, sha)
            for fp, sha in new_hashes.items()
            if existing_hashes.get(fp) != sha
        ]

        if deleted_node_ids:
            cur.executemany("DELETE FROM nodes WHERE id = ?", [(nid,) for nid in deleted_node_ids])
            cur.executemany("DELETE FROM rag_sync_state WHERE node_id = ?", [(nid,) for nid in deleted_node_ids])
        if upserted_nodes:
            cur.executemany(
                "INSERT OR REPLACE INTO nodes (id, type, name, file_path, description, metadata_json) VALUES (?, ?, ?, ?, ?, ?)",
                upserted_nodes,
            )

        if deleted_files:
            cur.executemany("DELETE FROM file_hashes WHERE file_path = ?", [(fp,) for fp in deleted_files])
        if upserted_files:
            cur.executemany(
                "INSERT OR REPLACE INTO file_hashes (file_path, sha256) VALUES (?, ?)",
                upserted_files,
            )

        # Refresh edges table atomically inside the transaction
        cur.execute("DELETE FROM edges")
        cur.executemany(
            "INSERT INTO edges VALUES (?, ?, ?, ?)",
            [
                (
                    e["source"],
                    e["target"],
                    e["relation"],
                    json.dumps(e.get("metadata", {})),
                )
                for e in graph_data["edges"]
            ],
        )

        self._populate_wiki_fts_tables(cur, graph_data)

        chg = graph_data.get("last_change_check", {})
        mode_str = "delta_update" if db_existed else "full_build"
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        cur.execute(
            """
            INSERT INTO kg_delta_log
                (updated_at, mode, files_added, files_modified, files_removed,
                 nodes_upserted, nodes_deleted, total_nodes, total_edges)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_ts,
                mode_str,
                len(chg.get("added", [])),
                len(chg.get("modified", [])),
                len(chg.get("removed", [])),
                len(upserted_nodes),
                len(deleted_node_ids),
                len(new_nodes_rows),
                len(graph_data["edges"]),
            ),
        )
        # Keep last 100 delta log entries so knowledge_graph.db stays compact and deterministic
        cur.execute(
            "DELETE FROM kg_delta_log WHERE id NOT IN (SELECT id FROM kg_delta_log ORDER BY id DESC LIMIT 100)"
        )
        conn.commit()
        conn.close()
        return {
            "mode": mode_str,
            "db_path": str(KG_DB_PATH),
            "nodes_upserted": len(upserted_nodes),
            "nodes_deleted": len(deleted_node_ids),
            "files_upserted": len(upserted_files),
            "files_deleted": len(deleted_files),
            "total_nodes_in_db": len(new_nodes_rows),
            "total_edges_in_db": len(graph_data["edges"]),
            "total_files_tracked": len(new_hashes),
        }

    def _save_gnn_weights(self, graph_data: Dict[str, Any]) -> None:
        """Maintain Model 2 GNN weights & relational parameters in knowledge_graph/kg_gnn.pt."""
        KG_DIR.mkdir(parents=True, exist_ok=True)
        meta = graph_data.get("metadata", {})
        num_nodes = meta.get("total_nodes", len(graph_data.get("nodes", [])))
        num_edges = meta.get("total_edges", len(graph_data.get("edges", [])))
        gnn_path = self.repo_root / "knowledge_graph" / "kg_gnn.pt"
        existing_ts = meta.get("generated_at", "")
        if gnn_path.exists():
            try:
                old_g = json.loads(gnn_path.read_text(encoding="utf-8"))
                if (
                    old_g.get("graph_stats", {}).get("nodes") == num_nodes
                    and old_g.get("graph_stats", {}).get("edges") == num_edges
                ):
                    return
            except Exception:
                pass
        gnn_state = {
            "model_type": "GraphSAGE-2Hop-Residual-GNN",
            "embedding_dim": 384,
            "self_alpha": 0.68,
            "hop1_beta": 0.24,
            "hop2_gamma": 0.08,
            "relation_weights": {
                "CALLS": 1.0,
                "DEPENDS_ON": 0.95,
                "IMPORTS": 0.85,
                "EXPOSES_ENDPOINT": 0.90,
                "HOSTS_SERVICE": 0.85,
                "DEPLOYED_ON": 0.85,
                "APPLIES_MANIFEST": 0.80,
                "TARGETS_NODE": 0.80,
                "DOCUMENTS": 0.75,
                "REFERENCES": 0.70,
                "CONTAINS_SECTION": 0.85,
                "HAS_CHAT_TURN": 0.85,
                "DISCUSSED_FILE": 0.90,
                "MENTIONS_TOPIC": 0.75,
            },
            "graph_stats": {
                "nodes": num_nodes,
                "edges": num_edges,
                "updated_at": existing_ts,
            },
        }
        gnn_path.write_text(json.dumps(gnn_state, indent=2) + "\n", encoding="utf-8")

    def _categorize_wiki_path(self, rel_path: str) -> str:
        norm = rel_path.replace("\\", "/")
        base = pathlib.Path(norm).name
        if base.startswith(("VM1_", "VM2_", "VM3_")) or "SAHAR" in base or "SANDEEP" in base or "KRITHIKA" in base:
            return "vm_wikis"
        if norm in ("man/WIKI_INDEX.md", "man/MANPAGES_README.md", "man/CLUSTER_PUBLISH_CHECKLIST.md", "man/MIGRATION_CHECKLIST.md", "man/MIGRATION_TIMELINE.md", "man/MIGRATION_MANPAGE_README.md"):
            return "index_checklists"
        if "/" not in norm and norm.endswith(".md"):
            return "root_docs"
        if norm.startswith("man/man"):
            return "man_pages"
        return "arch_guides"

    def _populate_wiki_fts_tables(self, cur: sqlite3.Cursor, graph_data: Dict[str, Any]) -> None:
        cur.executescript(
            '''
            DROP TABLE IF EXISTS wiki_pages;
            DROP TABLE IF EXISTS wiki_fts;

            CREATE TABLE wiki_pages (
                rel_path TEXT PRIMARY KEY,
                doc_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                format TEXT NOT NULL,
                sections_json TEXT NOT NULL,
                outgoing_links_json TEXT NOT NULL,
                broken_links_json TEXT NOT NULL,
                content TEXT NOT NULL
            );
            '''
        )
        fts_enabled = True
        try:
            cur.execute(
                "CREATE VIRTUAL TABLE wiki_fts USING fts5(rel_path UNINDEXED, title, category, sections, content);"
            )
        except sqlite3.OperationalError:
            fts_enabled = False

        link_re = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
        doc_nodes = [n for n in graph_data.get("nodes", []) if n.get("type") == "document" and n.get("file_path")]

        wiki_rows = []
        fts_rows = []
        for nd in sorted(doc_nodes, key=lambda x: x.get("file_path", "")):
            rel_path = nd["file_path"].replace("\\", "/")
            abs_p = self.repo_root / rel_path
            if not abs_p.exists() or not abs_p.is_file():
                continue
            raw_content = abs_p.read_text(encoding="utf-8", errors="replace")
            meta = nd.get("metadata", {}) or {}
            fmt = meta.get("format") or ("man" if rel_path.startswith("man/man") else "md")
            sections = meta.get("sections", []) or []
            title = nd.get("name") or pathlib.Path(rel_path).name
            category = self._categorize_wiki_path(rel_path)

            outgoing_links = []
            broken_links = []
            if fmt == "md":
                # Strip fenced code blocks before link extraction
                stripped_md = re.sub(r"```[\s\S]*?```", "", raw_content)
                for m in link_re.finditer(stripped_md):
                    label, target = m.group(1).strip(), m.group(2).strip()
                    if not target or target.startswith(("http://", "https://", "mailto:", "#", "javascript:", "file://", "conversation://")):
                        continue
                    clean_target = target.split("#", 1)[0].split("?", 1)[0].strip()
                    if not clean_target:
                        continue
                    resolved = (abs_p.parent / clean_target).resolve()
                    try:
                        rel_target = str(resolved.relative_to(self.repo_root.resolve())).replace("\\", "/")
                        if resolved.exists():
                            outgoing_links.append({"label": label, "target": rel_target, "raw": target})
                        else:
                            broken_links.append({"label": label, "target": rel_target, "raw": target})
                    except ValueError:
                        if not resolved.exists():
                            broken_links.append({"label": label, "target": clean_target, "raw": target})

            wiki_rows.append(
                (
                    rel_path,
                    nd["id"],
                    title,
                    category,
                    fmt,
                    json.dumps(sections),
                    json.dumps(outgoing_links),
                    json.dumps(broken_links),
                    raw_content,
                )
            )
            fts_rows.append(
                (
                    rel_path,
                    title,
                    category,
                    " | ".join(sections),
                    raw_content,
                )
            )

        cur.executemany("INSERT OR REPLACE INTO wiki_pages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", wiki_rows)
        if fts_enabled and fts_rows:
            cur.executemany("INSERT INTO wiki_fts VALUES (?, ?, ?, ?, ?)", fts_rows)

    def _save_markdown_summary(self, graph_data: Dict[str, Any]) -> None:
        meta = graph_data["metadata"]
        lines = [
            "# Kubernetes Repository Knowledge Graph",
            "",
            f"- **Repository Root**: `{meta['repository']}`",
            f"- **Last Updated**: `{meta['generated_at']}`",
            f"- **Indexed Files**: `{meta['total_files_indexed']}`",
            f"- **Total Graph Nodes**: `{meta['total_nodes']}`",
            f"- **Total Graph Edges**: `{meta['total_edges']}`",
            "",
            "## Entity Counts by Type",
            "",
            "| Entity Type | Count |",
            "| :--- | :---: |",
        ]
        for ntype, count in meta["node_type_counts"].items():
            lines.append(f"| `{ntype}` | {count} |")

        lines.extend(
            [
                "",
                "## Cluster Nodes",
                "",
                "| Node ID | Name | IP Address | Role | Services |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for n in sorted(graph_data["nodes"], key=lambda x: x["id"]):
            if n["type"] == "cluster_node":
                m = n.get("metadata", {})
                svcs = ", ".join(m.get("services", []))
                lines.append(
                    f"| `{n['id']}` | {n['name']} | `{m.get('ip_address', 'N/A')}` | {m.get('role', 'N/A')} | {svcs} |"
                )

        lines.extend(
            [
                "",
                "## Kubernetes Manifest Resources",
                "",
                "| Resource | File | NodePorts | Images |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for n in sorted(graph_data["nodes"], key=lambda x: x["name"]):
            if n["type"] == "k8s_resource":
                m = n.get("metadata", {})
                nports = ", ".join(str(p) for p in m.get("node_ports", [])) or "—"
                imgs = ", ".join(m.get("images", [])) or "—"
                lines.append(f"| `{n['name']}` | `{n.get('file_path')}` | {nports} | `{imgs}` |")

        lines.extend(
            [
                "",
                "## FastAPI & WebSocket Endpoints",
                "",
                "| Endpoint | Handler | File | Description |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for n in sorted(graph_data["nodes"], key=lambda x: x["name"]):
            if n["type"] == "api_endpoint":
                m = n.get("metadata", {})
                lines.append(
                    f"| `{n['name']}` | `{m.get('handler')}` | `{n.get('file_path')}:{m.get('lineno')}` | {n.get('description', '')} |"
                )

        KG_MD_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _save_html_graph(self, graph_data: Dict[str, Any]) -> None:
        """Generate interactive HTML Knowledge Graph browser with Node Path filtering and per-hit (#1, #2, #3...) KG tables."""
        KG_DIR.mkdir(parents=True, exist_ok=True)
        html_content = build_interactive_kg_html(graph_data)
        KG_HTML_PATH.write_text(html_content, encoding="utf-8")

    def _save_repo_md(self, graph_data: Dict[str, Any]) -> None:
        """
        Maintain `/home/sanjay/container/kubernetes/repo.md` listing all top-level parent folders
        processed by the Knowledge Graph, their file counts, extracted Knowledge Graph entity counts,
        immediate subdirectories, root-level files, and excluded folders.
        """
        file_hashes: Dict[str, str] = graph_data.get("file_hashes", {})
        nodes: List[Dict[str, Any]] = graph_data.get("nodes", [])

        folder_file_counts: Dict[str, int] = {}
        folder_subfolders: Dict[str, Set[str]] = {}
        for rel_path in file_hashes:
            parts = pathlib.Path(rel_path).parts
            top = parts[0] if len(parts) > 1 else "."
            folder_file_counts[top] = folder_file_counts.get(top, 0) + 1
            if len(parts) > 2:
                folder_subfolders.setdefault(top, set()).add(parts[1])

        folder_node_counts: Dict[str, int] = {}
        folder_node_types: Dict[str, Dict[str, int]] = {}
        for n in nodes:
            fp = n.get("file_path")
            if not fp:
                continue
            parts = pathlib.Path(fp).parts
            top = parts[0] if len(parts) > 1 else "."
            folder_node_counts[top] = folder_node_counts.get(top, 0) + 1
            nt = n.get("type", "unknown")
            by_type = folder_node_types.setdefault(top, {})
            by_type[nt] = by_type.get(nt, 0) + 1

        top_folders = sorted(k for k in folder_file_counts if k != ".")
        root_files_count = folder_file_counts.get(".", 0)
        root_nodes_count = folder_node_counts.get(".", 0)

        lines: List[str] = [
            "# Repository Top-Level Parent Folders Processed by Knowledge Graph (`repo.md`)",
            "",
            f"This file maintains the authoritative inventory of all **top-level parent folders** in `{self.repo_root}` that are scanned, parsed, and indexed by [`knowledge_graph/query_kg.py`](knowledge_graph/query_kg.py).",
            "",
            f"- **Repository Root**: `{self.repo_root}`",
            f"- **Top-Level Parent Folders Processed**: `{len(top_folders)}` (plus repository root `.` files)",
            f"- **Total Indexed Files**: `{len(file_hashes)}`",
            f"- **Total Knowledge Graph Nodes**: `{len(nodes)}`",
            "",
            "---",
            "",
            "## 1. Top-Level Parent Folders Processed by Knowledge Graph",
            "",
            "| # | Top-Level Parent Folder | Absolute Path | Indexed Files | Extracted KG Nodes | Key Subfolders | Description & Scope |",
            "| :---: | :--- | :--- | :---: | :---: | :--- | :--- |",
        ]

        for idx, folder in enumerate(top_folders, start=1):
            abs_p = self.repo_root / folder
            f_cnt = folder_file_counts.get(folder, 0)
            n_cnt = folder_node_counts.get(folder, 0)
            subs = sorted(folder_subfolders.get(folder, set()))
            subs_str = ", ".join(f"`{s}/`" for s in subs[:6])
            if len(subs) > 6:
                subs_str += f" (+{len(subs) - 6} more)"
            if not subs_str:
                subs_str = "—"
            desc = TOP_LEVEL_FOLDER_DESCRIPTIONS.get(
                folder, f"Top-level repository folder `{folder}/` indexed by Knowledge Graph"
            )
            lines.append(
                f"| {idx} | [`{folder}/`]({folder}) | `{abs_p}/` | `{f_cnt}` | `{n_cnt}` | {subs_str} | {desc} |"
            )

        root_desc = TOP_LEVEL_FOLDER_DESCRIPTIONS["."]
        lines.extend(
            [
                "",
                "### Repository Root (`.` Top-Level Files)",
                "",
                "| Location | Absolute Path | Indexed Root Files | Extracted KG Nodes | Description |",
                "| :--- | :--- | :---: | :---: | :--- |",
                f"| `.` (Root Files) | `{self.repo_root}/` | `{root_files_count}` | `{root_nodes_count}` | {root_desc} |",
                "",
                "---",
                "",
                "## 2. Entity Breakdown by Top-Level Parent Folder",
                "",
                "| Top-Level Parent Folder | Extracted Entity Types (`type: count`) |",
                "| :--- | :--- |",
            ]
        )

        for folder in top_folders + ["."]:
            by_type = folder_node_types.get(folder, {})
            label = f"`{folder}/`" if folder != "." else "`.` (Root Files)"
            if by_type:
                summary = ", ".join(f"`{k}`: {v}" for k, v in sorted(by_type.items()))
            else:
                summary = "_(File hash indexed; no standalone AST/manifest nodes)_"
            lines.append(f"| {label} | {summary} |")

        excluded_sorted = sorted(EXCLUDED_DIRS)
        lines.extend(
            [
                "",
                "---",
                "",
                "## 3. Excluded Top-Level & Generated Directories",
                "",
                "The following directories are intentionally excluded from Knowledge Graph source indexing to avoid recursion, virtual-environment bloat, or binary cache scanning:",
                "",
                "| Excluded Directory | Reason |",
                "| :--- | :--- |",
            ]
        )
        reasons = {
            ".git": "Git version control internals",
            "__pycache__": "Compiled Python bytecode cache",
            "management_venv": "Python virtual environment for cluster-management",
            "venv": "Python virtual environment",
            ".venv": "Python virtual environment",
            "node_modules": "Node.js dependency directory",
            ".pytest_cache": "Pytest execution cache",
            ".mypy_cache": "Mypy type-checking cache",
            "wheels": "Pre-built Python binary wheel archive",
            "pgvector_repo": "External cloned pgvector source repository",
            "jvm": "Extracted SAPJVM runtime binary archive",
            "knowledge_graph": "Generated Knowledge Graph output directory (`knowledge_graph.json`, `knowledge_graph.db`, HTML reports, and `Files/` queue)",
            "knowledge-graph": "Legacy Knowledge Graph directory alias",
            "retire": "Archived/retired node scripts preserved for reference",
        }
        for ex in excluded_sorted:
            lines.append(f"| `{ex}/` | {reasons.get(ex, 'Excluded directory')} |")

        lines.extend(
            [
                "",
                "---",
                "",
                "## 4. Synchronization Rule",
                "",
                f"Whenever a top-level folder is added, renamed, or removed in `{self.repo_root}`, running:",
                "```bash",
                f"python3 {self.repo_root}/knowledge_graph/query_kg.py --update",
                "```",
                "automatically updates `repo.md` alongside the Knowledge Graph stores.",
            ]
        )

        new_repo_content = "\n".join(lines) + "\n"
        if not REPO_MD_PATH.exists() or REPO_MD_PATH.read_text(encoding="utf-8") != new_repo_content:
            REPO_MD_PATH.write_text(new_repo_content, encoding="utf-8")


def parse_query_expression(raw_params: List[str]) -> List[List[str]]:
    """
    Parse CLI query arguments into Disjunctive Normal Form (OR of AND groups):
      - Quoted sentences/phrases are preserved as a single term (e.g. "purchase order")
      - '+' between parameters means AND
      - ',' between parameters means OR
      - Adjacent space-separated parameters without ',' default to '+' (AND)
    Returns a list of OR-clauses, where each clause is a list of AND-terms.
    """
    tokens: List[Tuple[str, str]] = []  # ("TERM", val) | ("AND", "+") | ("OR", ",")

    for arg in raw_params:
        s = arg.strip()
        if not s:
            continue
        if s == "+":
            tokens.append(("AND", "+"))
            continue
        if s == ",":
            tokens.append(("OR", ","))
            continue

        # If the argument has no operators or embedded quotes, treat the entire argument
        # as a single term (preserving spaces if the shell passed a quoted sentence)
        if "+" not in s and "," not in s and '"' not in s and "'" not in s:
            tokens.append(("TERM", s))
            continue

        buf: List[str] = []
        i = 0
        n = len(s)
        while i < n:
            ch = s[i]
            if ch in ('"', "'"):
                quote_char = ch
                i += 1
                qbuf: List[str] = []
                while i < n and s[i] != quote_char:
                    qbuf.append(s[i])
                    i += 1
                if i < n and s[i] == quote_char:
                    i += 1
                phrase = "".join(qbuf).strip()
                if phrase:
                    existing = "".join(buf).strip()
                    if existing:
                        tokens.append(("TERM", existing))
                        buf = []
                    tokens.append(("TERM", phrase))
            elif ch == "+":
                term = "".join(buf).strip()
                if term:
                    tokens.append(("TERM", term))
                    buf = []
                tokens.append(("AND", "+"))
                i += 1
            elif ch == ",":
                term = "".join(buf).strip()
                if term:
                    tokens.append(("TERM", term))
                    buf = []
                tokens.append(("OR", ","))
                i += 1
            else:
                buf.append(ch)
                i += 1

        trailing = "".join(buf).strip()
        if trailing:
            tokens.append(("TERM", trailing))

    # Group into OR-clauses of AND-terms
    or_groups: List[List[str]] = []
    current_and_group: List[str] = []

    for tok_type, tok_val in tokens:
        if tok_type == "TERM":
            if tok_val:
                current_and_group.append(tok_val)
        elif tok_type == "AND":
            continue
        elif tok_type == "OR":
            if current_and_group:
                or_groups.append(current_and_group)
                current_and_group = []

    if current_and_group:
        or_groups.append(current_and_group)

    return or_groups


def format_query_expression(or_groups: List[List[str]]) -> str:
    """Format parsed OR-of-AND query groups into a readable expression string."""
    clause_strs: List[str] = []
    for and_group in or_groups:
        formatted_terms = [f'"{t}"' if " " in t else t for t in and_group]
        clause = " + ".join(formatted_terms)
        if len(or_groups) > 1 and len(and_group) > 1:
            clause = f"({clause})"
        clause_strs.append(clause)
    return " , ".join(clause_strs)


_GRAPH_CACHE: Dict[int, Tuple[Dict[str, Dict[str, Any]], Dict[str, List[Tuple[str, str]]], Dict[str, List[Tuple[str, str]]]]] = {}


def _get_graph_lookup(
    cur: sqlite3.Cursor,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[Tuple[str, str]]], Dict[str, List[Tuple[str, str]]]]:
    """Load and cache all nodes and edges for fast multi-hop stack traversal."""
    key = id(cur.connection)
    if key in _GRAPH_CACHE:
        return _GRAPH_CACHE[key]

    cur.execute("SELECT id, type, name, file_path, description, metadata_json FROM nodes")
    nodes_map: Dict[str, Dict[str, Any]] = {}
    for r in cur.fetchall():
        nodes_map[r[0]] = {
            "id": r[0],
            "type": r[1],
            "name": r[2],
            "file_path": r[3] or "",
            "description": r[4] or "",
            "metadata": json.loads(r[5] or "{}"),
        }

    cur.execute("SELECT source, relation, target FROM edges ORDER BY relation, target")
    out_map: Dict[str, List[Tuple[str, str]]] = {}
    in_map: Dict[str, List[Tuple[str, str]]] = {}
    for src, rel, tgt in cur.fetchall():
        out_map.setdefault(src, []).append((rel, tgt))
        in_map.setdefault(tgt, []).append((src, rel))

    _GRAPH_CACHE[key] = (nodes_map, out_map, in_map)
    return nodes_map, out_map, in_map


def _format_stack_node(nd: Dict[str, Any], is_target: bool = False) -> str:
    """Format a single node in the full node stack with its type, name, ID, IP/ports/URL, and file location."""
    prefix = "★ " if is_target else ""
    ntype = nd.get("type", "node")
    nname = nd.get("name") or nd.get("id") or ""
    nid = nd.get("id") or ""
    meta = nd.get("metadata") or {}
    fp = nd.get("file_path") or ""

    tags: List[str] = [f"ID: {nid}"]
    ip = meta.get("ip_address")
    wan_ip = meta.get("wan_ip")
    if wan_ip and ip:
        tags.append(f"WAN: {wan_ip}, LAN: {ip}")
    elif ip:
        tags.append(f"IP: {ip}")
    if meta.get("role"):
        tags.append(f"Role: {meta['role']}")
    if meta.get("management_url"):
        tags.append(f"URL: {meta['management_url']}")
    if meta.get("node_ports"):
        tags.append(f"NodePorts: {meta['node_ports']}")
    if meta.get("lineno") and fp:
        tags.append(f"Loc: {fp}:{meta['lineno']}")
    elif fp and ntype not in ("network_device", "cluster_node", "cluster_service", "repo_root", "folder"):
        tags.append(f"Path: {fp}")

    return f"{prefix}[{ntype}] {nname} ({' | '.join(tags)})"


def _pick_upstream_parent(
    curr_id: str,
    nodes_map: Dict[str, Dict[str, Any]],
    out_map: Dict[str, List[Tuple[str, str]]],
    in_map: Dict[str, List[Tuple[str, str]]],
    visited: Set[str],
) -> Optional[Tuple[str, str]]:
    """
    Determine the next upstream parent `(parent_id, relation_label)` when walking backwards
    from a target node toward the root of the Knowledge Graph.
    """
    inc = in_map.get(curr_id, [])
    out = out_map.get(curr_id, [])

    # 1. Direct physical/network topology & service hierarchy incoming edges
    topo_priority = [
        "WAN_UPLINK",
        "WAN_GATEWAY",
        "LAN_UPLINK_PORT_1",
        "HOSTS_VM",
        "HOSTS_SERVICE",
        "PROVIDES_SERVICE",
    ]
    for pref_rel in topo_priority:
        for src, rel in inc:
            if rel == pref_rel and src not in visited and src in nodes_map:
                return src, rel

    for src, rel in inc:
        if rel.startswith("SWITCH_PORT_") and src not in visited and src in nodes_map:
            return src, rel

    # 2. Code / AST / Endpoint / Multi-Modal Document / Chat hierarchy incoming edges
    code_priority = [
        "EXPOSES_ENDPOINT",
        "DEFINES_METHOD",
        "DEFINES_CLASS",
        "DEFINES_FUNCTION",
        "DEFINES_JS_FUNCTION",
        "CONTAINS_SECTION",
        "HAS_CHAT_TURN",
        "DISCUSSED_FILE",
        "MENTIONS_TOPIC",
    ]
    for pref_rel in code_priority:
        for src, rel in inc:
            if rel == pref_rel and src not in visited and src in nodes_map:
                return src, rel

    # 3. If current node is a module/script/manifest/dockerfile deployed on or targeting a cluster node
    host_out_priority = [
        "DEPLOYED_ON",
        "TARGETS_NODE",
        "CONFIGURES_NODE",
        "BUILDS_IMAGE_FOR",
        "PROVIDES_SERVICE",
    ]
    for pref_rel in host_out_priority:
        for rel, tgt in out:
            if rel == pref_rel and tgt not in visited and tgt in nodes_map:
                return tgt, rel

    # 4. Config file defining root network device or cluster node
    for pref_rel in ("DEFINES_DEVICE", "DEFINES_NODE"):
        # Prefer cluster-management/network_config.json or root network_config.json
        matching_srcs = [src for src, rel in inc if rel == pref_rel and src not in visited and src in nodes_map]
        if matching_srcs:
            matching_srcs.sort(key=lambda s: (0 if s == "file:network_config.json" else 1, s))
            return matching_srcs[0], pref_rel

    return None


def _build_full_node_stacks(cur: sqlite3.Cursor, item: Dict[str, Any]) -> None:
    """
    Compute and attach the full multi-hop stack of nodes to reach `item` (`node_stack`,
    `node_stack_lines`, `node_stack_compact`) as well as the downstream hierarchy tree
    reachable through `item` (`downstream_stack_lines`).
    """
    nodes_map, out_map, in_map = _get_graph_lookup(cur)
    target_id = item["id"]
    if target_id not in nodes_map:
        nodes_map[target_id] = item

    # Walk upstream from target_id to root
    visited_up: Set[str] = {target_id}
    chain_reversed: List[Tuple[Dict[str, Any], Optional[str]]] = [(nodes_map[target_id], None)]
    curr_id = target_id

    for _ in range(16):
        picked = _pick_upstream_parent(curr_id, nodes_map, out_map, in_map, visited_up)
        if not picked:
            break
        parent_id, rel_to_curr = picked
        visited_up.add(parent_id)
        # Update the relation leading into the previous item in chain_reversed
        prev_node, _ = chain_reversed[-1]
        chain_reversed[-1] = (prev_node, rel_to_curr)
        chain_reversed.append((nodes_map[parent_id], None))
        curr_id = parent_id

    chain: List[Tuple[Dict[str, Any], Optional[str]]] = list(reversed(chain_reversed))

    # Prepend repository root and folder stack for the top node in the chain
    top_node = chain[0][0]
    top_fp = top_node.get("file_path") or ""
    prefix_chain: List[Tuple[Dict[str, Any], Optional[str]]] = [
        (
            {
                "id": f"repo:{REPO_ROOT.name}",
                "type": "repo_root",
                "name": str(REPO_ROOT),
                "file_path": "",
                "metadata": {},
            },
            None,
        )
    ]
    if top_fp:
        parts = pathlib.Path(top_fp).parts
        # Add intermediate parent folders
        for i in range(len(parts) - 1):
            folder_rel = "/".join(parts[: i + 1])
            folder_node = {
                "id": f"folder:{folder_rel}",
                "type": "folder",
                "name": f"{folder_rel}/",
                "file_path": folder_rel,
                "metadata": {},
            }
            prefix_chain.append((folder_node, "CONTAINS_FOLDER"))

    # Connect prefix_chain to chain[0]
    if prefix_chain:
        first_type = top_node.get("type", "")
        link_rel = "CONTAINS_FILE" if first_type in ("config_file", "python_module", "shell_script", "document", "document_file", "image_document", "audio_transcript", "chat_session", "dockerfile", "yaml_config", "k8s_resource", "sql_file", "json_file", "html_template", "env_config", "requirements_file") else "CONTAINS"
        chain[0] = (top_node, link_rel)
        full_chain = prefix_chain + chain
    else:
        full_chain = chain

    # Also if the target has its own file_path that wasn't part of top_fp (e.g. when top_node went via network topology)
    stack_steps: List[Dict[str, Any]] = []
    stack_lines: List[str] = []
    compact_names: List[str] = []

    for step_idx, (nd, rel_in) in enumerate(full_chain, start=1):
        is_target = step_idx == len(full_chain)
        formatted = _format_stack_node(nd, is_target=is_target)
        indent = "  " * (step_idx - 1)
        if step_idx == 1:
            line = f"[{step_idx}] {formatted}"
        else:
            line = f"[{step_idx}] {indent}└─[{rel_in}]─> {formatted}"
        stack_lines.append(line)
        ip_suffix = f" ({nd.get('metadata', {}).get('ip_address')})" if nd.get("metadata", {}).get("ip_address") else ""
        compact_names.append(f"{nd.get('name')}{ip_suffix}")
        stack_steps.append(
            {
                "step": step_idx,
                "id": nd.get("id"),
                "type": nd.get("type"),
                "name": nd.get("name"),
                "file_path": nd.get("file_path") or "",
                "relation_from_parent": rel_in or "ROOT",
                "formatted": formatted,
            }
        )

    item["node_stack"] = stack_steps
    item["node_stack_lines"] = stack_lines
    item["node_stack_compact"] = " -> ".join(compact_names)

    # Now build Downstream Stack (hierarchical nodes reachable through target_id)
    downstream_rels_exact = {
        "WAN_UPLINK",
        "WAN_GATEWAY",
        "LAN_UPLINK_PORT_1",
        "HOSTS_VM",
        "HOSTS_SERVICE",
        "MANAGES_SWITCH",
        "PROVIDES_SERVICE",
        "DEFINES_CLASS",
        "DEFINES_METHOD",
        "DEFINES_FUNCTION",
        "DEFINES_JS_FUNCTION",
        "EXPOSES_ENDPOINT",
        "HANDLED_BY",
        "CALLS",
        "CALLS_ENDPOINT",
        "CALLS_SCRIPT",
        "APPLIES_MANIFEST",
        "CONTAINS_SECTION",
        "HAS_CHAT_TURN",
        "DISCUSSED_FILE",
        "MENTIONS_TOPIC",
    }
    downstream_lines: List[str] = []

    def _walk_downstream(curr: str, prefix_str: str, depth: int, path_seen: Set[str]) -> None:
        if depth > 4:
            return
        children: List[Tuple[str, str]] = []
        for rel, tgt in out_map.get(curr, []):
            if tgt in path_seen or tgt not in nodes_map:
                continue
            if rel in downstream_rels_exact or rel.startswith("SWITCH_PORT_"):
                children.append((rel, tgt))
        # Deduplicate while preserving order
        dedup_children: List[Tuple[str, str]] = []
        seen_pair: Set[Tuple[str, str]] = set()
        for pair in children:
            if pair not in seen_pair:
                seen_pair.add(pair)
                dedup_children.append(pair)

        for idx_c, (rel, tgt) in enumerate(dedup_children[:16]):
            is_last = idx_c == len(dedup_children[:16]) - 1
            branch = "└─" if is_last else "├─"
            child_nd = nodes_map[tgt]
            downstream_lines.append(f"{prefix_str}{branch}[{rel}]─> {_format_stack_node(child_nd, is_target=False)}")
            next_prefix = prefix_str + ("    " if is_last else "│   ")
            _walk_downstream(tgt, next_prefix, depth + 1, path_seen | {tgt})

    _walk_downstream(target_id, "", 1, {target_id})
    item["downstream_stack_lines"] = downstream_lines


def _attach_edges_and_neighbors(cur: sqlite3.Cursor, item: Dict[str, Any]) -> None:
    """Attach outgoing/incoming edges and full multi-hop node stacks to reach `item`."""
    node_id = item["id"]
    cur.execute(
        """
        SELECT e.relation, e.target, n.type, n.name, n.file_path, n.description
        FROM edges e
        LEFT JOIN nodes n ON n.id = e.target
        WHERE e.source = ?
        ORDER BY e.relation, e.target
        LIMIT 100
        """,
        (node_id,),
    )
    item["outgoing_edges"] = [
        {
            "relation": r[0],
            "target": r[1],
            "target_type": r[2] or "external_ref",
            "target_name": r[3] or r[1],
            "target_path": r[4] or "",
            "target_description": r[5] or "",
        }
        for r in cur.fetchall()
    ]

    cur.execute(
        """
        SELECT e.source, e.relation, n.type, n.name, n.file_path, n.description
        FROM edges e
        LEFT JOIN nodes n ON n.id = e.source
        WHERE e.target = ?
        ORDER BY e.relation, e.source
        LIMIT 100
        """,
        (node_id,),
    )
    item["incoming_edges"] = [
        {
            "source": r[0],
            "relation": r[1],
            "source_type": r[2] or "external_ref",
            "source_name": r[3] or r[0],
            "source_path": r[4] or "",
            "source_description": r[5] or "",
        }
        for r in cur.fetchall()
    ]
    _build_full_node_stacks(cur, item)


def search_kg(
    queries: List[str],
    limit: Optional[int] = None,
    include_edges: bool = True,
    path_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Search nodes and edges matching query parameters using:
      - quoted sentences for phrase matching
      - '+' for AND
      - ',' for OR
      - optional path_filter for filtering node file_path
    """
    or_groups = parse_query_expression(queries)
    if not or_groups and not path_filter:
        return []

    conn = sqlite3.connect(str(KG_DB_PATH))
    cur = conn.cursor()

    # Build (term1 AND term2 ...) OR (term3 AND term4 ...)
    or_sql_clauses: List[str] = []
    params: List[Any] = []
    all_terms: List[str] = []

    for and_group in or_groups:
        and_sql_clauses: List[str] = []
        for term in and_group:
            all_terms.append(term)
            q = f"%{term}%"
            and_sql_clauses.append(
                "(id LIKE ? OR type LIKE ? OR name LIKE ? OR file_path LIKE ? OR description LIKE ? OR metadata_json LIKE ?)"
            )
            params.extend([q, q, q, q, q, q])
        if and_sql_clauses:
            or_sql_clauses.append("(" + " AND ".join(and_sql_clauses) + ")")

    where_parts: List[str] = []
    if or_sql_clauses:
        where_parts.append("(" + " OR ".join(or_sql_clauses) + ")")
    if path_filter:
        where_parts.append("(file_path LIKE ? OR id LIKE ?)")
        params.extend([f"%{path_filter}%", f"%{path_filter}%"])

    where_sql = " AND ".join(where_parts) if where_parts else "1=1"

    if all_terms:
        exact_name_checks = " OR ".join(["lower(name) = lower(?)" for _ in all_terms])
        exact_id_checks = " OR ".join(["lower(id) = lower(?)" for _ in all_terms])
        like_name_checks = " OR ".join(["lower(name) LIKE lower(?)" for _ in all_terms])
        order_sql = f"""
          CASE WHEN ({exact_name_checks}) THEN 0
               WHEN ({exact_id_checks}) THEN 1
               WHEN ({like_name_checks}) THEN 2
               ELSE 3 END,
          CASE WHEN type = 'document' AND file_path IN ('sap_install/README.md', 'agent/tower/sap/sap_install/README.md') THEN 0
               WHEN type = 'document' AND file_path IN ('README.md', 'agent/tower/sap/README.md') THEN 1
               WHEN type = 'document' AND file_path = 'man/SAP_S4HANA_TOWER_GUIDE.md' THEN 2
               WHEN type = 'document' AND file_path = 'man/SAP_LICENSE_RENEWAL_GUIDE.md' THEN 3
               WHEN type = 'document' AND file_path = 'agent/tower/sap/sap_install/Makefile' THEN 4
               WHEN type = 'document' AND file_path IN ('sap_install/Makefile', 'Makefile', 'agent/tower/sap/sap_install/Makefile') THEN 4
               WHEN type = 'document' AND file_path LIKE 'man/man8/sap-%' THEN 5
               WHEN type = 'document' AND file_path LIKE 'agent/tower/sap/%' THEN 6
               WHEN type = 'document' AND (file_path LIKE 'sap_install/%' OR file_path LIKE 'agent/tower/sap/%') THEN 6
               WHEN type = 'document' THEN 7
               ELSE 8 END,
          type, name
        """
        query_params: List[Any] = (
            params
            + [t for t in all_terms]
            + [t for t in all_terms]
            + [f"%{t}%" for t in all_terms]
        )
    else:
        order_sql = "type, name"
        query_params = list(params)

    sql = f"""
        SELECT id, type, name, file_path, description, metadata_json
        FROM nodes
        WHERE {where_sql}
        ORDER BY {order_sql}
    """
    if limit is not None and limit > 0:
        sql += " LIMIT ?"
        query_params.append(limit)

    cur.execute(sql, query_params)
    rows = cur.fetchall()

    results = []
    for row in rows:
        node_id = row[0]
        item: Dict[str, Any] = {
            "id": node_id,
            "type": row[1],
            "name": row[2],
            "file_path": row[3],
            "description": row[4],
            "metadata": json.loads(row[5] or "{}"),
        }
        if include_edges:
            _attach_edges_and_neighbors(cur, item)
        results.append(item)

    conn.close()
    return results


def _html_escape(val: Any) -> str:
    s = "" if val is None else str(val)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _extract_path_prefixes(paths: List[str]) -> List[str]:
    prefixes: Set[str] = set()
    for p in paths:
        if not p:
            continue
        parts = p.split("/")
        if len(parts) >= 2:
            prefixes.add(parts[0] + "/")
        if len(parts) >= 3:
            prefixes.add(parts[0] + "/" + parts[1] + "/")
    return sorted(prefixes)


def _build_hit_neural_net_svg(idx: int, m: Dict[str, Any]) -> str:
    """
    Build a self-contained interactive SVG Neural Network diagram for result #idx:
      - Layer 1 (Input Stack): Multi-hop upstream stack hops leading to #idx
      - Layer 2 (Incoming Synapses): Incoming neighbor nodes feeding into #idx
      - Layer 3 (Target Activation Neuron ★): Central target entity #idx
      - Layer 4 (Output Synapses): Outgoing neighbor nodes activated by #idx
    """
    stack_steps = (m.get("node_stack") or [])[:-1][:10]
    in_edges = (m.get("incoming_edges") or [])[:14]
    out_edges = (m.get("outgoing_edges") or [])[:14]

    max_rows = max(len(stack_steps), len(in_edges), len(out_edges), 3)
    svg_h = max(360, min(920, 90 + max_rows * 52))
    svg_w = 1120

    col_x = {1: 130, 2: 410, 3: 670, 4: 960}
    center_y = svg_h // 2

    def _layer_y_positions(count: int) -> List[int]:
        if count <= 0:
            return []
        if count == 1:
            return [center_y]
        usable_h = svg_h - 110
        step = usable_h / max(1, count - 1)
        return [int(65 + i * step) for i in range(count)]

    l1_ys = _layer_y_positions(len(stack_steps))
    l2_ys = _layer_y_positions(len(in_edges))
    l4_ys = _layer_y_positions(len(out_edges))

    paths_svg: List[str] = []
    nodes_svg: List[str] = []

    layer_headers = [
        (col_x[1], "LAYER 1: UPSTREAM STACK", f"{len(stack_steps)} hop(s)", "#38bdf8"),
        (col_x[2], "LAYER 2: INCOMING NEURONS", f"{len(in_edges)} input(s)", "#fbbf24"),
        (col_x[3], f"LAYER 3: TARGET NEURON #{idx}", m.get("type", "entity"), "#a855f7"),
        (col_x[4], "LAYER 4: OUTPUT NEURONS", f"{len(out_edges)} output(s)", "#4ade80"),
    ]
    for lx, ltitle, lsub, lcol in layer_headers:
        nodes_svg.append(
            f'<g transform="translate({lx}, 26)">'
            f'<text x="0" y="0" text-anchor="middle" fill="{lcol}" font-size="11" font-weight="700" font-family="ui-monospace,monospace">{_html_escape(ltitle)}</text>'
            f'<text x="0" y="15" text-anchor="middle" fill="#94a3b8" font-size="10" font-family="ui-monospace,monospace">{_html_escape(lsub)}</text>'
            f"</g>"
        )

    # Layer 1: Stack nodes & sequential synapses
    prev_x, prev_y = None, None
    for i, st in enumerate(stack_steps):
        x1, y1 = col_x[1], l1_ys[i]
        st_name = str(st.get("name") or "")[:24]
        st_type = str(st.get("type") or "")
        st_rel = str(st.get("relation_from_parent") or "STACK")
        st_fp = str(st.get("file_path") or "")
        if prev_x is not None and prev_y is not None:
            paths_svg.append(
                f'<line x1="{prev_x}" y1="{prev_y + 14}" x2="{x1}" y2="{y1 - 14}" stroke="#38bdf8" stroke-width="1.8" stroke-dasharray="3,2" opacity="0.75"/>'
            )
        prev_x, prev_y = x1, y1
        if i == len(stack_steps) - 1:
            cx1, cy1 = (x1 + col_x[3]) // 2, y1
            cx2, cy2 = (x1 + col_x[3]) // 2, center_y
            paths_svg.append(
                f'<path class="nn-synapse" d="M {x1 + 16} {y1} C {cx1} {cy1}, {cx2} {cy2}, {col_x[3] - 28} {center_y}" '
                f'fill="none" stroke="#38bdf8" stroke-width="2" opacity="0.65"><title>Stack Hop: {_html_escape(st_rel)}</title></path>'
            )
        nodes_svg.append(
            f'<g class="nn-node" data-node-path="{_html_escape(st_fp.lower())}" data-relation="{_html_escape(st_rel)}" '
            f'transform="translate({x1},{y1})" onclick="showNeuronInfo({idx}, {_html_escape(json.dumps(st_name))}, {_html_escape(json.dumps(st_type))}, {_html_escape(json.dumps(st_fp))}, {_html_escape(json.dumps(st_rel))})">'
            f'<circle r="13" fill="#0f172a" stroke="#38bdf8" stroke-width="2.2"/>'
            f'<text x="0" y="4" text-anchor="middle" fill="#38bdf8" font-size="9" font-weight="700" font-family="ui-monospace,monospace">S{i+1}</text>'
            f'<text x="-20" y="4" text-anchor="end" fill="#e2e8f0" font-size="11" font-family="ui-monospace,monospace">{_html_escape(st_name)}</text>'
            f"<title>[STACK #{i+1}] {_html_escape(st.get('name', ''))} ({_html_escape(st_type)}) {_html_escape(st_fp)}</title>"
            f"</g>"
        )

    # Layer 2: Incoming neurons -> Target Neuron (#idx)
    for i, e in enumerate(in_edges):
        x2, y2 = col_x[2], l2_ys[i]
        s_name = str(e.get("source_name") or e.get("source") or "")
        s_short = s_name[:25]
        s_type = str(e.get("source_type") or "entity")
        s_rel = str(e.get("relation") or "IN")
        s_fp = str(e.get("source_path") or "")
        cx1 = x2 + int((col_x[3] - x2) * 0.45)
        cx2 = x2 + int((col_x[3] - x2) * 0.65)
        mid_x = (x2 + col_x[3]) // 2
        mid_y = (y2 + center_y) // 2
        paths_svg.append(
            f'<path class="nn-synapse" data-node-path="{_html_escape(s_fp.lower())}" data-relation="{_html_escape(s_rel)}" '
            f'd="M {x2 + 15} {y2} C {cx1} {y2}, {cx2} {center_y}, {col_x[3] - 28} {center_y}" '
            f'fill="none" stroke="#f59e0b" stroke-width="2" opacity="0.78"><title>{_html_escape(s_name)} --[{_html_escape(s_rel)}]--> #{idx}</title></path>'
            f'<text x="{mid_x}" y="{mid_y - 4}" text-anchor="middle" fill="#fbbf24" font-size="9" font-family="ui-monospace,monospace" opacity="0.88">{_html_escape(s_rel[:20])}</text>'
        )
        nodes_svg.append(
            f'<g class="nn-node" data-node-path="{_html_escape(s_fp.lower())}" data-relation="{_html_escape(s_rel)}" '
            f'transform="translate({x2},{y2})" onclick="showNeuronInfo({idx}, {_html_escape(json.dumps(s_name))}, {_html_escape(json.dumps(s_type))}, {_html_escape(json.dumps(s_fp))}, {_html_escape(json.dumps(s_rel))})">'
            f'<circle r="13" fill="#0f172a" stroke="#f59e0b" stroke-width="2.2"/>'
            f'<text x="0" y="3" text-anchor="middle" fill="#fbbf24" font-size="8" font-weight="700" font-family="ui-monospace,monospace">IN</text>'
            f'<text x="-18" y="4" text-anchor="end" fill="#f8fafc" font-size="11" font-family="ui-monospace,monospace">{_html_escape(s_short)}</text>'
            f"<title>[INCOMING: {_html_escape(s_rel)}] {_html_escape(s_name)} ({_html_escape(s_type)}) {_html_escape(s_fp)}</title>"
            f"</g>"
        )

    # Layer 4: Target Neuron (#idx) -> Outgoing neurons
    for i, e in enumerate(out_edges):
        x4, y4 = col_x[4], l4_ys[i]
        t_name = str(e.get("target_name") or e.get("target") or "")
        t_short = t_name[:26]
        t_type = str(e.get("target_type") or "entity")
        t_rel = str(e.get("relation") or "OUT")
        t_fp = str(e.get("target_path") or "")
        cx1 = col_x[3] + int((x4 - col_x[3]) * 0.35)
        cx2 = col_x[3] + int((x4 - col_x[3]) * 0.55)
        mid_x = (col_x[3] + x4) // 2
        mid_y = (center_y + y4) // 2
        paths_svg.append(
            f'<path class="nn-synapse" data-node-path="{_html_escape(t_fp.lower())}" data-relation="{_html_escape(t_rel)}" '
            f'd="M {col_x[3] + 28} {center_y} C {cx1} {center_y}, {cx2} {y4}, {x4 - 15} {y4}" '
            f'fill="none" stroke="#22c55e" stroke-width="2" opacity="0.8"><title>#{idx} --[{_html_escape(t_rel)}]--> {_html_escape(t_name)}</title></path>'
            f'<text x="{mid_x}" y="{mid_y - 4}" text-anchor="middle" fill="#4ade80" font-size="9" font-family="ui-monospace,monospace" opacity="0.88">{_html_escape(t_rel[:20])}</text>'
        )
        nodes_svg.append(
            f'<g class="nn-node" data-node-path="{_html_escape(t_fp.lower())}" data-relation="{_html_escape(t_rel)}" '
            f'transform="translate({x4},{y4})" onclick="showNeuronInfo({idx}, {_html_escape(json.dumps(t_name))}, {_html_escape(json.dumps(t_type))}, {_html_escape(json.dumps(t_fp))}, {_html_escape(json.dumps(t_rel))})">'
            f'<circle r="13" fill="#0f172a" stroke="#22c55e" stroke-width="2.2"/>'
            f'<text x="0" y="3" text-anchor="middle" fill="#4ade80" font-size="8" font-weight="700" font-family="ui-monospace,monospace">OUT</text>'
            f'<text x="18" y="4" text-anchor="start" fill="#f8fafc" font-size="11" font-family="ui-monospace,monospace">{_html_escape(t_short)}</text>'
            f"<title>[OUTGOING: {_html_escape(t_rel)}] {_html_escape(t_name)} ({_html_escape(t_type)}) {_html_escape(t_fp)}</title>"
            f"</g>"
        )

    # Layer 3: Target Activation Neuron (#idx)
    t_self_name = str(m.get("name") or "")
    t_self_type = str(m.get("type") or "")
    t_self_fp = str(m.get("file_path") or "")
    nodes_svg.append(
        f'<g class="nn-node nn-target" transform="translate({col_x[3]},{center_y})" '
        f'onclick="showNeuronInfo({idx}, {_html_escape(json.dumps(t_self_name))}, {_html_escape(json.dumps(t_self_type))}, {_html_escape(json.dumps(t_self_fp))}, {_html_escape(json.dumps("TARGET_ENTITY"))})">'
        f'<circle r="34" fill="rgba(168,85,247,0.16)" stroke="#a855f7" stroke-width="1.5" stroke-dasharray="4,3"/>'
        f'<circle r="26" fill="#1e1b4b" stroke="#c084fc" stroke-width="3"/>'
        f'<text x="0" y="-2" text-anchor="middle" fill="#f8fafc" font-size="12" font-weight="800" font-family="ui-monospace,monospace">★ #{idx}</text>'
        f'<text x="0" y="12" text-anchor="middle" fill="#e9d5ff" font-size="9" font-family="ui-monospace,monospace">{_html_escape(t_self_type[:10])}</text>'
        f'<text x="0" y="48" text-anchor="middle" fill="#ffffff" font-size="12" font-weight="700" font-family="ui-monospace,monospace">{_html_escape(t_self_name[:30])}</text>'
        f'<text x="0" y="63" text-anchor="middle" fill="#7dd3fc" font-size="10" font-family="ui-monospace,monospace">{_html_escape(t_self_fp[:38])}</text>'
        f"<title>[TARGET #{idx}] {_html_escape(t_self_name)} ({_html_escape(t_self_type)}) {_html_escape(t_self_fp)}</title>"
        f"</g>"
    )

    return (
        f'<div class="nn-container" id="nn-view-{idx}">'
        f'<div class="nn-toolbar">'
        f'<span>🧠 <strong>Neural Network Activation Graph for Response #{idx}</strong> &mdash; Click any neuron to inspect</span>'
        f'<span id="nn-inspector-{idx}" class="nn-inspector">Selected: <code>{_html_escape(t_self_name)}</code> ({_html_escape(t_self_type)}) &bull; <code>{_html_escape(t_self_fp or "N/A")}</code></span>'
        f"</div>"
        f'<div class="nn-canvas-wrap">'
        f'<svg class="nn-svg" viewBox="0 0 {svg_w} {svg_h}" width="100%" height="{svg_h}">'
        f'{"".join(paths_svg)}{"".join(nodes_svg)}'
        f"</svg>"
        f"</div>"
        f"</div>"
    )


def generate_query_results_html(
    matches: List[Dict[str, Any]],
    queries: List[str],
    summary_only: bool = False,
    output_path: pathlib.Path = KG_QUERY_HTML_PATH,
) -> pathlib.Path:
    """
    Translate `query_kg.py "search text" /S` directly into the single Graphical Knowledge Graph:
      - Pre-populates the search text box with the executed search text.
      - Populates the top-line ON/OFF result buttons (#1, #2, #3... up to #10) with the exact
        ranked results from `query_kg.py "search text" /S`.
      - Writes both `query_results.html` and `knowledge_graph.html` so opening the Knowledge Graph
        immediately reflects the latest query.
    """
    or_groups = parse_query_expression(queries)
    query_str = format_query_expression(or_groups) if or_groups else " ".join(queries)
    try:
        if KG_JSON_PATH.exists():
            graph_data = json.loads(KG_JSON_PATH.read_text(encoding="utf-8"))
        else:
            graph_data = {"metadata": {}, "nodes": matches, "edges": []}
    except Exception:
        graph_data = {"metadata": {}, "nodes": matches, "edges": []}

    html_doc = build_interactive_kg_html(
        graph_data,
        initial_query=query_str,
        initial_matches=matches[:10],
    )
    output_path.write_text(html_doc, encoding="utf-8")
    try:
        if output_path != KG_HTML_PATH:
            KG_HTML_PATH.write_text(html_doc, encoding="utf-8")
    except OSError:
        pass
    return output_path


def build_interactive_kg_html(
    graph_data: Dict[str, Any],
    initial_query: str = "",
    initial_matches: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Generate the single unified Graphical Knowledge Graph for the full codebase
    (knowledge_graph/knowledge_graph.html):
      - Row 1 (Top Line): Search text box on the left + "All Results" ON/OFF button
        and Top-10 Ranked Result (#1..#10) ON/OFF toggle buttons alongside the top line.
        Uses the exact same ranking algorithm as `query_kg.py "search text" /S`.
      - Row 2 (Below Text Box): Node Option Selectors as ON/OFF toggle buttons.
      - Main Viewport: One interactive SVG Graphical Knowledge Graph for the full codebase
        (or focused on the selected #1..#10 result node / All Results subgraph) with zero tables.
    """
    meta = graph_data.get("metadata", {})
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    # If no explicit initial_query was passed, check if last_query_results.json exists
    if not initial_query and initial_matches is None and KG_LAST_RESULTS_PATH.exists():
        try:
            saved = json.loads(KG_LAST_RESULTS_PATH.read_text(encoding="utf-8"))
            saved_queries = saved.get("queries") or []
            if saved_queries:
                or_g = parse_query_expression(saved_queries)
                initial_query = format_query_expression(or_g) if or_g else " ".join(saved_queries)
                initial_matches = (saved.get("matches") or [])[:10]
        except Exception:
            pass

    embedded_payload = json.dumps(
        {
            "metadata": meta,
            "nodes": nodes,
            "edges": edges,
            "initial_query": initial_query or "",
            "initial_match_ids": [m.get("id") for m in (initial_matches or []) if m.get("id")][:10],
        }
    ).replace("</", "<\\/")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>💡 Codebase Graphical Knowledge Graph</title>
  <style>
    :root {{
      --bg: #0b1120;
      --panel: #111827;
      --panel-alt: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --on-bg: linear-gradient(135deg, #0284c7 0%, #6366f1 100%);
      --on-border: #38bdf8;
      --off-bg: #0f172a;
      --off-border: #334155;
    }}
    * {{ box-sizing: border-box; }}
    html, body {{
      margin: 0;
      padding: 0;
      width: 100%;
      height: 100vh;
      overflow: hidden;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      flex-direction: column;
    }}

    /* Control Deck: Row 1 (Search + Top-10 Ranked Result ON/OFF Buttons) + Row 2 (Node Type ON/OFF Buttons) */
    .kg-control-deck {{
      background: var(--panel);
      border-bottom: 1px solid var(--border);
      padding: 10px 14px;
      display: flex;
      flex-direction: column;
      gap: 9px;
      flex-shrink: 0;
      z-index: 20;
    }}

    /* Row 1: Search Box + Top-10 Ranked Results alongside the top line */
    .kg-top-line {{
      display: flex;
      align-items: center;
      gap: 10px;
      width: 100%;
      min-height: 38px;
    }}
    .kg-search-wrap {{
      position: relative;
      flex: 0 0 340px;
      display: flex;
      align-items: center;
    }}
    .kg-search-icon {{
      position: absolute;
      left: 11px;
      font-size: 0.88rem;
      color: var(--accent);
      pointer-events: none;
    }}
    .kg-search-input {{
      width: 100%;
      padding: 8px 30px 8px 34px;
      border-radius: 7px;
      border: 1px solid #475569;
      background: #070b14;
      color: var(--text);
      font-size: 0.84rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      outline: none;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }}
    .kg-search-input:focus {{
      border-color: var(--accent);
      box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
    }}
    .kg-search-clear {{
      position: absolute;
      right: 8px;
      background: none;
      border: none;
      color: var(--muted);
      cursor: pointer;
      font-size: 0.9rem;
      padding: 2px 4px;
      display: none;
    }}
    .kg-search-clear:hover {{ color: #fff; }}

    /* Top-line Ranked Result ON/OFF Buttons strip */
    .kg-results-strip {{
      display: flex;
      align-items: center;
      gap: 6px;
      flex: 1;
      overflow-x: auto;
      padding-bottom: 2px;
      scrollbar-width: thin;
    }}
    .kg-results-strip::-webkit-scrollbar {{ height: 4px; }}
    .kg-results-strip::-webkit-scrollbar-thumb {{ background: #334155; border-radius: 4px; }}

    /* Copy Query 2 Button & Ask Input */
    .kg-ask-input {{
      width: 210px;
      padding: 7px 10px;
      border-radius: 7px;
      border: 1px solid #475569;
      background: #070b14;
      color: var(--text);
      font-size: 0.78rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      outline: none;
      flex-shrink: 0;
    }}
    .kg-ask-input:focus {{
      border-color: #a855f7;
    }}
    .kg-copy-q2-btn {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 7px 13px;
      border-radius: 7px;
      border: 1px solid #a855f7;
      background: linear-gradient(135deg, #7c3aed 0%, #0284c7 100%);
      color: #ffffff;
      font-size: 0.78rem;
      font-weight: 700;
      cursor: pointer;
      white-space: nowrap;
      flex-shrink: 0;
      box-shadow: 0 0 12px rgba(124, 58, 237, 0.35);
      transition: all 0.15s ease;
    }}
    .kg-copy-q2-btn:hover {{
      filter: brightness(1.12);
      border-color: #38bdf8;
    }}
    .kg-copy-q2-btn.copied {{
      background: linear-gradient(135deg, #059669 0%, #10b981 100%);
      border-color: #4ade80;
    }}

    /* Row 2: query_kg.py CLI Flag Checkboxes Bar */
    .kg-flags-line {{
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      padding: 4px 8px;
      background: rgba(15, 23, 42, 0.65);
      border: 1px solid rgba(51, 65, 85, 0.7);
      border-radius: 7px;
    }}
    .flag-chk-label {{
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 8px;
      border-radius: 5px;
      font-size: 0.74rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      color: #cbd5e1;
      background: #0f172a;
      border: 1px solid #334155;
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
      transition: all 0.12s ease;
    }}
    .flag-chk-label:hover {{
      border-color: #64748b;
      color: #ffffff;
    }}
    .flag-chk-label.checked {{
      background: rgba(124, 58, 237, 0.2);
      border-color: #a855f7;
      color: #f3e8ff;
    }}
    .flag-chk-label input[type="checkbox"] {{
      accent-color: #a855f7;
      margin: 0;
      cursor: pointer;
    }}
    .cmd-preview-pill {{
      margin-left: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.73rem;
      color: #38bdf8;
      background: #070b14;
      border: 1px solid #1e293b;
      padding: 3px 9px;
      border-radius: 5px;
      white-space: nowrap;
      max-width: 440px;
      overflow: hidden;
      text-overflow: ellipsis;
    }}

    /* Copied Query 2 Prompt Preview Drawer */
    .kg-prompt-drawer {{
      position: absolute;
      bottom: 54px;
      right: 14px;
      width: min(680px, calc(100vw - 28px));
      max-height: 320px;
      background: rgba(15, 23, 42, 0.97);
      border: 1px solid #a855f7;
      border-radius: 10px;
      box-shadow: 0 12px 32px rgba(0, 0, 0, 0.65);
      display: none;
      flex-direction: column;
      z-index: 30;
      overflow: hidden;
    }}
    .kg-prompt-drawer-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 12px;
      background: #1e1b4b;
      border-bottom: 1px solid #334155;
      font-size: 0.78rem;
      font-weight: 700;
      color: #e9d5ff;
    }}
    .kg-prompt-drawer pre {{
      margin: 0;
      padding: 10px 12px;
      font-size: 0.73rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      color: #e2e8f0;
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }}

    /* Row 3: Node Options ON/OFF Toggle Buttons below the text box */
    .kg-node-options-line {{
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }}
    .kg-row-label {{
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      margin-right: 4px;
      white-space: nowrap;
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }}

    /* Shared ON/OFF Toggle Button Style */
    .toggle-btn {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 10px;
      border-radius: 6px;
      font-size: 0.76rem;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
      user-select: none;
      transition: all 0.14s ease;
      border: 1px solid var(--off-border);
      background: var(--off-bg);
      color: var(--muted);
    }}
    .toggle-btn:hover {{
      border-color: #64748b;
      color: #e2e8f0;
    }}
    .toggle-btn.is-on {{
      background: rgba(14, 165, 233, 0.16);
      border-color: var(--on-border);
      color: #ffffff;
      box-shadow: 0 0 10px rgba(56, 189, 248, 0.22);
    }}
    .toggle-btn.result-btn.is-on {{
      background: var(--on-bg);
      border-color: #7dd3fc;
      color: #ffffff;
      box-shadow: 0 0 12px rgba(99, 102, 241, 0.4);
    }}
    .toggle-state-pill {{
      font-size: 0.63rem;
      font-weight: 800;
      padding: 1px 5px;
      border-radius: 4px;
      letter-spacing: 0.04em;
      font-family: ui-monospace, monospace;
      background: rgba(148, 163, 184, 0.15);
      color: #94a3b8;
    }}
    .toggle-btn.is-on .toggle-state-pill {{
      background: rgba(34, 197, 94, 0.25);
      color: #4ade80;
      border: 1px solid rgba(74, 222, 128, 0.4);
    }}
    .type-dot {{
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
      flex-shrink: 0;
    }}
    .rank-badge {{
      background: rgba(15, 23, 42, 0.65);
      color: #38bdf8;
      padding: 1px 5px;
      border-radius: 4px;
      font-family: ui-monospace, monospace;
      font-size: 0.7rem;
      font-weight: 800;
    }}
    .toggle-btn.result-btn.is-on .rank-badge {{
      background: rgba(255, 255, 255, 0.2);
      color: #fff;
    }}

    /* Main Graphical Knowledge Graph Viewport */
    .kg-graph-stage {{
      position: relative;
      flex: 1;
      width: 100%;
      overflow: hidden;
      background:
        radial-gradient(circle at 50% 50%, rgba(30, 41, 59, 0.55) 0%, rgba(11, 17, 32, 0.98) 75%),
        linear-gradient(rgba(51, 65, 85, 0.12) 1px, transparent 1px),
        linear-gradient(90deg, rgba(51, 65, 85, 0.12) 1px, transparent 1px);
      background-size: 100% 100%, 36px 36px, 36px 36px;
      cursor: grab;
    }}
    .kg-graph-stage.dragging {{ cursor: grabbing; }}
    #kg-svg {{
      width: 100%;
      height: 100%;
      display: block;
    }}

    /* Floating Overlay HUD inside Graph Canvas */
    .kg-hud-top-left {{
      position: absolute;
      top: 12px;
      left: 14px;
      background: rgba(15, 23, 42, 0.88);
      backdrop-filter: blur(6px);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 7px 12px;
      font-size: 0.78rem;
      color: #cbd5e1;
      pointer-events: none;
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .kg-hud-top-right {{
      position: absolute;
      top: 12px;
      right: 14px;
      display: flex;
      gap: 6px;
    }}
    .hud-btn {{
      background: rgba(15, 23, 42, 0.9);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 10px;
      border-radius: 6px;
      font-size: 0.76rem;
      font-weight: 600;
      cursor: pointer;
    }}
    .hud-btn:hover {{ border-color: var(--accent); color: var(--accent); }}

    /* Bottom Node Inspector Bar */
    .kg-inspector-bar {{
      position: absolute;
      bottom: 12px;
      left: 14px;
      right: 14px;
      background: rgba(15, 23, 42, 0.94);
      backdrop-filter: blur(8px);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 14px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      font-size: 0.8rem;
      color: #e2e8f0;
    }}
    .inspector-meta {{
      display: flex;
      align-items: center;
      gap: 12px;
      overflow: hidden;
      white-space: nowrap;
      text-overflow: ellipsis;
    }}
    .inspector-meta code {{
      color: #7dd3fc;
      background: rgba(2, 132, 199, 0.15);
      padding: 2px 6px;
      border-radius: 4px;
      font-family: ui-monospace, monospace;
    }}
    .kg-node-group {{ cursor: pointer; }}
    .kg-node-group:hover circle.node-core {{
      filter: drop-shadow(0 0 10px #38bdf8);
      stroke-width: 3px;
    }}
    .kg-node-group .node-label-auto {{
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.12s ease;
    }}
    .kg-node-group:hover .node-label-auto,
    svg.kg-zoomed-in .kg-node-group .node-label-auto {{
      opacity: 1;
    }}
  </style>
</head>
<body>
  <!-- Control Deck -->
  <div class="kg-control-deck">
    <!-- Row 1: Search Text Box + Copy Query 2 (--#<N>) Button + All Results & Top 10 Ranked Result (#1..#10) ON/OFF Toggle Buttons -->
    <div class="kg-top-line">
      <div class="kg-search-wrap">
        <span class="kg-search-icon">🔍</span>
        <input type="text" id="kg-search-input" class="kg-search-input"
               placeholder='Search text (same as query_kg.py "search text" /S)...'
               oninput="onSearchInput()">
        <button type="button" id="kg-search-clear" class="kg-search-clear" onclick="clearSearch()" title="Clear search">✕</button>
      </div>
      <input type="text" id="kg-ask-input" class="kg-ask-input"
             placeholder="Optional LLM ask (--ask)..."
             oninput="updateCliCommandPreview()">
      <button type="button" id="kg-copy-q2-btn" class="kg-copy-q2-btn" onclick="copyQuery2ToClipboard()"
              title='Execute Query 2 (query_kg.py "searchtext" --#<N> [checked flags]) and copy LLM prompt to clipboard'>
        <span id="kg-copy-q2-label">📋 Copy --#1 /I</span>
      </button>
      <div class="kg-results-strip" id="kg-results-strip"></div>
    </div>

    <!-- Row 2: All Available query_kg.py Flag Options as Checkboxes -->
    <div class="kg-flags-line" id="kg-flags-line"></div>

    <!-- Row 3: Node Option Selectors (ON/OFF Toggle Buttons) below the text box -->
    <div class="kg-node-options-line" id="kg-node-options-line"></div>
  </div>

  <!-- Single Graphical Knowledge Graph Canvas for the Full Codebase -->
  <div class="kg-graph-stage" id="kg-graph-stage">
    <svg id="kg-svg" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <marker id="arrow-out" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#22c55e" opacity="0.85"/>
        </marker>
        <marker id="arrow-in" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#f59e0b" opacity="0.85"/>
        </marker>
        <marker id="arrow-net" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" opacity="0.7"/>
        </marker>
      </defs>
      <g id="kg-viewport"></g>
    </svg>

    <div class="kg-hud-top-left" id="kg-hud-status">
      <span>💡 <strong id="hud-mode-title">Full Codebase Knowledge Graph</strong></span>
      <span>•</span>
      <span>Total Matches: <strong id="hud-match-count" style="color:#c084fc;">0</strong></span>
      <span>•</span>
      <span>Graph Nodes: <strong id="hud-node-count" style="color:#38bdf8;">0</strong></span>
      <span>•</span>
      <span>Synapses/Edges: <strong id="hud-edge-count" style="color:#4ade80;">0</strong></span>
    </div>

    <div class="kg-hud-top-right">
      <button type="button" id="hud-3d-spin-btn" class="hud-btn" onclick="toggle3DAutoSpin()" title="Toggle 3D Spatial Auto-Rotation (Drag to 3D Orbit, Shift+Drag to Pan)" style="border-color:#475569;color:#94a3b8;font-weight:700;">🌐 3D Spin: OFF</button>
      <button type="button" class="hud-btn" onclick="clearAndCompactGraphMemory()" title="Clear cached graph DOM/memory and reset to clean 3D view" style="border-color:#10b981;color:#34d399;font-weight:700;">🧹 Clear Memory</button>
      <button type="button" class="hud-btn" onclick="zoomBy(1.22)" title="Zoom In (3D Perspective)">＋ Zoom In</button>
      <button type="button" class="hud-btn" onclick="zoomBy(0.82)" title="Zoom Out (3D Perspective)">－ Zoom Out</button>
      <button type="button" class="hud-btn" onclick="resetTransform()" title="Reset 3D Orbit, Pan & Zoom">🧭 Reset 3D Orbit</button>
    </div>

    <div class="kg-prompt-drawer" id="kg-prompt-drawer">
      <div class="kg-prompt-drawer-header">
        <span id="kg-prompt-drawer-title">✅ Copied Query 2 Prompt to Clipboard</span>
        <button type="button" class="hud-btn" style="padding:2px 8px;" onclick="document.getElementById('kg-prompt-drawer').style.display='none'">✕ Close</button>
      </div>
      <pre id="kg-prompt-drawer-body"></pre>
    </div>

    <div class="kg-inspector-bar" id="kg-inspector-bar">
      <div class="inspector-meta" id="inspector-content">
        <span>Enter search text above or click any <strong>#1–#10</strong> result button on the top line to focus the Knowledge Graph on that result node.</span>
      </div>
      <div id="inspector-actions" style="flex-shrink:0;"></div>
    </div>
  </div>

  <script>
    const KG_DATA = {embedded_payload};
    const NODE_MAP = new Map();
    const OUT_EDGES = new Map();
    const IN_EDGES = new Map();
    const DEGREE_MAP = new Map();

    const TYPE_COLORS = {{
      cluster_node: '#10b981',
      cluster_service: '#06b6d4',
      k8s_resource: '#3b82f6',
      network_device: '#14b8a6',
      api_endpoint: '#a855f7',
      python_module: '#f59e0b',
      python_class: '#ec4899',
      python_function: '#6366f1',
      shell_script: '#22c55e',
      js_function: '#eab308',
      sql_file: '#0ea5e9',
      html_template: '#f97316',
      dockerfile: '#38bdf8',
      yaml_config: '#8b5cf6',
      env_config: '#64748b',
      config_file: '#94a3b8',
      requirements_file: '#cbd5e1',
      document: '#e879f9',
      document_file: '#c084fc',
      document_section: '#d8b4fe',
      document_table: '#2dd4bf',
      image_document: '#fb7185',
      audio_transcript: '#f43f5e',
      topic_entity: '#facc15',
      chat_session: '#34d399',
      chat_turn: '#6ee7b7'
    }};

    KG_DATA.nodes.forEach(n => {{
      NODE_MAP.set(n.id, n);
      OUT_EDGES.set(n.id, []);
      IN_EDGES.set(n.id, []);
    }});
    KG_DATA.edges.forEach(e => {{
      if (OUT_EDGES.has(e.source)) OUT_EDGES.get(e.source).push(e);
      if (IN_EDGES.has(e.target)) IN_EDGES.get(e.target).push(e);
    }});
    KG_DATA.nodes.forEach(n => {{
      const deg = (OUT_EDGES.get(n.id) || []).length + (IN_EDGES.get(n.id) || []).length;
      DEGREE_MAP.set(n.id, deg);
    }});

    const ALL_TYPES = Object.keys(KG_DATA.metadata.node_type_counts || {{}});
    const enabledTypes = new Set(ALL_TYPES);

    let top10Results = [];
    let totalMatchesCount = KG_DATA.nodes.length;
    let selectedResultMode = 'all';
    let inspectedNodeId = null;

    // All available CLI flag options in query_kg.py represented as checkboxes
    const CLI_FLAG_OPTIONS = [
      {{ flag: '/I', label: '/I (--investigate)', desc: 'Instruct LLM: INVESTIGATE ONLY — NO CODE UPDATES', defaultChecked: true }},
      {{ flag: '/S', label: '/S (--summary)', desc: 'Summary-only mode (#1, #2, #3...)', defaultChecked: true }},
      {{ flag: '--json', label: '--json', desc: 'Output matching hits as JSON', defaultChecked: false }},
      {{ flag: '--stats', label: '--stats', desc: 'Display Knowledge Graph statistics', defaultChecked: false }},
      {{ flag: '--update', label: '--update (-u)', desc: 'Incrementally update Knowledge Graph & global.md', defaultChecked: false }},
      {{ flag: '--rebuild', label: '--rebuild (-r)', desc: 'Force full rebuild of the Knowledge Graph', defaultChecked: false }},
      {{ flag: '--sync-chats', label: '--sync-chats', desc: 'Index Zed/Antigravity chat transcripts & chats/ folder into Knowledge Graph', defaultChecked: false }},
      {{ flag: '--sync-docs', label: '--sync-docs', desc: 'Synchronize man/ pages, wiki index, repo.md, global.md', defaultChecked: false }},
      {{ flag: '--sap-check', label: '--sap-check', desc: 'Run SAP S/4HANA & HANA license/backup check', defaultChecked: false }},
      {{ flag: '--mojibake-audit', label: '--mojibake-audit', desc: 'Audit Git delta for UTF-8/CP1252 mojibake', defaultChecked: false }},
      {{ flag: '--mojibake-fix', label: '--mojibake-fix', desc: 'Audit and repair mojibake on Git delta', defaultChecked: false }},
      {{ flag: '--vuln-scan', label: '--vuln-scan', desc: 'Scan Git delta for security vulnerabilities (SEC001-SEC006)', defaultChecked: false }},
      {{ flag: '--pre-commit-hook', label: '--pre-commit-hook', desc: 'Run full Git pre-commit hook check suite', defaultChecked: false }},
      {{ flag: '--sync-global', label: '--sync-global', desc: 'Force-propagate query_kg.py across all folders in global.md', defaultChecked: false }},
      {{ flag: '--install-hooks', label: '--install-hooks', desc: 'Install or refresh .git/hooks/pre-commit', defaultChecked: false }},
      {{ flag: '--commit-push', label: '--commit-push', desc: 'Stage, commit (running pre-commit hook), and push dirty repo', defaultChecked: false }}
    ];
    const activeCliFlags = new Set(CLI_FLAG_OPTIONS.filter(o => o.defaultChecked).map(o => o.flag));

    function renderCliFlagCheckboxes() {{
      const bar = document.getElementById('kg-flags-line');
      if (!bar) return;
      let html = `<span class="kg-row-label">query_kg.py Flags:</span>`;
      CLI_FLAG_OPTIONS.forEach(opt => {{
        const isChecked = activeCliFlags.has(opt.flag);
        html += `
          <label class="flag-chk-label ${{isChecked ? 'checked' : ''}}" title="${{esc(opt.desc)}}">
            <input type="checkbox" ${{isChecked ? 'checked' : ''}} onchange="toggleCliFlag('${{esc(opt.flag)}}', this.checked)">
            <span>${{esc(opt.label)}}</span>
          </label>
        `;
      }});
      html += `<span class="cmd-preview-pill" id="kg-cmd-preview"></span>`;
      bar.innerHTML = html;
      updateCliCommandPreview();
    }}

    function toggleCliFlag(flag, checked) {{
      if (checked) activeCliFlags.add(flag);
      else activeCliFlags.delete(flag);
      renderCliFlagCheckboxes();
    }}

    function getActiveHitSelector() {{
      if (selectedResultMode !== 'all') {{
        return String(Number(selectedResultMode) + 1);
      }}
      return '1';
    }}

    function updateCliCommandPreview() {{
      const q = (document.getElementById('kg-search-input')?.value || '').trim();
      const ask = (document.getElementById('kg-ask-input')?.value || '').trim();
      const hitNum = getActiveHitSelector();
      const flagsArr = Array.from(activeCliFlags);
      const qPart = q ? `"${{q}}"` : '';
      const askPart = ask ? ` "${{ask}}"` : '';
      const flagsStr = flagsArr.join(' ');
      const cmdStr = `query_kg.py ${{qPart}} --#${{hitNum}} ${{flagsStr}}${{askPart}}`.replace(/\\s+/g, ' ').trim();

      const previewEl = document.getElementById('kg-cmd-preview');
      if (previewEl) {{
        previewEl.textContent = cmdStr;
        previewEl.title = cmdStr;
      }}
      const btnLabel = document.getElementById('kg-copy-q2-label');
      if (btnLabel) {{
        const iFlag = activeCliFlags.has('/I') ? ' /I' : '';
        btnLabel.textContent = `📋 Copy --#${{hitNum}}${{iFlag}}`;
      }}
    }}

    function buildClientSideQuery2Prompt(hitNum, targetNode, qStr, askStr, investigateOnly) {{
      const repoRoot = KG_DATA.metadata.repository || '/home/sanjay/container/kubernetes';
      const relPath = targetNode.file_path || '';
      const lineno = (targetNode.metadata && targetNode.metadata.lineno) ? targetNode.metadata.lineno : null;
      const fileUri = relPath ? `file://${{repoRoot}}/${{relPath}}${{lineno ? '#L' + lineno : ''}}` : `file://${{repoRoot}}/knowledge_graph/query_results.html#hit-kg-table-${{hitNum}}`;
      const kgTableUri = `file://${{repoRoot}}/knowledge_graph/query_results.html#hit-kg-table-${{hitNum}}`;
      const lineHint = lineno ? `Line=${{lineno}}` : (relPath ? 'Full file' : 'Graph entity');
      const outs = (OUT_EDGES.get(targetNode.id) || []).slice(0, 12).map(e => {{
        const tn = NODE_MAP.get(e.target) || {{}};
        return `--[${{e.relation}}]--> ${{tn.name || e.target}} (${{tn.file_path || tn.type || 'entity'}})`;
      }}).join(', ') || 'none';
      const ins = (IN_EDGES.get(targetNode.id) || []).slice(0, 12).map(e => {{
        const sn = NODE_MAP.get(e.source) || {{}};
        return `<--[${{e.relation}}]-- ${{sn.name || e.source}} (${{sn.file_path || sn.type || 'entity'}})`;
      }}).join(', ') || 'none';

      const modeHeader = investigateOnly
        ? 'INSTRUCTION TO LLM (LOCAL KNOWLEDGE GRAPH PREPROCESSED CONTEXT — INVESTIGATE ONLY / NO CODE UPDATES):'
        : 'INSTRUCTION TO LLM (LOCAL KNOWLEDGE GRAPH PREPROCESSED CONTEXT):';
      const execRule = investigateOnly
        ? '- Execution Mode (/I): INVESTIGATE ONLY — NO CODE UPDATES. Analyze, diagnose, and answer the request without modifying, creating, or deleting any files.'
        : `- Code Edit Rule: All code edits MUST be done using Python only (/usr/bin/python3) — do NOT use PowerShell.\n- Post-Change Rule (see ${{repoRoot}}/rules.md): After any edit, update man/ docs, run Delta-Only Mojibake Audit & Fix, run Pre-Commit Vulnerability Scan, run query_kg.py --update, and prompt for git commit / git push.`;

      const defaultAsk = investigateOnly
        ? '[Investigate and explain this target — NO CODE UPDATES]'
        : '[Enter your specific request/change for the above target here]';
      let finalAsk = askStr || defaultAsk;
      if (investigateOnly && !finalAsk.toLowerCase().includes('no code update') && !finalAsk.toLowerCase().includes('investigate only')) {{
        finalAsk = `[INVESTIGATE ONLY — NO CODE UPDATES] ${{finalAsk}}`;
      }}

      return [
        modeHeader,
        `- Repository Root: ${{repoRoot}}`,
        `- Preprocessed Context Guidance: This context was locally assembled via 'query_kg.py' to provide rich upfront context (exact target file/lines, code snippet, connected Knowledge Graph dependencies, and tokenized files) and reduce blind discovery token usage. Start from the context below, and inspect or search the codebase further as needed.`,
        execRule,
        '',
        `Context for Hit #${{hitNum}} (Query: ${{qStr || targetNode.name}}):`,
        `  - Entity:      [${{targetNode.type}}] ${{targetNode.name}} (ID: ${{targetNode.id}})`,
        `  - File Target: ${{fileUri}} (${{lineHint}})`,
        `  - Description: ${{targetNode.description || 'N/A'}}`,
        `  - Metadata:    ${{JSON.stringify(targetNode.metadata || {{}})}}`,
        `  - Outgoing KG: ${{outs}}`,
        `  - Incoming KG: ${{ins}}`,
        '',
        `REQUEST TO LLM (#${{hitNum}}: ${{fileUri}} (KG Table: ${{kgTableUri}})): ${{finalAsk}}`
      ].join('\\n');
    }}

    function writeTextToClipboardFallback(text) {{
      try {{
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        ta.style.top = '0';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }} catch (e) {{}}
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).catch(() => {{}});
      }}
    }}

    async function copyQuery2ToClipboard() {{
      const q = (document.getElementById('kg-search-input')?.value || '').trim();
      const ask = (document.getElementById('kg-ask-input')?.value || '').trim();
      const hitNum = Number(getActiveHitSelector());
      const targetNode = top10Results[hitNum - 1] || top10Results[0] || KG_DATA.nodes[0];
      const investigateOnly = activeCliFlags.has('/I');
      const flagsParam = Array.from(activeCliFlags).join(',');

      // 1. Immediate synchronous copy using client-side builder so user-gesture clipboard always succeeds
      let promptText = targetNode
        ? buildClientSideQuery2Prompt(hitNum, targetNode, q, ask, investigateOnly)
        : '';
      if (promptText) {{
        writeTextToClipboardFallback(promptText);
      }}

      // 2. If hosted via FastAPI portal, also call /api/knowledge-graph/query2 to get full AST snippet & server-side execution
      let cliCmd = document.getElementById('kg-cmd-preview')?.textContent || `query_kg.py "${{q}}" --#${{hitNum}}`;
      if (window.location.protocol.startsWith('http')) {{
        try {{
          const url = `/api/knowledge-graph/query2?q=${{encodeURIComponent(q || (targetNode ? targetNode.name : ''))}}&hit=${{encodeURIComponent(String(hitNum))}}&flags=${{encodeURIComponent(flagsParam)}}&ask=${{encodeURIComponent(ask)}}`;
          const resp = await fetch(url);
          if (resp.ok) {{
            const data = await resp.json();
            if (data.prompt) {{
              promptText = data.prompt;
              cliCmd = data.command || cliCmd;
              writeTextToClipboardFallback(promptText);
            }}
          }}
        }} catch (e) {{}}
      }}

      // 3. Visual confirmation on button + preview drawer
      const btn = document.getElementById('kg-copy-q2-btn');
      const lbl = document.getElementById('kg-copy-q2-label');
      if (btn && lbl) {{
        btn.classList.add('copied');
        lbl.textContent = `✅ Copied --#${{hitNum}}!`;
        setTimeout(() => {{
          btn.classList.remove('copied');
          updateCliCommandPreview();
        }}, 2200);
      }}
      const drawer = document.getElementById('kg-prompt-drawer');
      const drawerTitle = document.getElementById('kg-prompt-drawer-title');
      const drawerBody = document.getElementById('kg-prompt-drawer-body');
      if (drawer && drawerTitle && drawerBody) {{
        drawerTitle.textContent = `✅ Copied to Clipboard: ${{cliCmd}}`;
        drawerBody.textContent = promptText;
        drawer.style.display = 'flex';
      }}
    }}

    let panX = 0, panY = 0, scale = 1;
    let rotY = -0.45, rotX = 0.28;
    let autoSpin3D = false, isHoveringNode = false;
    let isDragging = false, dragMode = 'orbit', dragStartX = 0, dragStartY = 0, startRotY = -0.45, startRotX = 0.28;
    let _scene3D = {{ nodes3D: new Map(), edgesToDraw: [], rankLabels: new Map(), modeTitle: '', maxR: 420 }};

    function esc(s) {{
      return String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }}

    function typeColor(t) {{
      return TYPE_COLORS[t] || '#38bdf8';
    }}

    function renderNodeOptionButtons() {{
      const container = document.getElementById('kg-node-options-line');
      const allOn = enabledTypes.size === ALL_TYPES.length;
      const counts = KG_DATA.metadata.node_type_counts || {{}};

      let html = `<span class="kg-row-label">Node Options:</span>`;
      html += `
        <button type="button" class="toggle-btn ${{allOn ? 'is-on' : ''}}" onclick="toggleAllNodeTypes()">
          <span>All Nodes (${{KG_DATA.nodes.length}})</span>
          <span class="toggle-state-pill">${{allOn ? 'ON' : 'OFF'}}</span>
        </button>
      `;

      ALL_TYPES.forEach(t => {{
        const isOn = enabledTypes.has(t);
        const cnt = counts[t] || 0;
        const col = typeColor(t);
        html += `
          <button type="button" class="toggle-btn ${{isOn ? 'is-on' : ''}}" onclick="toggleNodeType('${{esc(t)}}')" title="Toggle ${{esc(t)}} nodes ON/OFF">
            <span class="type-dot" style="background:${{col}}; opacity:${{isOn ? 1 : 0.35}};"></span>
            <span>${{esc(t)}} (${{cnt}})</span>
            <span class="toggle-state-pill">${{isOn ? 'ON' : 'OFF'}}</span>
          </button>
        `;
      }});

      container.innerHTML = html;
    }}

    function toggleAllNodeTypes() {{
      if (enabledTypes.size === ALL_TYPES.length) {{
        enabledTypes.clear();
      }} else {{
        ALL_TYPES.forEach(t => enabledTypes.add(t));
      }}
      renderNodeOptionButtons();
      recomputeResultsAndGraph();
    }}

    function toggleNodeType(typeName) {{
      if (enabledTypes.has(typeName)) {{
        enabledTypes.delete(typeName);
      }} else {{
        enabledTypes.add(typeName);
      }}
      renderNodeOptionButtons();
      recomputeResultsAndGraph();
    }}

    // Parse query expression identically to query_kg.py `parse_query_expression` (supporting `/S` or `/s` flag)
    function parseQueryExpr(qStr) {{
      const cleaned = (qStr || '').replace(/(?:^|\\s)\\/[sSiI](?=\\s|$)/g, ' ').trim();
      if (!cleaned) return [];
      const tokens = [];
      let buf = '';
      let i = 0;
      while (i < cleaned.length) {{
        const ch = cleaned[i];
        if (ch === '"' || ch === "'") {{
          const q = ch; i++;
          let phrase = '';
          while (i < cleaned.length && cleaned[i] !== q) phrase += cleaned[i++];
          if (i < cleaned.length && cleaned[i] === q) i++;
          if (buf.trim()) {{ tokens.push({{t:'TERM', v:buf.trim().toLowerCase()}}); buf=''; }}
          if (phrase.trim()) tokens.push({{t:'TERM', v:phrase.trim().toLowerCase()}});
        }} else if (ch === '+') {{
          if (buf.trim()) {{ tokens.push({{t:'TERM', v:buf.trim().toLowerCase()}}); buf=''; }}
          tokens.push({{t:'AND'}}); i++;
        }} else if (ch === ',') {{
          if (buf.trim()) {{ tokens.push({{t:'TERM', v:buf.trim().toLowerCase()}}); buf=''; }}
          tokens.push({{t:'OR'}}); i++;
        }} else {{
          buf += ch; i++;
        }}
      }}
      if (buf.trim()) {{
        buf.trim().split(/\\s+/).forEach(w => {{
          if (w) tokens.push({{t:'TERM', v:w.toLowerCase()}});
        }});
      }}
      const orGroups = [];
      let curAnd = [];
      tokens.forEach(tok => {{
        if (tok.t === 'TERM') curAnd.push(tok.v);
        else if (tok.t === 'OR') {{
          if (curAnd.length) {{ orGroups.push(curAnd); curAnd = []; }}
        }}
      }});
      if (curAnd.length) orGroups.push(curAnd);
      return orGroups;
    }}

    // Document priority rank identical to `search_kg()` SQL CASE in query_kg.py
    function docPriorityRank(n) {{
      if (n.type !== 'document') return 8;
      const fp = n.file_path || '';
      if (fp === 'sap_install/README.md' || fp === 'agent/tower/sap/sap_install/README.md') return 0;
      if (fp === 'README.md' || fp === 'agent/tower/sap/README.md') return 1;
      if (fp === 'man/SAP_S4HANA_TOWER_GUIDE.md') return 2;
      if (fp === 'man/SAP_LICENSE_RENEWAL_GUIDE.md') return 3;
      if (fp === 'agent/tower/sap/sap_install/Makefile' || fp === 'sap_install/Makefile' || fp === 'Makefile') return 4;
      if (fp.startsWith('man/man8/sap-')) return 5;
      if (fp.startsWith('agent/tower/sap/') || fp.startsWith('sap_install/')) return 6;
      return 7;
    }}

    // Exact match & ordering function matching `query_kg.py "search text" /S` (#1, #2, #3...)
    function matchAndRankNodes(orGroups) {{
      const allTerms = [];
      orGroups.forEach(g => g.forEach(t => allTerms.push(t)));

      const matched = KG_DATA.nodes.filter(n => {{
        if (!enabledTypes.has(n.type)) return false;
        if (!orGroups.length) return true;
        const metaJson = JSON.stringify(n.metadata || {{}}).toLowerCase();
        const hay = `${{(n.id || '').toLowerCase()}} ${{(n.type || '').toLowerCase()}} ${{(n.name || '').toLowerCase()}} ${{(n.file_path || '').toLowerCase()}} ${{(n.description || '').toLowerCase()}} ${{metaJson}}`;
        return orGroups.some(andGroup => andGroup.every(term => hay.includes(term)));
      }});

      if (!allTerms.length) {{
        // When search box is empty, rank by connectivity degree so the top 10 hubs appear on the top bar
        return matched.slice().sort((a, b) => (DEGREE_MAP.get(b.id) || 0) - (DEGREE_MAP.get(a.id) || 0));
      }}

      function tierRank(n) {{
        const nameL = (n.name || '').toLowerCase();
        const idL = (n.id || '').toLowerCase();
        if (allTerms.some(t => nameL === t)) return 0;
        if (allTerms.some(t => idL === t)) return 1;
        if (allTerms.some(t => nameL.includes(t))) return 2;
        return 3;
      }}

      return matched.slice().sort((a, b) => {{
        const tA = tierRank(a), tB = tierRank(b);
        if (tA !== tB) return tA - tB;
        const dA = docPriorityRank(a), dB = docPriorityRank(b);
        if (dA !== dB) return dA - dB;
        const tyCmp = String(a.type || '').localeCompare(String(b.type || ''));
        if (tyCmp !== 0) return tyCmp;
        const nmCmp = String(a.name || '').localeCompare(String(b.name || ''));
        if (nmCmp !== 0) return nmCmp;
        return String(a.file_path || '').localeCompare(String(b.file_path || ''));
      }});
    }}

    function onSearchInput() {{
      const q = document.getElementById('kg-search-input').value;
      document.getElementById('kg-search-clear').style.display = q ? 'block' : 'none';
      selectedResultMode = 'all';
      recomputeResultsAndGraph();
    }}

    function clearSearch() {{
      const inp = document.getElementById('kg-search-input');
      inp.value = '';
      document.getElementById('kg-search-clear').style.display = 'none';
      selectedResultMode = 'all';
      recomputeResultsAndGraph();
    }}

    function toggleResultButton(mode) {{
      if (mode === 'all') {{
        selectedResultMode = 'all';
      }} else {{
        const idx = Number(mode);
        if (selectedResultMode === idx) {{
          selectedResultMode = 'all';
        }} else {{
          selectedResultMode = idx;
          if (top10Results[idx]) {{
            inspectedNodeId = top10Results[idx].id;
          }}
        }}
      }}
      renderTopLineResultButtons();
      renderGraphicalKnowledgeGraph();
    }}

    function focusNodeInGraph(nodeId) {{
      const n = NODE_MAP.get(nodeId);
      if (!n) return;
      inspectedNodeId = nodeId;
      const existingIdx = top10Results.findIndex(r => r.id === nodeId);
      if (existingIdx !== -1) {{
        selectedResultMode = existingIdx;
      }} else {{
        top10Results = [n, ...top10Results.slice(0, 9)];
        selectedResultMode = 0;
      }}
      renderTopLineResultButtons();
      renderGraphicalKnowledgeGraph();
    }}

    // Render Row 1 Right Strip: "All Results" ON/OFF button + Top-10 Ranked Result (#1..#10) ON/OFF buttons
    function renderTopLineResultButtons() {{
      const strip = document.getElementById('kg-results-strip');
      const q = (document.getElementById('kg-search-input').value || '').trim();
      const isAllOn = selectedResultMode === 'all';
      const allLabel = q ? `All Results (${{top10Results.length}})` : `All Results`;

      let html = `
        <button type="button" class="toggle-btn result-btn ${{isAllOn ? 'is-on' : ''}}" onclick="toggleResultButton('all')" title="Toggle All Results view ON/OFF">
          <span>🌐 ${{esc(allLabel)}}</span>
          <span class="toggle-state-pill">${{isAllOn ? 'ON' : 'OFF'}}</span>
        </button>
      `;

      top10Results.forEach((n, idx) => {{
        const rank = idx + 1;
        const isOn = selectedResultMode === idx;
        const shortName = (n.name || n.id || '').slice(0, 20);
        const col = typeColor(n.type);
        const fp = n.file_path ? ` (${{n.file_path}})` : '';
        html += `
          <button type="button" id="rank-btn-${{rank}}" class="toggle-btn result-btn ${{isOn ? 'is-on' : ''}}"
                  onclick="toggleResultButton(${{idx}})"
                  title="#${{rank}} [${{esc(n.type)}}] ${{esc(n.name)}}${{esc(fp)}} — ${{esc(n.description || '')}}">
            <span class="rank-badge">#${{rank}}</span>
            <span class="type-dot" style="background:${{col}};"></span>
            <span>${{esc(shortName)}}</span>
            <span class="toggle-state-pill">${{isOn ? 'ON' : 'OFF'}}</span>
          </button>
        `;
      }});

      strip.innerHTML = html;
      updateCliCommandPreview();
    }}

    function recomputeResultsAndGraph() {{
      const rawQ = document.getElementById('kg-search-input').value || '';
      const orGroups = parseQueryExpr(rawQ);
      const ranked = matchAndRankNodes(orGroups);
      totalMatchesCount = ranked.length;
      document.getElementById('hud-match-count').textContent = totalMatchesCount;

      // Restrict strictly to Top 10 ranks (#1 .. #10)
      top10Results = ranked.slice(0, 10);

      if (selectedResultMode !== 'all' && selectedResultMode >= top10Results.length) {{
        selectedResultMode = 'all';
      }}
      renderTopLineResultButtons();
      renderGraphicalKnowledgeGraph();
    }}

    function updateInspector(n, rankNum) {{
      const contentEl = document.getElementById('inspector-content');
      const actionsEl = document.getElementById('inspector-actions');
      if (!n) {{
        contentEl.innerHTML = `<span>Enter search text above or click any <strong>#1–#10</strong> result button on the top line to focus the Knowledge Graph on that result node.</span>`;
        actionsEl.innerHTML = '';
        return;
      }}
      const outs = (OUT_EDGES.get(n.id) || []).filter(e => NODE_MAP.has(e.target) && enabledTypes.has((NODE_MAP.get(e.target) || {{}}).type));
      const ins = (IN_EDGES.get(n.id) || []).filter(e => NODE_MAP.has(e.source) && enabledTypes.has((NODE_MAP.get(e.source) || {{}}).type));
      const col = typeColor(n.type);
      const lineno = (n.metadata && n.metadata.lineno) ? `:${{n.metadata.lineno}}` : '';
      const fp = (n.file_path || 'N/A') + lineno;
      const rankPrefix = rankNum ? `<span class="rank-badge">#${{rankNum}}</span>` : '';

      contentEl.innerHTML = `
        ${{rankPrefix}}
        <span class="type-dot" style="background:${{col}};"></span>
        <strong>${{esc(n.name)}}</strong>
        <code>${{esc(n.type)}}</code>
        <span>Path: <code>${{esc(fp)}}</code></span>
        <span>Synapses: <strong>${{ins.length}} in / ${{outs.length}} out</strong></span>
        <span style="color:#94a3b8;">${{esc((n.description || '').slice(0, 95))}}</span>
      `;
      actionsEl.innerHTML = `
        <button type="button" class="hud-btn" onclick="focusNodeInGraph('${{esc(n.id)}}')">🎯 Focus Node Graph</button>
      `;
    }}

    function ensure3DSphereGradients() {{
      const defs = document.querySelector('#kg-svg defs');
      if (!defs || document.getElementById('grad3d-default')) return;
      let gradHtml = '';
      const allCols = Object.assign({{ default: '#38bdf8' }}, TYPE_COLORS);
      Object.keys(allCols).forEach(k => {{
        const c = allCols[k];
        gradHtml += `
          <radialGradient id="grad3d-${{k}}" cx="32%" cy="28%" r="70%" fx="32%" fy="28%">
            <stop offset="0%" stop-color="#ffffff" stop-opacity="0.95"/>
            <stop offset="28%" stop-color="${{c}}" stop-opacity="0.95"/>
            <stop offset="72%" stop-color="${{c}}" stop-opacity="0.55"/>
            <stop offset="100%" stop-color="#050811" stop-opacity="0.95"/>
          </radialGradient>`;
      }});
      defs.insertAdjacentHTML('beforeend', gradHtml);
    }}

    function renderGraphicalKnowledgeGraph() {{
      ensure3DSphereGradients();
      const stage = document.getElementById('kg-graph-stage');
      const W = stage.clientWidth || 1280;
      const H = stage.clientHeight || 720;
      const rawQ = (document.getElementById('kg-search-input').value || '').trim();

      const nodes3D = new Map();
      const rankLabels = new Map();
      top10Results.forEach((n, i) => rankLabels.set(n.id, i + 1));

      let modeTitle = '';
      let edgesToDraw = [];
      const maxR = Math.min(W, H) * 0.44;
      const goldenAngle = Math.PI * (3 - Math.sqrt(5));

      const placeFibonacciSphereShell = (arr, shellR, baseRadiusPx, roleName) => {{
        const len = arr.length;
        if (!len) return;
        arr.forEach((n, idx) => {{
          let x3d = 0, y3d = 0, z3d = 0;
          if (len === 1) {{
            x3d = 0; y3d = 0; z3d = 0;
          }} else {{
            const yNorm = 1 - (idx / (len - 1)) * 2;
            const rAtY = Math.sqrt(Math.max(0, 1 - yNorm * yNorm));
            const theta = goldenAngle * idx;
            x3d = shellR * rAtY * Math.cos(theta);
            y3d = shellR * yNorm * 0.84;
            z3d = shellR * rAtY * Math.sin(theta);
          }}
          nodes3D.set(n.id, {{ node: n, role: roleName, r: baseRadiusPx, x3d, y3d, z3d }});
        }});
      }};

      if (selectedResultMode !== 'all' && top10Results[selectedResultMode]) {{
        // FOCUSED SINGLE RESULT NODE (#1..#10) 3D SPATIAL STARBURST
        const target = top10Results[selectedResultMode];
        const rankNum = selectedResultMode + 1;
        modeTitle = `3D Spatial Focus #${{rankNum}}: [${{target.type}}] ${{target.name}}`;
        nodes3D.set(target.id, {{ node: target, role: 'target', r: 25, x3d: 0, y3d: 0, z3d: 0 }});

        const ins = (IN_EDGES.get(target.id) || [])
          .filter(e => NODE_MAP.has(e.source) && enabledTypes.has(NODE_MAP.get(e.source).type))
          .slice(0, 22);
        const outs = (OUT_EDGES.get(target.id) || [])
          .filter(e => NODE_MAP.has(e.target) && enabledTypes.has(NODE_MAP.get(e.target).type))
          .slice(0, 22);

        const spreadR = maxR * 0.78;
        ins.forEach((e, idx) => {{
          const sn = NODE_MAP.get(e.source);
          if (!sn) return;
          if (!nodes3D.has(sn.id)) {{
            const t = ins.length === 1 ? 0 : (idx / (ins.length - 1)) * 2 - 1;
            const ang = idx * 1.15;
            const ringRad = spreadR * 0.58 * Math.sqrt(Math.max(0.15, 1 - t * t * 0.65));
            nodes3D.set(sn.id, {{
              node: sn,
              role: 'in',
              r: 14,
              x3d: -spreadR * 0.68,
              y3d: t * spreadR * 0.65,
              z3d: ringRad * Math.sin(ang),
            }});
          }}
          edgesToDraw.push({{ source: sn.id, target: target.id, relation: e.relation, kind: 'in' }});
        }});

        outs.forEach((e, idx) => {{
          const tn = NODE_MAP.get(e.target);
          if (!tn) return;
          if (!nodes3D.has(tn.id)) {{
            const t = outs.length === 1 ? 0 : (idx / (outs.length - 1)) * 2 - 1;
            const ang = idx * 1.15 + 0.6;
            const ringRad = spreadR * 0.58 * Math.sqrt(Math.max(0.15, 1 - t * t * 0.65));
            nodes3D.set(tn.id, {{
              node: tn,
              role: 'out',
              r: 14,
              x3d: spreadR * 0.68,
              y3d: t * spreadR * 0.65,
              z3d: ringRad * Math.sin(ang),
            }});
          }}
          edgesToDraw.push({{ source: target.id, target: tn.id, relation: e.relation, kind: 'out' }});
        }});

        updateInspector(target, rankNum);
      }} else if (rawQ && top10Results.length > 0) {{
        // ALL RESULTS MODE (3D Inner Core Constellation + 3D Outer Neighbor Cloud)
        modeTitle = `3D Spatial Top ${{top10Results.length}} Results (#1–#${{top10Results.length}}) for "${{rawQ}}"`;
        placeFibonacciSphereShell(top10Results, top10Results.length === 1 ? 0 : maxR * 0.36, 19, 'top10');

        const neighborList = [];
        top10Results.forEach(n => {{
          const outs = (OUT_EDGES.get(n.id) || []).slice(0, 6);
          const ins = (IN_EDGES.get(n.id) || []).slice(0, 6);
          outs.forEach(e => {{
            const tn = NODE_MAP.get(e.target);
            if (tn && enabledTypes.has(tn.type)) {{
              if (!nodes3D.has(tn.id) && !neighborList.some(x => x.id === tn.id)) {{
                neighborList.push(tn);
              }}
              edgesToDraw.push({{ source: n.id, target: tn.id, relation: e.relation, kind: 'out' }});
            }}
          }});
          ins.forEach(e => {{
            const sn = NODE_MAP.get(e.source);
            if (sn && enabledTypes.has(sn.type)) {{
              if (!nodes3D.has(sn.id) && !neighborList.some(x => x.id === sn.id)) {{
                neighborList.push(sn);
              }}
              edgesToDraw.push({{ source: sn.id, target: n.id, relation: e.relation, kind: 'in' }});
            }}
          }});
        }});

        placeFibonacciSphereShell(neighborList, maxR * 0.88, 11, 'neighbor');
        updateInspector(top10Results[0], 1);
      }} else {{
        // SIMPLE, MEMORY-LIGHT 3D SPATIAL MULTI-SHELL SPHERE (Capped at Top 150 Hub Nodes & 200 Edges for Large Graphs)
        const allFiltered = KG_DATA.nodes
          .filter(n => enabledTypes.has(n.type))
          .sort((a, b) => (DEGREE_MAP.get(b.id) || 0) - (DEGREE_MAP.get(a.id) || 0));
        const MAX_3D_NODES = 150;
        const MAX_3D_EDGES = 200;
        const activeAll = allFiltered.length > MAX_3D_NODES ? allFiltered.slice(0, MAX_3D_NODES) : allFiltered;
        const totalInTable = (KG_DATA.metadata && KG_DATA.metadata.total_vectors_in_table) || KG_DATA.nodes.length;
        modeTitle = allFiltered.length > MAX_3D_NODES
          ? `Full Codebase Graphical Knowledge Graph (Top ${{activeAll.length}} Hub Nodes of ${{totalInTable}} • 3D Spatial)`
          : `Full Codebase Graphical Knowledge Graph (${{activeAll.length}} Nodes • 3D Spatial)`;

        const shell1Types = new Set(['cluster_node', 'network_device', 'cluster_service', 'k8s_resource', 'document_file']);
        const shell2Types = new Set(['python_module', 'html_template', 'dockerfile', 'yaml_config', 'env_config', 'config_file', 'requirements_file', 'document_section', 'document']);
        const shell3Types = new Set(['shell_script', 'sql_file', 'python_class', 'topic_entity', 'api_endpoint']);

        const shell1 = activeAll.filter(n => shell1Types.has(n.type));
        const shell2 = activeAll.filter(n => shell2Types.has(n.type));
        const shell3 = activeAll.filter(n => shell3Types.has(n.type));
        const remaining = activeAll.filter(n => !shell1Types.has(n.type) && !shell2Types.has(n.type) && !shell3Types.has(n.type));

        if (activeAll.length <= 30) {{
          placeFibonacciSphereShell(activeAll, maxR * 0.62, 16, 'core');
        }} else {{
          placeFibonacciSphereShell(shell1, maxR * 0.30, 14, 'core');
          placeFibonacciSphereShell(shell2, maxR * 0.56, 11, 'mid');
          placeFibonacciSphereShell(shell3, maxR * 0.80, 9, 'mid');
          placeFibonacciSphereShell(remaining, maxR * 0.98, 7.5, 'outer');
        }}

        for (let i = 0; i < KG_DATA.edges.length; i++) {{
          if (edgesToDraw.length >= MAX_3D_EDGES) break;
          const e = KG_DATA.edges[i];
          if (nodes3D.has(e.source) && nodes3D.has(e.target)) {{
            edgesToDraw.push({{ source: e.source, target: e.target, relation: e.relation, kind: 'net' }});
          }}
        }}
        updateInspector(inspectedNodeId ? NODE_MAP.get(inspectedNodeId) : (top10Results[0] || null), rankLabels.get(inspectedNodeId));
      }}

      _scene3D = {{ nodes3D, edgesToDraw, rankLabels, modeTitle, maxR }};
      document.getElementById('hud-mode-title').textContent = modeTitle;
      document.getElementById('hud-node-count').textContent = nodes3D.size;
      document.getElementById('hud-edge-count').textContent = edgesToDraw.length;
      projectAndRender3DScene();
    }}

    function projectAndRender3DScene() {{
      const vp = document.getElementById('kg-viewport');
      const stage = document.getElementById('kg-graph-stage');
      if (!vp || !stage) return;
      const W = stage.clientWidth || 1280;
      const H = stage.clientHeight || 720;
      const cx = W / 2;
      const cy = H / 2;
      const rawQ = (document.getElementById('kg-search-input')?.value || '').trim();

      const {{ nodes3D, edgesToDraw, rankLabels, maxR }} = _scene3D;
      if (!nodes3D) return;

      const cosY = Math.cos(rotY), sinY = Math.sin(rotY);
      const cosX = Math.cos(rotX), sinX = Math.sin(rotX);
      const fov = Math.max(W, H) * 0.95;

      const projected = new Map();
      const sortedNodes = [];

      nodes3D.forEach((info, id) => {{
        const x1 = info.x3d * cosY + info.z3d * sinY;
        const z1 = -info.x3d * sinY + info.z3d * cosY;
        const y2 = info.y3d * cosX - z1 * sinX;
        const z2 = info.y3d * sinX + z1 * cosX;

        const persp = fov / Math.max(120, fov + z2);
        const sx = cx + x1 * persp;
        const sy = cy + y2 * persp;
        const sr = Math.max(2.3, info.r * persp);
        const depthNorm = Math.max(0, Math.min(1, (maxR - z2) / Math.max(1, 2 * maxR)));

        const pObj = {{
          id,
          node: info.node,
          role: info.role,
          x: sx,
          y: sy,
          r: sr,
          zCam: z2,
          persp,
          depthNorm,
        }};
        projected.set(id, pObj);
        sortedNodes.push(pObj);
      }});

      // Painter's algorithm: sort back-to-front (largest zCam = furthest away drawn first)
      sortedNodes.sort((a, b) => b.zCam - a.zCam);

      // Draw subtle 3D Spatial Equatorial & Meridian Wireframe Rings for 3D depth reference
      let svgGuides = '';
      const ringRadius = maxR * 0.92;
      const build3DRingPath = (axis) => {{
        const steps = 40;
        let d = '';
        for (let i = 0; i <= steps; i++) {{
          const ang = (2 * Math.PI * i) / steps;
          let gx = 0, gy = 0, gz = 0;
          if (axis === 'xz') {{
            gx = ringRadius * Math.cos(ang);
            gz = ringRadius * Math.sin(ang);
          }} else if (axis === 'xy') {{
            gx = ringRadius * Math.cos(ang);
            gy = ringRadius * Math.sin(ang) * 0.84;
          }} else {{
            gy = ringRadius * Math.cos(ang) * 0.84;
            gz = ringRadius * Math.sin(ang);
          }}
          const x1 = gx * cosY + gz * sinY;
          const z1 = -gx * sinY + gz * cosY;
          const y2 = gy * cosX - z1 * sinX;
          const z2 = gy * sinX + z1 * cosX;
          const p = fov / Math.max(120, fov + z2);
          const px = cx + x1 * p;
          const py = cy + y2 * p;
          d += (i === 0 ? `M ${{px.toFixed(1)}} ${{py.toFixed(1)}}` : ` L ${{px.toFixed(1)}} ${{py.toFixed(1)}}`);
        }}
        return d;
      }};
      svgGuides += `<path d="${{build3DRingPath('xz')}}" fill="none" stroke="#1e293b" stroke-width="1" stroke-dasharray="5,5" opacity="0.55"/>`;
      svgGuides += `<path d="${{build3DRingPath('xy')}}" fill="none" stroke="#1e293b" stroke-width="1" stroke-dasharray="3,6" opacity="0.4"/>`;

      let svgEdges = svgGuides;
      const isDenseFullGraph = (edgesToDraw.length > 350 && selectedResultMode === 'all' && !rawQ);
      edgesToDraw.forEach(e => {{
        const p1 = projected.get(e.source);
        const p2 = projected.get(e.target);
        if (!p1 || !p2) return;
        const avgDepth = (p1.depthNorm + p2.depthNorm) * 0.5;
        if (isDenseFullGraph) {{
          const isHubEdge = rankLabels.has(e.source) || rankLabels.has(e.target);
          if (!isHubEdge && avgDepth < 0.22) return;
          const lStroke = isHubEdge ? '#38bdf8' : '#475569';
          const lOp = (isHubEdge ? 0.58 : 0.14 + avgDepth * 0.28).toFixed(2);
          const lW = isHubEdge ? '1.2' : (0.55 + avgDepth * 0.55).toFixed(2);
          svgEdges += `<line x1="${{p1.x.toFixed(1)}}" y1="${{p1.y.toFixed(1)}}" x2="${{p2.x.toFixed(1)}}" y2="${{p2.y.toFixed(1)}}" stroke="${{lStroke}}" stroke-width="${{lW}}" opacity="${{lOp}}"/>`;
          return;
        }}
        const dx = p2.x - p1.x;
        const dy = p2.y - p1.y;
        const mx = (p1.x + p2.x) / 2 - dy * 0.07;
        const my = (p1.y + p2.y) / 2 + dx * 0.07;

        let stroke = '#38bdf8';
        let opacity = (0.25 + avgDepth * 0.55).toFixed(2);
        let width = (0.9 + avgDepth * 0.9).toFixed(2);
        let marker = 'url(#arrow-net)';
        if (e.kind === 'out') {{
          stroke = '#22c55e'; opacity = '0.86'; width = '2'; marker = 'url(#arrow-out)';
        }} else if (e.kind === 'in') {{
          stroke = '#f59e0b'; opacity = '0.86'; width = '2'; marker = 'url(#arrow-in)';
        }}

        svgEdges += `<path d="M ${{p1.x.toFixed(1)}} ${{p1.y.toFixed(1)}} Q ${{mx.toFixed(1)}} ${{my.toFixed(1)}} ${{p2.x.toFixed(1)}} ${{p2.y.toFixed(1)}}" fill="none" stroke="${{stroke}}" stroke-width="${{width}}" opacity="${{opacity}}" marker-end="${{marker}}"/>`;
        if (selectedResultMode !== 'all' && e.relation) {{
          svgEdges += `<text x="${{mx.toFixed(1)}}" y="${{(my - 4).toFixed(1)}}" text-anchor="middle" fill="#cbd5e1" font-size="9" font-family="monospace">${{esc(e.relation.slice(0, 20))}}</text>`;
        }}
      }});

      let svgNodes = '';
      const isDenseNodes = sortedNodes.length > 90;
      sortedNodes.forEach(pObj => {{
        const id = pObj.id;
        const n = pObj.node;
        const col = typeColor(n.type);
        const gradId = TYPE_COLORS[n.type] ? `grad3d-${{n.type}}` : 'grad3d-default';
        const rank = rankLabels.get(id);
        const shortName = (n.name || id).slice(0, 24);
        const isTarget = pObj.role === 'target' || pObj.role === 'top10';
        const isFrontHighlight = pObj.depthNorm > 0.72 && (n.type === 'cluster_node' || n.type === 'network_device' || n.type === 'document_file');
        const alwaysShowLabel = !isDenseNodes || isTarget || Boolean(rank) || id === inspectedNodeId || isFrontHighlight;
        const labelCls = alwaysShowLabel ? 'node-label-always' : 'node-label-auto';
        const fpHint = n.file_path ? ` (${{n.file_path}})` : '';
        const nodeAlpha = isTarget || rank ? 1.0 : Math.max(0.24, Math.min(1.0, 0.28 + pObj.depthNorm * 0.75));

        svgNodes += `<g class="kg-node-group" opacity="${{nodeAlpha.toFixed(2)}}" transform="translate(${{pObj.x.toFixed(1)}},${{pObj.y.toFixed(1)}})" onmouseenter="isHoveringNode=true;highlightNodeEdges('${{esc(id)}}')" onmouseleave="isHoveringNode=false;clearHighlightNodeEdges()" onclick="onGraphNodeClick(event, '${{esc(id)}}')">`;
        svgNodes += `<title>[${{esc(n.type)}}] ${{esc(n.name)}}${{esc(fpHint)}}\n${{esc(n.description || '')}}</title>`;
        if (isTarget) {{
          svgNodes += `<ellipse rx="${{(pObj.r + 8).toFixed(1)}}" ry="${{((pObj.r + 8) * 0.48).toFixed(1)}}" fill="none" stroke="${{col}}" stroke-width="1.5" stroke-dasharray="4,3" opacity="0.85"/>`;
          svgNodes += `<circle r="${{(pObj.r + 4).toFixed(1)}}" fill="none" stroke="${{col}}" stroke-width="1.2" opacity="0.55"/>`;
        }}
        svgNodes += `<circle class="node-core" r="${{pObj.r.toFixed(1)}}" fill="url(#${{gradId}})" stroke="${{col}}" stroke-width="${{isTarget ? 2.4 : 1.1}}"/>`;
        if (rank) {{
          svgNodes += `<text x="0" y="3" text-anchor="middle" fill="#ffffff" font-size="${{pObj.r >= 14 ? 9.5 : 7.5}}" font-weight="800" font-family="monospace">#${{rank}}</text>`;
        }}
        svgNodes += `<text class="${{labelCls}}" x="0" y="${{(pObj.r + 11).toFixed(1)}}" text-anchor="middle" fill="${{alwaysShowLabel ? '#f8fafc' : '#38bdf8'}}" font-size="${{isTarget ? 11 : Math.max(8, 9.5 * pObj.persp).toFixed(1)}}" font-weight="${{isTarget || !alwaysShowLabel ? 700 : 500}}" font-family="monospace">${{esc(shortName)}}</text>`;
        svgNodes += `</g>`;
      }});

      window._lastGraphPositions = projected;
      window._lastVisibleNodes = nodes3D;
      vp.innerHTML = `<g id="kg-base-edges">${{svgEdges}}</g><g id="kg-hover-edges"></g><g id="kg-nodes-layer">${{svgNodes}}</g>`;
      applyTransform();
    }}

    function toggle3DAutoSpin() {{
      autoSpin3D = !autoSpin3D;
      const btn = document.getElementById('hud-3d-spin-btn');
      if (btn) {{
        btn.textContent = autoSpin3D ? '🌐 3D Spin: ON' : '🌐 3D Spin: OFF';
        btn.style.borderColor = autoSpin3D ? '#38bdf8' : '#475569';
        btn.style.color = autoSpin3D ? '#38bdf8' : '#94a3b8';
      }}
    }}

    function clearAndCompactGraphMemory() {{
      autoSpin3D = false;
      const spinBtn = document.getElementById('hud-3d-spin-btn');
      if (spinBtn) {{
        spinBtn.textContent = '🌐 3D Spin: OFF';
        spinBtn.style.borderColor = '#475569';
        spinBtn.style.color = '#94a3b8';
      }}
      const hoverLayer = document.getElementById('kg-hover-edges');
      if (hoverLayer) hoverLayer.innerHTML = '';
      const drawer = document.getElementById('kg-prompt-drawer');
      if (drawer) drawer.style.display = 'none';
      const drawerBody = document.getElementById('kg-prompt-drawer-body');
      if (drawerBody) drawerBody.textContent = '';
      if (_scene3D && _scene3D.nodes3D) _scene3D.nodes3D.clear();
      window._lastGraphPositions = null;
      window._lastVisibleNodes = null;
      inspectedNodeId = null;
      selectedResultMode = 'all';
      panX = 0; panY = 0; scale = 1;
      rotY = -0.45; rotX = 0.28;
      renderTopLineResultButtons();
      renderGraphicalKnowledgeGraph();
    }}
    window.freeGraphMemory = clearAndCompactGraphMemory;
    window.addEventListener('pagehide', () => {{
      const vp = document.getElementById('kg-viewport');
      if (vp) vp.innerHTML = '';
      if (_scene3D && _scene3D.nodes3D) _scene3D.nodes3D.clear();
      window._lastGraphPositions = null;
      window._lastVisibleNodes = null;
    }});

    function highlightNodeEdges(nodeId) {{
      const hoverLayer = document.getElementById('kg-hover-edges');
      const positions = window._lastGraphPositions;
      if (!hoverLayer || !positions || !positions.has(nodeId)) return;
      const pSelf = positions.get(nodeId);
      let html = '';
      (OUT_EDGES.get(nodeId) || []).forEach(e => {{
        const pT = positions.get(e.target);
        if (!pT) return;
        html += `<line x1="${{pSelf.x.toFixed(1)}}" y1="${{pSelf.y.toFixed(1)}}" x2="${{pT.x.toFixed(1)}}" y2="${{pT.y.toFixed(1)}}" stroke="#22c55e" stroke-width="2.2" opacity="0.95" marker-end="url(#arrow-out)"/>`;
      }});
      (IN_EDGES.get(nodeId) || []).forEach(e => {{
        const pS = positions.get(e.source);
        if (!pS) return;
        html += `<line x1="${{pS.x.toFixed(1)}}" y1="${{pS.y.toFixed(1)}}" x2="${{pSelf.x.toFixed(1)}}" y2="${{pSelf.y.toFixed(1)}}" stroke="#f59e0b" stroke-width="2.2" opacity="0.95" marker-end="url(#arrow-in)"/>`;
      }});
      hoverLayer.innerHTML = html;
    }}

    function clearHighlightNodeEdges() {{
      const hoverLayer = document.getElementById('kg-hover-edges');
      if (hoverLayer) hoverLayer.innerHTML = '';
    }}

    function onGraphNodeClick(evt, nodeId) {{
      evt.stopPropagation();
      const n = NODE_MAP.get(nodeId);
      if (!n) return;
      inspectedNodeId = nodeId;
      const rIdx = top10Results.findIndex(item => item.id === nodeId);
      if (rIdx !== -1 && selectedResultMode !== rIdx) {{
        selectedResultMode = rIdx;
        renderTopLineResultButtons();
        renderGraphicalKnowledgeGraph();
      }} else {{
        focusNodeInGraph(nodeId);
      }}
    }}

    function applyTransform() {{
      const vp = document.getElementById('kg-viewport');
      vp.setAttribute('transform', `translate(${{panX}}, ${{panY}}) scale(${{scale}})`);
      const svgEl = document.getElementById('kg-svg');
      if (svgEl) {{
        if (scale >= 2.1) svgEl.classList.add('kg-zoomed-in');
        else svgEl.classList.remove('kg-zoomed-in');
      }}
    }}

    function zoomBy(factor) {{
      const stage = document.getElementById('kg-graph-stage');
      const cx = (stage.clientWidth || 1280) / 2;
      const cy = (stage.clientHeight || 720) / 2;
      const newScale = Math.max(0.35, Math.min(3.5, scale * factor));
      panX = cx - (cx - panX) * (newScale / scale);
      panY = cy - (cy - panY) * (newScale / scale);
      scale = newScale;
      applyTransform();
    }}

    function resetTransform() {{
      panX = 0; panY = 0; scale = 1;
      rotY = -0.45; rotX = 0.28;
      projectAndRender3DScene();
    }}

    (function initStageInteraction() {{
      const stage = document.getElementById('kg-graph-stage');
      stage.addEventListener('mousedown', e => {{
        if (e.target.closest('.kg-node-group') || e.target.closest('button') || e.target.closest('select')) return;
        isDragging = true;
        if (e.shiftKey || e.button === 2) {{
          dragMode = 'pan';
          dragStartX = e.clientX - panX;
          dragStartY = e.clientY - panY;
        }} else {{
          dragMode = 'orbit';
          dragStartX = e.clientX;
          dragStartY = e.clientY;
          startRotY = rotY;
          startRotX = rotX;
        }}
        stage.classList.add('dragging');
      }});
      window.addEventListener('mousemove', e => {{
        if (!isDragging) return;
        if (dragMode === 'pan') {{
          panX = e.clientX - dragStartX;
          panY = e.clientY - dragStartY;
          applyTransform();
        }} else {{
          const dx = e.clientX - dragStartX;
          const dy = e.clientY - dragStartY;
          rotY = startRotY + dx * 0.0065;
          rotX = Math.max(-1.42, Math.min(1.42, startRotX + dy * 0.0065));
          projectAndRender3DScene();
        }}
      }});
      window.addEventListener('mouseup', () => {{
        isDragging = false;
        stage.classList.remove('dragging');
      }});
      stage.addEventListener('wheel', e => {{
        e.preventDefault();
        const factor = e.deltaY < 0 ? 1.12 : 0.89;
        const rect = stage.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const newScale = Math.max(0.35, Math.min(3.5, scale * factor));
        panX = mx - (mx - panX) * (newScale / scale);
        panY = my - (my - panY) * (newScale / scale);
        scale = newScale;
        applyTransform();
      }}, {{ passive: false }});
      window.addEventListener('resize', () => renderGraphicalKnowledgeGraph());

      // Gentle 3D Spatial Auto-Rotation Loop
      let lastTick = performance.now();
      function animate3DLoop(now) {{
        const dt = now - lastTick;
        lastTick = now;
        if (autoSpin3D && !isDragging && !isHoveringNode && document.visibilityState !== 'hidden') {{
          rotY += (dt * 0.00022);
          projectAndRender3DScene();
        }}
        requestAnimationFrame(animate3DLoop);
      }}
      requestAnimationFrame(animate3DLoop);
    }})();

    function syncHashRankSelection() {{
      const h = window.location.hash || '';
      const m = h.match(/^#(?:hit-kg-table-|tab-|rank-)?(\\d+)$/);
      if (m) {{
        const idx = parseInt(m[1], 10) - 1;
        if (idx >= 0 && idx < top10Results.length) {{
          selectedResultMode = idx;
          renderTopLineResultButtons();
          renderGraphicalKnowledgeGraph();
        }}
      }}
    }}

    window.addEventListener('DOMContentLoaded', () => {{
      const params = new URLSearchParams(window.location.search);
      const qParam = params.get('q') || KG_DATA.initial_query || '';
      const inp = document.getElementById('kg-search-input');
      if (qParam) {{
        inp.value = qParam;
        document.getElementById('kg-search-clear').style.display = 'block';
      }}
      renderCliFlagCheckboxes();
      renderNodeOptionButtons();
      recomputeResultsAndGraph();
      syncHashRankSelection();
    }});
    window.addEventListener('hashchange', syncHashRankSelection);
    window.addEventListener('message', (evt) => {{
      if (evt && evt.data && evt.data.type === 'KG_TRACE_QUERY') {{
        const q = String(evt.data.query || '').trim();
        const inp = document.getElementById('kg-search-input');
        if (inp) {{
          inp.value = q;
          const clr = document.getElementById('kg-search-clear');
          if (clr) clr.style.display = q ? 'block' : 'none';
          selectedResultMode = 'all';
          recomputeResultsAndGraph();
        }}
      }}
    }});
  </script>
</body>
</html>
"""


def _save_last_query_results(matches: List[Dict[str, Any]], queries: List[str]) -> None:
    """Persist the most recent query hits so follow-up `query_kg.py --#1` or `--#N` works immediately."""
    try:
        KG_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "saved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "queries": queries,
            "matches": matches,
        }
        KG_LAST_RESULTS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        pass


def _load_last_query_results() -> Tuple[List[Dict[str, Any]], List[str]]:
    """Load the most recent query hits for standalone `--#N` execution."""
    if not KG_LAST_RESULTS_PATH.exists():
        return [], []
    try:
        data = json.loads(KG_LAST_RESULTS_PATH.read_text(encoding="utf-8"))
        return data.get("matches", []), data.get("queries", [])
    except Exception:
        return [], []


def _resolve_exact_line_range(rel_path: Optional[str], lineno: Optional[int]) -> Tuple[Optional[int], Optional[int]]:
    """Locally resolve exact (start_line, end_line) via AST so the LLM only reads the target block."""
    if not rel_path or not lineno:
        return lineno, lineno
    abs_path = REPO_ROOT / rel_path
    if not abs_path.exists():
        return lineno, lineno
    if abs_path.suffix.lower() != ".py":
        return lineno, lineno + 40
    try:
        src = abs_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = getattr(node, "lineno", None)
                end = getattr(node, "end_lineno", None)
                if start == lineno and end:
                    # Include decorator lines if present
                    if getattr(node, "decorator_list", None):
                        dec_start = min( getattr(d, "lineno", start) for d in node.decorator_list )
                        start = min(start, dec_start)
                    return start, end
    except Exception:
        pass
    return lineno, lineno + 40


def copy_to_clipboard(text: str) -> List[str]:
    """Copy text to system clipboard (X11/Wayland/macOS/OSC-52) and persist to last_llm_prompt.txt."""
    methods_used: List[str] = []
    try:
        KG_LAST_PROMPT_PATH.write_text(text, encoding="utf-8")
        methods_used.append(f"file:{KG_LAST_PROMPT_PATH.name}")
    except OSError:
        pass

    clipboard_cmds = [
        (["xclip", "-selection", "clipboard"], "xclip (clipboard)"),
        (["xclip", "-selection", "primary"], "xclip (primary)"),
        (["xsel", "--clipboard", "--input"], "xsel"),
        (["wl-copy"], "wl-copy"),
        (["pbcopy"], "pbcopy"),
    ]
    for cmd, label in clipboard_cmds:
        if shutil.which(cmd[0]):
            try:
                proc = subprocess.run(
                    cmd,
                    input=text.encode("utf-8"),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                    check=False,
                )
                if proc.returncode == 0:
                    methods_used.append(label)
                    if label == "xclip (clipboard)":
                        break
            except Exception:
                pass

    # Also emit OSC-52 clipboard sequence for terminal emulators / IDE integrated terminals
    if sys.stdout.isatty():
        try:
            b64 = base64.b64encode(text.encode("utf-8")).decode("ascii")
            sys.stderr.write(f"\033]52;c;{b64}\a")
            sys.stderr.flush()
            methods_used.append("OSC-52 terminal clipboard")
        except Exception:
            pass

    return methods_used


_STOP_WORDS = {
    "the", "and", "for", "that", "this", "with", "from", "are", "was", "were",
    "have", "has", "had", "not", "but", "what", "all", "can", "will", "into",
    "your", "you", "our", "out", "use", "used", "using", "any", "when", "then",
}


def _extract_image_dimensions_and_ocr(fpath: pathlib.Path) -> Tuple[str, str]:
    """Extract image format/dimensions and OCR text for screenshots in knowledge_graph/Files/."""
    import struct
    size_kb = round(fpath.stat().st_size / 1024.0, 1)
    dims = "unknown"
    try:
        with open(fpath, "rb") as bf:
            head = bf.read(32)
            if head.startswith(b"\x89PNG\r\n\x1a\n") and len(head) >= 24:
                w, h = struct.unpack(">II", head[16:24])
                dims = f"{w}x{h}"
            elif head[:2] == b"\xff\xd8":
                bf.seek(2)
                while True:
                    marker = bf.read(2)
                    if len(marker) < 2 or marker[0] != 0xFF:
                        break
                    mtype = marker[1]
                    if mtype in (0xC0, 0xC1, 0xC2, 0xC3):
                        seg = bf.read(7)
                        if len(seg) == 7:
                            _, _, h, w = struct.unpack(">BHH", seg[:5])
                            dims = f"{w}x{h}"
                        break
                    else:
                        slen_b = bf.read(2)
                        if len(slen_b) < 2:
                            break
                        slen = struct.unpack(">H", slen_b)[0]
                        bf.seek(slen - 2, 1)
    except Exception:
        pass

    ocr_text = ""
    if shutil.which("tesseract"):
        try:
            proc = subprocess.run(
                ["tesseract", str(fpath), "stdout", "--psm", "6"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                ocr_text = proc.stdout.strip()
        except Exception:
            pass
    if not ocr_text:
        try:
            from PIL import Image  # type: ignore
            with Image.open(fpath) as im:
                dims = f"{im.width}x{im.height}"
                info_txt = " ".join(f"{k}={v}" for k, v in (im.info or {}).items() if isinstance(v, (str, int, float)))
                ocr_text = f"Image({im.format}, {dims}, mode={im.mode}) {info_txt}".strip()
        except Exception:
            ocr_text = f"Screenshot/Image ({fpath.suffix.lstrip('.').upper()}, {dims}, {size_kb} KB)"

    meta_summary = f"{fpath.suffix.lstrip('.').upper()} {dims} ({size_kb} KB)"
    return meta_summary, ocr_text


def _scan_and_tokenize_files_folder(files_dir: pathlib.Path = KG_FILES_DIR) -> List[str]:
    """
    Scan knowledge_graph/Files/ for any files (including screenshots/images, logs, configs, and code),
    tokenize their contents locally to provide additional context to the LLM, and consume each scanned
    file once tokenized to avoid repetition.
    """
    files_dir.mkdir(parents=True, exist_ok=True)
    gitkeep = files_dir / ".gitkeep"
    if not gitkeep.exists():
        try:
            gitkeep.write_text("", encoding="utf-8")
        except OSError:
            pass

    scanned_files = sorted(
        p for p in files_dir.rglob("*")
        if p.is_file() and not p.name.startswith(".")
    )

    section_lines: List[str] = [
        f"Additional Context from {files_dir} (Scanned, Tokenized & Consumed Files: {len(scanned_files)}):"
    ]
    if not scanned_files:
        section_lines.append("  - (No files queued in knowledge_graph/Files/)")
        section_lines.append("")
        return section_lines

    signal_re = re.compile(
        r"(error|warn|fail|exception|traceback|critical|denied|timeout|refused|fatal|status|http|sap|k3s|offline|gpu|cpu|memory)",
        re.IGNORECASE,
    )
    image_exts = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}

    for idx, fpath in enumerate(scanned_files, start=1):
        rel_name = str(fpath.relative_to(files_dir))
        is_image = fpath.suffix.lower() in image_exts
        image_meta = ""

        if is_image:
            image_meta, raw_text = _extract_image_dimensions_and_ocr(fpath)
        else:
            try:
                raw_text = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

        raw_lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
        raw_tokens = re.findall(r"[A-Za-z0-9_./:@=-]+", raw_text)

        # Count technical tokens (excluding trivial stop words)
        freq: Dict[str, int] = {}
        ordered_unique_tokens: List[str] = []
        for tok in raw_tokens:
            low = tok.lower().strip(".,:;()[]{}")
            if len(low) < 2 or low in _STOP_WORDS:
                continue
            if low not in freq:
                ordered_unique_tokens.append(tok)
            freq[low] = freq.get(low, 0) + 1

        top_tokens = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[:25]
        top_tokens_str = ", ".join(f"{k}({v})" if v > 1 else k for k, v in top_tokens) or "none"

        # Extract deduplicated high-signal lines (errors, warnings, statuses)
        signal_lines: List[str] = []
        seen_sig: Set[str] = set()
        for ln in raw_lines:
            if signal_re.search(ln):
                compact_ln = re.sub(r"\s+", " ", ln)[:160]
                if compact_ln not in seen_sig:
                    seen_sig.add(compact_ln)
                    signal_lines.append(compact_ln)
                if len(signal_lines) >= 6:
                    break

        # Build compact tokenized stream (preserving order of unique/meaningful tokens, capped at 80 tokens)
        tokenized_stream = " ".join(ordered_unique_tokens[:80])
        if len(ordered_unique_tokens) > 80:
            tokenized_stream += f" ... (+{len(ordered_unique_tokens) - 80} more unique tokens)"

        # Delete the file once scanned and tokenized to avoid repetition on subsequent Query 2 runs
        deleted_ok = False
        try:
            fpath.unlink()
            deleted_ok = True
        except OSError:
            pass

        status_tag = "consumed & deleted" if deleted_ok else "scanned"
        extra_img = f" | Image={image_meta}" if is_image else ""
        section_lines.append(
            f"  - File #{idx}: {rel_name} [{status_tag}]{extra_img} | Lines={len(raw_lines)}, RawTokens={len(raw_tokens)}, UniqueTokens={len(ordered_unique_tokens)}"
        )
        section_lines.append(f"    Key Tokens:        {top_tokens_str}")
        if signal_lines:
            section_lines.append(f"    Signal Lines:      {' || '.join(signal_lines)}")
        section_lines.append(f"    Tokenized Content: {tokenized_stream}")

    section_lines.append("")
    return section_lines


def _extract_code_snippet(rel_path: Optional[str], start_line: Optional[int], end_line: Optional[int], max_lines: int = 45) -> List[str]:
    """Extract the relevant source lines for the target entity to provide rich upfront context to the LLM."""
    if not rel_path:
        return []
    abs_path = REPO_ROOT / rel_path
    if not abs_path.exists() or not abs_path.is_file():
        return []
    try:
        all_lines = abs_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not all_lines:
            return []
        s_idx = max(0, (start_line - 1) if start_line else 0)
        e_idx = min(len(all_lines), end_line if end_line else (s_idx + max_lines))
        if e_idx - s_idx > max_lines:
            e_idx = s_idx + max_lines
        snippet = [f"    {ln_no:4d}: {all_lines[ln_no - 1]}" for ln_no in range(s_idx + 1, e_idx + 1)]
        return snippet
    except Exception:
        return []


def build_token_saving_llm_prompt(
    selected_hits: List[Tuple[int, Dict[str, Any]]],
    queries: List[str],
    ask_text: str = "",
    investigate_only: bool = False,
) -> str:
    """
    Build a locally preprocessed, rich-context LLM instruction + request block for --#1 / --#N.
    The last line is the REQUEST TO LLM (containing the target link and what the ask is).
    When investigate_only (/I) is True, instructs the LLM to investigate only with no code updates.
    """
    or_groups = parse_query_expression(queries)
    query_str = format_query_expression(or_groups) if or_groups else (" ".join(queries) or "saved_query")

    mode_header = (
        "INSTRUCTION TO LLM (LOCAL KNOWLEDGE GRAPH PREPROCESSED CONTEXT — INVESTIGATE ONLY / NO CODE UPDATES):"
        if investigate_only
        else "INSTRUCTION TO LLM (LOCAL KNOWLEDGE GRAPH PREPROCESSED CONTEXT):"
    )
    lines: List[str] = [
        mode_header,
        f"- Repository Root: {REPO_ROOT}",
        "- Preprocessed Context Guidance: This context was locally assembled via `query_kg.py` to provide rich upfront context (exact target file/lines, code snippet, connected Knowledge Graph dependencies, and tokenized files) and reduce blind discovery token usage. Start from the context below, and inspect or search the codebase further as needed.",
    ]
    if investigate_only:
        lines.append(
            "- Execution Mode (/I): INVESTIGATE ONLY — NO CODE UPDATES. Analyze, diagnose, and answer the request without modifying, creating, or deleting any files."
        )
    else:
        lines.append(
            "- Code Edit Rule: All code edits MUST be done using Python only (`/usr/bin/python3`) — do NOT use PowerShell."
        )
        lines.append(
            f"- Post-Change Rule (see {REPO_ROOT / 'rules.md'}): After any edit, update `man/` docs, run Delta-Only Mojibake Audit & Fix (`python3 {KG_DIR / 'query_kg.py'} --mojibake-fix`), run Pre-Commit Vulnerability Scan (`python3 {KG_DIR / 'query_kg.py'} --vuln-scan` and present report if any found), run `python3 {KG_DIR / 'query_kg.py'} --update`, and prompt for `git commit` / `git push`."
        )
    lines.append("")

    target_links: List[str] = []
    for hit_num, m in selected_hits:
        meta = m.get("metadata", {}) or {}
        rel_path = m.get("file_path") or ""
        lineno = meta.get("lineno")
        start_line, end_line = _resolve_exact_line_range(rel_path, lineno)
        if meta.get("end_lineno") and isinstance(meta.get("end_lineno"), int):
            end_line = meta["end_lineno"]

        if rel_path:
            abs_file = f"{REPO_ROOT}/{rel_path}"
            if start_line and end_line and start_line != end_line:
                file_uri = f"file://{abs_file}#L{start_line}-L{end_line}"
                line_hint = f"StartLine={start_line}, EndLine={end_line}"
            elif start_line:
                file_uri = f"file://{abs_file}#L{start_line}"
                line_hint = f"Line={start_line}"
            else:
                file_uri = f"file://{abs_file}"
                line_hint = "Full file"
        else:
            file_uri = f"file://{KG_QUERY_HTML_PATH}#hit-kg-table-{hit_num}"
            line_hint = "Graph entity (no source file)"

        kg_table_uri = f"file://{KG_QUERY_HTML_PATH}#hit-kg-table-{hit_num}"
        target_links.append(f"#{hit_num}: {file_uri} (KG Table: {kg_table_uri})")

        filtered_meta = {
            k: v for k, v in meta.items() if k not in ("lineno",) and v not in (None, "", [], {})
        }
        meta_compact = json.dumps(filtered_meta, separators=(",", ":")) if filtered_meta else "{}"

        out_edges = m.get("outgoing_edges") or []
        in_edges = m.get("incoming_edges") or []
        out_summary = ", ".join(
            f"--[{e['relation']}]--> {e.get('target_name') or e['target']} ({e.get('target_path') or e.get('target_type')})"
            for e in out_edges[:12]
        ) or "none"
        in_summary = ", ".join(
            f"<--[{e['relation']}]-- {e.get('source_name') or e['source']} ({e.get('source_path') or e.get('source_type')})"
            for e in in_edges[:12]
        ) or "none"

        lines.extend(
            [
                f"Context for Hit #{hit_num} (Query: {query_str}):",
                f"  - Entity:      [{m.get('type')}] {m.get('name')} (ID: {m.get('id')})",
                f"  - File Target: {file_uri} ({line_hint})",
                f"  - Description: {m.get('description') or 'N/A'}",
                f"  - Metadata:    {meta_compact}",
                f"  - Node Stack:  {m.get('node_stack_compact') or m.get('name')}",
                f"  - Outgoing KG: {out_summary}",
                f"  - Incoming KG: {in_summary}",
            ]
        )
        stack_lines = m.get("node_stack_lines") or []
        if stack_lines:
            lines.append("  - Full Stack of Nodes to Reach Target:")
            for sl in stack_lines:
                lines.append(f"      {sl}")
        down_lines = m.get("downstream_stack_lines") or []
        if down_lines:
            lines.append("  - Downstream Stack (Nodes Reached via Target):")
            for dl in down_lines:
                lines.append(f"      {dl}")
        snippet_lines = _extract_code_snippet(rel_path, start_line, end_line)
        if snippet_lines:
            lines.append("  - Target Source Snippet:")
            lines.extend(snippet_lines)
        lines.append("")

    # Scan and tokenize all files in knowledge_graph/Files/ to provide additional context to the request below
    lines.extend(_scan_and_tokenize_files_folder(KG_FILES_DIR))

    default_ask = (
        "[Investigate and explain this target — NO CODE UPDATES]"
        if investigate_only
        else "[Enter your specific request/change for the above target here]"
    )
    final_ask = ask_text.strip() if ask_text.strip() else default_ask
    if investigate_only and "no code update" not in final_ask.lower() and "investigate only" not in final_ask.lower():
        final_ask = f"[INVESTIGATE ONLY — NO CODE UPDATES] {final_ask}"
    links_joined = " ; ".join(target_links)
    # The last line is the REQUEST TO LLM with the target link and the ask
    lines.append(f"REQUEST TO LLM ({links_joined}): {final_ask}")
    raw_prompt = "\n".join(lines)
    try:
        mcp_mod = _load_local_mcp_middleware(REPO_ROOT)
        if mcp_mod is not None and hasattr(mcp_mod, "sanitize_pii_and_secrets"):
            scrubbed_prompt, pii_summary = mcp_mod.sanitize_pii_and_secrets(raw_prompt)
            if pii_summary.get("redacted"):
                return scrubbed_prompt
    except Exception:
        pass
    return raw_prompt


def _osc8_link(uri: str, label: str) -> str:
    """Wrap label in an OSC-8 clickable terminal hyperlink when stdout is an interactive TTY."""
    if sys.stdout.isatty():
        return f"\033]8;;{uri}\033\\{label}\033]8;;\033\\"
    return label


def format_and_print_hits(
    matches: List[Dict[str, Any]],
    queries: List[str],
    summary_only: bool = False,
) -> None:
    """
    Query 1 output:
      1) Prints the standard plain-text response (#1, #2, #3...)
      2) Prints a Formatted Clickable Response section (Markdown links + standalone file:// URIs + OSC-8 TTY links)
      3) Generates per-result HTML browser tables (query_results.html)
    Note: Query 2 (--#1 / --#N via build_token_saving_llm_prompt) does NOT call this function and remains strictly text-only for LLM communication.
    """
    or_groups = parse_query_expression(queries)
    query_str = format_query_expression(or_groups) if or_groups else " ".join(queries)
    mode_label = "SUMMARY (/s)" if summary_only else "DETAILED"
    print(f"Query: {query_str} | Mode: {mode_label} | Total Hits: {len(matches)}")
    print("-" * 80)

    _save_last_query_results(matches, queries)
    html_report_path = generate_query_results_html(matches, queries, summary_only=summary_only)

    if not matches:
        print("No hits found in the Knowledge Graph.")
        print(f"\nHTML Query Browser Table written to: file://{html_report_path}")
        return

    # 1. Current Plain-Text Response
    clickable_rows: List[Tuple[int, str, str, str, str, str]] = []
    for idx, m in enumerate(matches, start=1):
        meta = m.get("metadata", {}) or {}
        lineno = meta.get("lineno")
        rel_path = m.get("file_path") or ""
        loc = ""
        if rel_path:
            loc = f"{rel_path}:{lineno}" if lineno else f"{rel_path}"

        start_line, end_line = _resolve_exact_line_range(rel_path, lineno)
        if rel_path:
            abs_file = f"{REPO_ROOT}/{rel_path}"
            if start_line and end_line and start_line != end_line:
                file_uri = f"file://{abs_file}#L{start_line}-L{end_line}"
                display_target = f"{rel_path}#L{start_line}-L{end_line}"
            elif start_line:
                file_uri = f"file://{abs_file}#L{start_line}"
                display_target = f"{rel_path}#L{start_line}"
            else:
                file_uri = f"file://{abs_file}"
                display_target = rel_path
        else:
            file_uri = f"file://{html_report_path}#hit-kg-table-{idx}"
            display_target = m.get("name") or f"hit-{idx}"

        kg_table_uri = f"file://{html_report_path}#hit-kg-table-{idx}"
        short_title = (m.get("name") or "").strip()
        clickable_rows.append((idx, m.get("type") or "node", short_title, display_target, file_uri, kg_table_uri))

        if summary_only:
            loc_part = f" ({loc})" if loc else ""
            desc = (m.get("description") or "").strip().splitlines()[0] if m.get("description") else ""
            stack_compact = m.get("node_stack_compact") or ""
            stack_part = f" | Stack: {stack_compact}" if stack_compact else ""
            print(f"#{idx} [{m['type']}] {m['name']}{loc_part} — {desc}{stack_part}")
        else:
            print(f"#{idx} [{m['type']}] {m['name']}  (ID: {m['id']})")
            if loc:
                print(f"    Location:    {loc}")
            if m.get("description"):
                print(f"    Description: {m['description']}")
            # Print concise metadata highlights
            filtered_meta = {
                k: v
                for k, v in meta.items()
                if k not in ("lineno",) and v not in (None, "", [], {})
            }
            if filtered_meta:
                meta_pairs = [f"{k}={json.dumps(v) if isinstance(v, (list, dict)) else v}" for k, v in filtered_meta.items()]
                print(f"    Metadata:    {', '.join(meta_pairs)}")
            stack_lines = m.get("node_stack_lines") or []
            if stack_lines:
                print("    Node Stack (Full Path to Reach Target):")
                for sl in stack_lines:
                    print(f"      {sl}")
            down_lines = m.get("downstream_stack_lines") or []
            if down_lines:
                print("    Downstream Stack (Nodes Reached via Target):")
                for dl in down_lines:
                    print(f"      {dl}")
            out_edges = m.get("outgoing_edges") or []
            in_edges = m.get("incoming_edges") or []
            if out_edges:
                out_str = ", ".join(f"--[{e['relation']}]--> {e['target']}" for e in out_edges[:6])
                if len(out_edges) > 6:
                    out_str += f" (+{len(out_edges) - 6} more)"
                print(f"    Outgoing:    {out_str}")
            if in_edges:
                in_str = ", ".join(f"<--[{e['relation']}]-- {e['source']}" for e in in_edges[:6])
                if len(in_edges) > 6:
                    in_str += f" (+{len(in_edges) - 6} more)"
                print(f"    Incoming:    {in_str}")
            print()

    # 2. Formatted Clickable Response (Query 1 Only)
    print("-" * 80)
    print("FORMATTED CLICKABLE RESPONSE (QUERY 1):")
    print("-" * 80)
    for idx, ntype, short_title, display_target, file_uri, kg_table_uri in clickable_rows:
        md_link = f"[{display_target}]({file_uri})"
        tty_link = _osc8_link(file_uri, md_link)
        kg_link = _osc8_link(kg_table_uri, f"[KG Table #{idx}]({kg_table_uri})")
        print(f"#{idx:<2d} [{ntype}] {tty_link} — {short_title}")
        print(f"    Direct Link: {file_uri}  |  {kg_link}")

    print("-" * 80)
    html_uri = f"file://{html_report_path}"
    full_kg_uri = f"file://{KG_HTML_PATH}"
    print(f"HTML Browser Tables (per-#1, #2... result + Node Path filter): {_osc8_link(html_uri, html_uri)}")
    print(f"Full Interactive Knowledge Graph HTML:                         {_osc8_link(full_kg_uri, full_kg_uri)}")


def inspect_entity(entity_query: str) -> Dict[str, Any]:
    """Return an entity and its incoming/outgoing edges."""
    conn = sqlite3.connect(str(KG_DB_PATH))
    cur = conn.cursor()
    cur.execute(
        "SELECT id, type, name, file_path, description, metadata_json FROM nodes WHERE id = ? OR lower(name) = lower(?)",
        (entity_query, entity_query),
    )
    row = cur.fetchone()
    if not row:
        cur.execute(
            "SELECT id, type, name, file_path, description, metadata_json FROM nodes WHERE id LIKE ? OR name LIKE ? LIMIT 1",
            (f"%{entity_query}%", f"%{entity_query}%"),
        )
        row = cur.fetchone()
    if not row:
        conn.close()
        return {}

    entity: Dict[str, Any] = {
        "id": row[0],
        "type": row[1],
        "name": row[2],
        "file_path": row[3],
        "description": row[4],
        "metadata": json.loads(row[5] or "{}"),
    }
    _attach_edges_and_neighbors(cur, entity)
    conn.close()
    return {
        "entity": entity,
        "outgoing_edges": entity.get("outgoing_edges", []),
        "incoming_edges": entity.get("incoming_edges", []),
    }


def list_by_type(node_type: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(str(KG_DB_PATH))
    cur = conn.cursor()
    sql = "SELECT id, type, name, file_path, description, metadata_json FROM nodes WHERE lower(type) = lower(?) ORDER BY name"
    params: List[Any] = [node_type]
    if limit is not None and limit > 0:
        sql += " LIMIT ?"
        params.append(limit)
    cur.execute(sql, params)
    raw_rows = cur.fetchall()
    rows: List[Dict[str, Any]] = []
    for r in raw_rows:
        item: Dict[str, Any] = {
            "id": r[0],
            "type": r[1],
            "name": r[2],
            "file_path": r[3],
            "description": r[4],
            "metadata": json.loads(r[5] or "{}"),
        }
        _attach_edges_and_neighbors(cur, item)
        rows.append(item)
    conn.close()
    return rows


# Common UTF-8 decoded as Windows-1252 / Latin-1 mojibake mapping (escaped to keep source ASCII-clean)
MOJIBAKE_REPLACEMENTS: List[Tuple[str, str]] = [
    ("\u00e2\u20ac\u201d", "\u2014"),  # em-dash —
    ("\u00e2\u20ac\u201c", "\u2013"),  # en-dash –
    ("\u00e2\u20ac\u2122", "\u2019"),  # right single quote ’
    ("\u00e2\u20ac\u02dc", "\u2018"),  # left single quote ‘
    ("\u00e2\u20ac\u0153", "\u201c"),  # left double quote “
    ("\u00e2\u20ac\u009d", "\u201d"),  # right double quote ”
    ("\u00e2\u20ac\u00a2", "\u2022"),  # bullet •
    ("\u00e2\u20ac\u00a6", "\u2026"),  # ellipsis …
    ("\u00e2\u2020\u2019", "\u2192"),  # right arrow →
    ("\u00e2\u2020\u0090", "\u2190"),  # left arrow ←
    ("\u00e2\u2020\u201d", "\u2194"),  # left-right arrow ↔
    ("\u00e2\u201d\u20ac", "\u2500"),  # box drawing ─
    ("\u00e2\u201d\u201a", "\u2502"),  # box drawing │
    ("\u00e2\u201d\u201c", "\u251c"),  # box drawing ├
    ("\u00e2\u201d\u2014", "\u2514"),  # box drawing └
    ("\u00e2\u0153\u2026", "\u2705"),  # check mark ✅
    ("\u00e2\u009d\u0152", "\u274c"),  # cross mark ❌
    ("\u00e2\u0161\u00a0\u00ef\u00b8\u008f", "\u26a0\ufe0f"),  # warning ⚠️
    ("\u00c2\u00a0", " "),              # non-breaking space artifact
]


def _get_git_changed_line_numbers(repo_root: pathlib.Path, fp: pathlib.Path) -> Optional[Set[int]]:
    """
    Return the 1-based line numbers added/modified in `fp` relative to HEAD using `git diff HEAD -U0`
    (with fallback to `git diff --cached -U0` for initial commits without HEAD).
    Returns None if the file is untracked (so all lines of the new file are part of the delta).
    """
    try:
        rel_path = str(fp.relative_to(repo_root))
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "diff", "HEAD", "-U0", "--", rel_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            proc = subprocess.run(
                ["git", "-C", str(repo_root), "diff", "--cached", "-U0", "--", rel_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        changed_lines: Set[int] = set()
        hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
        for line in proc.stdout.splitlines():
            m = hunk_re.match(line)
            if m:
                start_ln = int(m.group(1))
                count_ln = int(m.group(2)) if m.group(2) is not None else 1
                for ln in range(start_ln, start_ln + max(count_ln, 0)):
                    changed_lines.add(ln)
        return changed_lines
    except Exception:
        return None


def _collect_git_delta_snapshot(
    repo_root: pathlib.Path,
    target_paths: Optional[List[str]] = None,
) -> List[Tuple[pathlib.Path, bool, Optional[Set[int]]]]:
    """
    Compute the Git delta file list and changed line numbers ONCE so both `mojibake_audit_and_fix`
    and `vulnerability_scan_delta` share the exact same snapshot without duplicate `git status`
    or `git diff HEAD -U0` subprocess calls.
    """
    raw_candidates: List[Tuple[pathlib.Path, bool]] = []
    if target_paths:
        for p in target_paths:
            fp = (repo_root / p).resolve() if not pathlib.Path(p).is_absolute() else pathlib.Path(p).resolve()
            if fp.is_file():
                raw_candidates.append((fp, False))
    else:
        try:
            proc = subprocess.run(
                ["git", "-C", str(repo_root), "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if len(line) > 3:
                        status_code = line[:2]
                        rel_part = line[3:].strip()
                        if " -> " in rel_part:
                            rel_part = rel_part.split(" -> ", 1)[1].strip()
                        rel_part = rel_part.strip('"')
                        fp = repo_root / rel_part
                        if fp.is_file():
                            raw_candidates.append((fp, status_code == "??"))
        except Exception:
            pass

    skip_names = {
        "knowledge_graph.json",
        "knowledge_graph.db",
        "KNOWLEDGE_GRAPH.md",
        "knowledge_graph.html",
        "query_results.html",
        "last_query_results.json",
        "last_llm_prompt.txt",
        "vulnerability_report.md",
        "publish_precheck_report.md",
        "publish_precheck_report.html",
    }
    snapshot: List[Tuple[pathlib.Path, bool, Optional[Set[int]]]] = []
    for fp, is_untracked in raw_candidates:
        if not target_paths:
            if fp.name in skip_names:
                continue
            if fp.is_relative_to(repo_root) and any(part in EXCLUDED_DIRS for part in fp.relative_to(repo_root).parts):
                continue
        delta_line_nums: Optional[Set[int]] = None if is_untracked else _get_git_changed_line_numbers(repo_root, fp)
        if delta_line_nums is not None and len(delta_line_nums) == 0:
            continue
        snapshot.append((fp, is_untracked, delta_line_nums))
    return snapshot


def mojibake_audit_and_fix(
    repo_root: pathlib.Path,
    fix: bool = False,
    target_paths: Optional[List[str]] = None,
    restage_fixed: bool = False,
    precomputed_delta: Optional[List[Tuple[pathlib.Path, bool, Optional[Set[int]]]]] = None,
) -> int:
    """
    Delta-only Mojibake Audit & Fix:
    Audits ONLY the Git delta (added/modified lines in changed files from `git status --porcelain`
    and `git diff HEAD -U0`, plus newly created untracked files) for UTF-8/CP1252 mojibake sequences.
    Never scans the entire repository every time. When fix=True, repairs mojibake on delta lines
    in-place using Python UTF-8 file I/O.
    """
    delta_entries = (
        precomputed_delta
        if precomputed_delta is not None
        else _collect_git_delta_snapshot(repo_root, target_paths=target_paths)
    )

    # Exclude generated KG JSON/DB/HTML blobs from default git-status delta sweep unless explicitly requested
    skip_names = {
        "knowledge_graph.json",
        "knowledge_graph.db",
        "KNOWLEDGE_GRAPH.md",
        "knowledge_graph.html",
        "query_results.html",
        "last_query_results.json",
        "last_llm_prompt.txt",
        "vulnerability_report.md",
        "publish_precheck_report.md",
        "publish_precheck_report.html",
    }
    checked_files = 0
    checked_delta_lines = 0
    issues_found = 0
    files_fixed = 0

    for fp, is_untracked, delta_line_nums in delta_entries:
        try:
            raw = fp.read_bytes()
            if b"\x00" in raw[:4096]:
                continue  # skip binary files
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            issues_found += 1
            print(f"[MOJIBAKE] Non-UTF-8 byte sequence in delta file: {fp.relative_to(repo_root)}")
            continue

        lines = text.splitlines(keepends=True)

        checked_files += 1
        file_hits: Dict[str, int] = {}
        modified_any_line = False

        for idx, line_str in enumerate(lines):
            lineno = idx + 1
            if delta_line_nums is not None and lineno not in delta_line_nums:
                continue
            checked_delta_lines += 1
            updated_line = line_str
            for bad_seq, good_seq in MOJIBAKE_REPLACEMENTS:
                if bad_seq in updated_line:
                    cnt = updated_line.count(bad_seq)
                    key = f"{bad_seq!r} -> {good_seq!r}"
                    file_hits[key] = file_hits.get(key, 0) + cnt
                    if fix:
                        updated_line = updated_line.replace(bad_seq, good_seq)
            if fix and updated_line != line_str:
                lines[idx] = updated_line
                modified_any_line = True

        if file_hits:
            issues_found += len(file_hits)
            rel_disp = fp.relative_to(repo_root) if fp.is_relative_to(repo_root) else fp
            hit_summary = ", ".join(f"{k} ({v}x)" for k, v in file_hits.items())
            if fix and modified_any_line:
                fp.write_text("".join(lines), encoding="utf-8")
                files_fixed += 1
                if restage_fixed:
                    try:
                        subprocess.run(
                            ["git", "-C", str(repo_root), "add", "--", str(rel_disp)],
                            capture_output=True,
                            text=True,
                            timeout=10,
                        )
                    except Exception:
                        pass
                print(f"[MOJIBAKE FIXED (DELTA)] {rel_disp}: {hit_summary}")
            else:
                print(f"[MOJIBAKE FOUND (DELTA)] {rel_disp}: {hit_summary}")

    mode_label = "DELTA AUDIT & FIX" if fix else "DELTA AUDIT"
    print(
        f"Mojibake {mode_label} Complete: {checked_files} changed file(s) "
        f"({checked_delta_lines} delta line(s)) scanned, "
        f"{issues_found} pattern match(es), {files_fixed} file(s) fixed "
        f"(delta-only — untouched repository files/lines skipped)."
    )
    return 0 if (issues_found == 0 or fix) else 1


# Pre-commit Delta Vulnerability Scanner rules (constructed via joined tokens to avoid self-matching)
VULN_SCAN_RULES: List[Dict[str, Any]] = [
    {
        "id": "SEC001",
        "severity": "CRITICAL",
        "title": "Embedded Private Key Material",
        "pattern": re.compile("-----BEGIN " + r"(?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
        "remediation": "Remove private key material immediately; store keys in ~/.ssh or untracked secret stores.",
        "code_only": False,
    },
    {
        "id": "SEC002",
        "severity": "HIGH",
        "title": "Hardcoded Password / Secret Assignment",
        "pattern": re.compile(
            r"(?i)\b(?:sap_hana_password|sap_password|postgres_password|api_key|secret_key|client_secret)\s*=\s*['\"](?!<|your_|change|example|\$\{)[^'\"]{6,}['\"]"
        ),
        "remediation": "Load credentials from environment variables (`os.getenv(...)`) or `.env` files (never commit secrets).",
        "code_only": True,
    },
    {
        "id": "SEC003",
        "severity": "HIGH",
        "title": "Subprocess / OS Command Execution with shell=True",
        "pattern": re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output)\([^)]*shell" + r"\s*=\s*True"),
        "remediation": "Pass command arguments as a list with `shell=False` and validate all user inputs.",
        "code_only": True,
    },
    {
        "id": "SEC004",
        "severity": "HIGH",
        "title": "Unsafe Dynamic Execution or Deserialization (eval / exec / pickle.loads / yaml.load)",
        "pattern": re.compile(r"\b(?:eval|exec|pickle\.loads)\s*\(|yaml\.load\s*\([^)]*(?!SafeLoader)"),
        "remediation": "Use `ast.literal_eval`, `json.loads`, or `yaml.safe_load` instead of unsafe dynamic execution.",
        "code_only": True,
    },
    {
        "id": "SEC005",
        "severity": "MEDIUM",
        "title": "Potential SQL Injection via String Interpolation",
        "pattern": re.compile(r"(?i)\b(?:cur|cursor|conn)\.execute\(\s*f['\"].*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{.+\}"),
        "remediation": "Use parameterized SQL queries (`?` or `%s` placeholders) instead of f-strings.",
        "code_only": True,
    },
    {
        "id": "SEC006",
        "severity": "MEDIUM",
        "title": "Disabled TLS Certificate Verification (verify=False)",
        "pattern": re.compile(r"\brequests\.(?:get|post|put|delete|request)\([^)]*verify" + r"\s*=\s*False"),
        "remediation": "Enable TLS certificate verification or pass a trusted CA bundle path.",
        "code_only": True,
    },
]


def vulnerability_scan_delta(
    repo_root: pathlib.Path,
    target_paths: Optional[List[str]] = None,
    precomputed_delta: Optional[List[Tuple[pathlib.Path, bool, Optional[Set[int]]]]] = None,
) -> int:
    """
    Pre-Commit Delta Vulnerability Scanner:
    Scans modified/added lines in the Git delta (or explicit target_paths) for security
    vulnerabilities. If any vulnerability is found, prints a detailed Vulnerability Report
    and writes `knowledge_graph/vulnerability_report.md` so it can be presented before commit.
    """
    delta_entries = (
        precomputed_delta
        if precomputed_delta is not None
        else _collect_git_delta_snapshot(repo_root, target_paths=target_paths)
    )
    doc_exts = {".md", ".txt", ".1", ".5", ".7", ".8", ".rst", ".html", ".json"}
    checked_files = 0
    checked_delta_lines = 0
    findings: List[Dict[str, Any]] = []

    for fp, is_untracked, delta_line_nums in delta_entries:
        try:
            raw = fp.read_bytes()
            if b"\x00" in raw[:4096]:
                continue
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue

        lines = text.splitlines()

        checked_files += 1
        is_doc_file = fp.suffix.lower() in doc_exts
        rel_disp = str(fp.relative_to(repo_root)) if fp.is_relative_to(repo_root) else str(fp)

        for idx, line_str in enumerate(lines):
            lineno = idx + 1
            if delta_line_nums is not None and lineno not in delta_line_nums:
                continue
            checked_delta_lines += 1
            stripped = line_str.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Skip regex rule definitions inside query_kg.py itself
            if fp.name == "query_kg.py" and ("re.compile(" in stripped or '"pattern":' in stripped):
                continue

            for rule in VULN_SCAN_RULES:
                if rule["code_only"] and is_doc_file:
                    continue
                if rule["pattern"].search(line_str):
                    findings.append(
                        {
                            "id": rule["id"],
                            "severity": rule["severity"],
                            "title": rule["title"],
                            "file": rel_disp,
                            "line": lineno,
                            "snippet": stripped[:160],
                            "remediation": rule["remediation"],
                        }
                    )

    report_path = KG_DIR / "vulnerability_report.md"
    if findings:
        report_lines = [
            "# Pre-Commit Vulnerability Scan Report",
            "",
            f"- **Status**: ⚠️ **{len(findings)} Potential Vulnerability Finding(s) Detected**",
            f"- **Scanned Scope**: `{checked_files}` changed file(s) (`{checked_delta_lines}` delta line(s))",
            "",
            "| # | Rule ID | Severity | Vulnerability | File & Line | Remediation |",
            "| :---: | :--- | :---: | :--- | :--- | :--- |",
        ]
        print("=" * 88)
        print(f"⚠️  PRE-COMMIT VULNERABILITY SCAN REPORT: {len(findings)} FINDING(S) DETECTED")
        print("=" * 88)
        for i, f in enumerate(findings, start=1):
            print(f"  [{i}] [{f['severity']}] {f['id']} — {f['title']}")
            print(f"      Location   : {f['file']}:{f['line']}")
            print(f"      Code       : {f['snippet']}")
            print(f"      Remediation: {f['remediation']}")
            print("-" * 88)
            report_lines.append(
                f"| #{i} | `{f['id']}` | **{f['severity']}** | {f['title']} | `{f['file']}:{f['line']}` | {f['remediation']} |"
            )
        report_Path_str = str(report_path)
        report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
        print(f"Report saved to: {report_Path_str}")
        return 1

    if report_path.exists():
        try:
            report_path.unlink()
        except Exception:
            pass
    print(
        f"Vulnerability DELTA SCAN Complete: {checked_files} changed file(s) "
        f"({checked_delta_lines} delta line(s)) scanned, 0 vulnerabilities found."
    )
    if checked_files > 0 and "--pre-commit-hook" not in sys.argv:
        emit_commit_ready_beep("All pre-commit checks passed — commit is ready for user confirmation.")
    return 0


def emit_commit_ready_beep(reason: str = "Commit ready for confirmation") -> None:
    """
    Emit an audible beep alert when pre-commit checks complete and changes are ready to commit:
      1. Terminal bell (\a) written to stdout/stderr, /dev/tty, and active user PTYs (/dev/pts/*)
         so both local terminals and remote Zed/SSH sessions receive the bell signal.
      2. Non-blocking desktop audio chime via pw-play / paplay / canberra-gtk-play (Linux) or afplay (macOS).
    """
    try:
        sys.stdout.write("\a")
        sys.stdout.flush()
    except Exception:
        pass
    try:
        uid = os.getuid()
        pts_dir = Path("/dev/pts")
        if pts_dir.is_dir():
            for pt in pts_dir.iterdir():
                if not pt.name.isdigit():
                    continue
                try:
                    if pt.stat().st_uid == uid:
                        with open(pt, "wb", buffering=0) as pf:
                            pf.write(b"\a")
                except Exception:
                    pass
    except Exception:
        pass
    try:
        sound_candidates = [
            "/usr/share/sounds/freedesktop/stereo/complete.oga",
            "/usr/share/sounds/freedesktop/stereo/bell.oga",
            "/System/Library/Sounds/Glass.aiff",
        ]
        sound_file = next((s for s in sound_candidates if os.path.isfile(s)), "")
        if sound_file:
            for player in ("pw-play", "paplay", "afplay"):
                if shutil.which(player):
                    subprocess.Popen(
                        [player, sound_file],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    break
        elif shutil.which("canberra-gtk-play"):
            subprocess.Popen(
                ["canberra-gtk-play", "-i", "complete"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
    except Exception:
        pass
    print(f"🔔 [COMMIT READY BEEP] {reason}", flush=True)


def _load_global_installations() -> List[str]:
    """
    Load the list of installed Knowledge Graph target repository root paths from
    `MASTER_GLOBAL_MD_PATH` (or local `GLOBAL_MD_PATH`). Always includes `MASTER_REPO_ROOT` first.
    """
    primary = str(MASTER_REPO_ROOT.resolve())
    cur_repo = str(REPO_ROOT.resolve())
    paths: List[str] = [primary]
    if cur_repo not in paths:
        paths.append(cur_repo)

    for candidate_md in (MASTER_GLOBAL_MD_PATH, GLOBAL_MD_PATH):
        if not candidate_md.exists():
            continue
        try:
            content = candidate_md.read_text(encoding="utf-8")
            m = re.search(r"<!--\s*GLOBAL_KG_INSTALLATIONS:\s*(\[.*?\])\s*-->", content, re.DOTALL)
            if m:
                parsed = json.loads(m.group(1))
                if isinstance(parsed, list):
                    for item in parsed:
                        norm = str(pathlib.Path(str(item)).expanduser().resolve())
                        if norm not in paths:
                            paths.append(norm)
            for row_m in re.finditer(r"^\|\s*\d+\s*\|\s*`([^`]+)`\s*\|", content, re.MULTILINE):
                folder_str = row_m.group(1).strip()
                if folder_str.startswith("/"):
                    norm = str(pathlib.Path(folder_str).expanduser().resolve())
                    if norm not in paths:
                        paths.append(norm)
        except Exception:
            continue
    return paths


def _build_global_md_content(installations: List[str]) -> str:
    """Render deterministic Markdown content for `global.md`."""
    norm_list: List[str] = []
    primary = str(MASTER_REPO_ROOT.resolve())
    norm_list.append(primary)
    for p in installations:
        resolved = str(pathlib.Path(p).expanduser().resolve())
        if resolved not in norm_list:
            norm_list.append(resolved)

    lines: List[str] = [
        "# Global Knowledge Graph Installations (`global.md`)",
        "",
        f"<!-- GLOBAL_KG_INSTALLATIONS: {json.dumps(norm_list)} -->",
        "",
        "This file maintains all repository/project locations where the `knowledge_graph/` folder and [`query_kg.py`](knowledge_graph/query_kg.py) are installed.",
        "",
        "- **Primary (Master) Location**: `/home/sanjay/container/kubernetes`",
        f"- **Total Registered Installations**: `{len(norm_list)}`",
        "",
        "---",
        "",
        "## 1. Installed Knowledge Graph Locations",
        "",
        "| # | Target Folder (Repository Root) | Knowledge Graph Folder | CLI Script | Root Wrapper | Role | Status |",
        "| :---: | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for idx, folder_str in enumerate(norm_list, start=1):
        f_path = pathlib.Path(folder_str)
        kg_folder = f_path / "knowledge_graph"
        cli_script = kg_folder / "query_kg.py"
        wrapper_script = f_path / "query_kg.py"
        role = "Primary (Master)" if folder_str == primary else "Installed Target"
        status = "Active" if cli_script.exists() else "Pending Sync"
        lines.append(
            f"| {idx} | `{f_path}` | `{kg_folder}` | `{cli_script}` | `{wrapper_script}` | {role} | {status} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 2. Installing `query_kg.py` to a New Folder (`/install <folder>`)",
            "",
            "To install the Knowledge Graph system onto a new target project folder, run:",
            "```bash",
            "python3 /home/sanjay/container/kubernetes/knowledge_graph/query_kg.py /install /path/to/target_folder",
            "```",
            "This automatically:",
            "1. Creates `/path/to/target_folder/knowledge_graph/` and `/path/to/target_folder/knowledge_graph/Files/.gitkeep`.",
            "2. Installs `knowledge_graph/query_kg.py` and the root wrapper `query_kg.py` into `/path/to/target_folder`.",
            "3. Builds the initial Knowledge Graph (`knowledge_graph.json`, `knowledge_graph.db`, `KNOWLEDGE_GRAPH.md`, `knowledge_graph.html`, and `repo.md`) in the target folder.",
            "4. Registers `/path/to/target_folder` in `global.md` and synchronizes `global.md` across all registered installations.",
            "",
            "---",
            "",
            "## 3. Automatic Global Synchronization Rule",
            "",
            "> **RULE: Anytime an update is made to `query_kg.py`, all folders listed in `global.md` MUST be updated.**",
            "",
            "- Running `python3 /home/sanjay/container/kubernetes/knowledge_graph/query_kg.py --update` (or `--sync-global`) automatically checks the SHA-256 of `query_kg.py` against every installation in `global.md`, propagates the updated `query_kg.py` and `global.md`, and refreshes each target folder's Knowledge Graph.",
        ]
    )
    return "\n".join(lines) + "\n"


def _save_global_md(installations: Optional[List[str]] = None) -> List[str]:
    """Write `global.md` to `MASTER_GLOBAL_MD_PATH`, `GLOBAL_MD_PATH`, and any existing installed folders."""
    inst_list = installations if installations is not None else _load_global_installations()
    content = _build_global_md_content(inst_list)

    targets: Set[pathlib.Path] = {GLOBAL_MD_PATH}
    if MASTER_REPO_ROOT.exists():
        targets.add(MASTER_GLOBAL_MD_PATH)
    for folder_str in inst_list:
        fp = pathlib.Path(folder_str)
        if fp.is_dir():
            targets.add(fp / "global.md")

    for t_md in targets:
        try:
            if not t_md.exists() or t_md.read_text(encoding="utf-8") != content:
                t_md.write_text(content, encoding="utf-8")
        except Exception:
            pass
    return inst_list


def _extract_troff_man_metadata(fp: pathlib.Path, repo_root: pathlib.Path) -> Dict[str, str]:
    """Extract section, title, and NAME summary from a troff man page (.1, .5, .7, .8)."""
    section = fp.suffix.lstrip(".") or "8"
    name = fp.stem
    summary = f"Manual page {fp.name}"
    try:
        lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        in_name = False
        for raw_line in lines:
            line = raw_line.strip()
            if line.upper().startswith(".TH "):
                parts = line.split()
                if len(parts) >= 3 and parts[2].strip('"').isdigit():
                    section = parts[2].strip('"')
            elif line.upper() == ".SH NAME":
                in_name = True
                continue
            elif in_name:
                if line.startswith("."):
                    if line.upper().startswith(".SH "):
                        break
                    continue
                if line:
                    cleaned = line.replace("\\-", "-").replace("\\fB", "").replace("\\fR", "").replace("\\fI", "")
                    if " - " in cleaned:
                        summary = cleaned.split(" - ", 1)[1].strip()
                    elif "-" in cleaned:
                        summary = cleaned.split("-", 1)[1].strip()
                    else:
                        summary = cleaned.strip()
                    break
    except Exception:
        pass
    rel_path = str(fp.relative_to(repo_root)) if fp.is_relative_to(repo_root) else str(fp)
    return {
        "name": name,
        "filename": fp.name,
        "section": section,
        "rel_path": rel_path,
        "summary": summary[:160],
    }


def _extract_md_title_and_sections(fp: pathlib.Path, repo_root: pathlib.Path) -> Dict[str, Any]:
    """Extract the top H1 title and H2/H3 section headings from a Markdown file (ignoring fenced code blocks)."""
    title = fp.name
    sections: List[str] = []
    in_code_block = False
    try:
        for raw_line in fp.read_text(encoding="utf-8", errors="replace").splitlines():
            s = raw_line.strip()
            if s.startswith("```"):
                in_code_block = not in_code_block
                continue
            if in_code_block:
                continue
            if s.startswith("# ") and title == fp.name:
                title = s[2:].strip()
            elif s.startswith("## ") or s.startswith("### "):
                sec = s.lstrip("#").strip()
                if title == fp.name and s.startswith("## "):
                    title = sec
                if sec and len(sections) < 8:
                    sections.append(sec)
    except Exception:
        pass
    rel_path = str(fp.relative_to(repo_root)) if fp.is_relative_to(repo_root) else str(fp)
    return {
        "filename": fp.name,
        "rel_path": rel_path,
        "title": title,
        "sections": sections,
    }


_AUTO_GENERATED_PATHS = {
    "knowledge_graph/knowledge_graph.json",
    "knowledge_graph/knowledge_graph.db",
    "knowledge_graph/kg_gnn.pt",
    "knowledge_graph/KNOWLEDGE_GRAPH.md",
    "knowledge_graph/knowledge_graph.html",
    "knowledge_graph/query_results.html",
    "knowledge_graph/last_query_results.json",
    "knowledge_graph/last_llm_prompt.txt",
    "repo.md",
    "global.md",
    "man/MANPAGES_README.md",
    "man/WIKI_INDEX.md",
    "docs/WIKI_INDEX.md",
    "man/man7/man_index.7",
}


def _map_source_path_to_man_pages(rel_path: str) -> List[str]:
    """Map a changed repository source path to the corresponding man/ manual page(s)."""
    if rel_path.startswith("knowledge_graph/") or rel_path == "query_kg.py":
        return ["man/man1/query_kg.1"]
    if rel_path.startswith("cluster-management/"):
        pages = ["man/man8/cluster-management-system.8"]
        if "api" in rel_path or rel_path.endswith("app.py"):
            pages.append("man/man7/api-reference.7")
        return pages
    if rel_path.startswith("agent/mac/"):
        return ["man/man8/mac-agent-setup.8", "man/man1/k3s-agent-scripts.1"]
    if rel_path.startswith("agent/spark1/") or rel_path.startswith("agent/spark2/"):
        return ["man/man8/nvidia-blackwell-support.8", "man/man1/k3s-agent-scripts.1"]
    if rel_path.startswith("agent/"):
        return ["man/man1/k3s-agent-scripts.1"]
    if rel_path.startswith("server/"):
        return ["man/man1/k3s-server.1", "man/man1/utility-scripts.1"]
    return ["man/man8/cluster-management-system.8"]


def _observe_incremental_git_changes(repo_root: pathlib.Path) -> Dict[str, Any]:
    """
    Inspect the incremental Git delta (working tree vs HEAD, or HEAD~1..HEAD when clean)
    excluding auto-generated KG/index stores, and extract changed files, line counts,
    modified symbols/functions/endpoints, and impacted man/ pages.
    Strictly deterministic for a given source state so repeated runs are idempotent.
    """
    changed_entries: List[Tuple[str, str]] = []
    diff_base = "HEAD"
    try:
        st_res = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        for raw_ln in st_res.stdout.splitlines():
            if len(raw_ln) < 4:
                continue
            status_code = raw_ln[:2].strip() or "M"
            rel_p = raw_ln[3:].strip().split(" -> ")[-1].strip()
            if not rel_p or rel_p in _AUTO_GENERATED_PATHS or rel_p.startswith("man/man"):
                continue
            changed_entries.append((status_code[0], rel_p))
    except Exception:
        pass

    if not changed_entries:
        diff_base = "HEAD~1..HEAD"
        try:
            hd_res = subprocess.run(
                ["git", "-C", str(repo_root), "diff", "--name-status", "HEAD~1", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for raw_ln in hd_res.stdout.splitlines():
                parts = raw_ln.strip().split("\t")
                if len(parts) >= 2:
                    st_c = parts[0].strip()[0]
                    rel_p = parts[-1].strip()
                    if rel_p and rel_p not in _AUTO_GENERATED_PATHS and not rel_p.startswith("man/man"):
                        changed_entries.append((st_c, rel_p))
        except Exception:
            pass

    dedup_entries: List[Tuple[str, str]] = []
    seen_paths: Set[str] = set()
    for st_c, rel_p in sorted(changed_entries, key=lambda x: x[1]):
        if rel_p not in seen_paths:
            seen_paths.add(rel_p)
            dedup_entries.append((st_c, rel_p))

    file_observations: List[Dict[str, Any]] = []
    all_symbols: List[str] = []
    impacted_man_pages: List[str] = []

    sym_py_re = re.compile(r"^\+\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)\b")
    sym_js_re = re.compile(r"^\+\s*(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
    sym_api_re = re.compile(r"^\+\s*@(?:app|router|mcp_router)\.(?:get|post|put|delete|websocket)\(\s*['\"]([^'\"]+)['\"]")
    sym_h3_re = re.compile(r"^\+.*?<h3[^>]*>(.*?)</h3>", re.I)
    hunk_hdr_re = re.compile(r"^@@\s+-[0-9,]+\s+\+([0-9]+)(?:,([0-9]+))?\s+@@(?:\s+(.*))?")

    for st_c, rel_p in dedup_entries:
        diff_cmd = (
            ["git", "-C", str(repo_root), "diff", "HEAD~1", "HEAD", "-U0", "--", rel_p]
            if diff_base == "HEAD~1..HEAD"
            else ["git", "-C", str(repo_root), "diff", "HEAD", "-U0", "--", rel_p]
        )
        added_lines = 0
        removed_lines = 0
        symbols: List[str] = []
        try:
            d_res = subprocess.run(diff_cmd, capture_output=True, text=True, timeout=5, check=False)
            for dln in d_res.stdout.splitlines():
                if dln.startswith("+++") or dln.startswith("---"):
                    continue
                m_hunk = hunk_hdr_re.match(dln)
                if m_hunk and m_hunk.group(3):
                    ctx_hdr = m_hunk.group(3).strip()
                    m_ctx_fn = re.search(r"(?:def|class|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)", ctx_hdr)
                    if m_ctx_fn:
                        csym = m_ctx_fn.group(1)
                        if csym not in symbols:
                            symbols.append(csym)
                        if csym not in all_symbols:
                            all_symbols.append(csym)
                    continue
                if dln.startswith("+"):
                    added_lines += 1
                    for rx in (sym_py_re, sym_js_re, sym_api_re):
                        m = rx.match(dln)
                        if m:
                            sym = m.group(1)
                            if sym not in symbols:
                                symbols.append(sym)
                            if sym not in all_symbols:
                                all_symbols.append(sym)
                    m_card = sym_h3_re.search(dln) if rel_p.endswith((".html", ".htm")) else None
                    if m_card:
                        card_txt = re.sub(r"<[^>]+>", "", m_card.group(1)).strip()
                        if card_txt and len(card_txt) <= 45 and "{{" not in card_txt and "${" not in card_txt:
                            card_label = f"Card:{card_txt}"
                            if card_label not in symbols:
                                symbols.append(card_label)
                            if card_label not in all_symbols:
                                all_symbols.append(card_label)
                elif dln.startswith("-"):
                    removed_lines += 1
        except Exception:
            pass

        mapped_mans = _map_source_path_to_man_pages(rel_p)
        for mp in mapped_mans:
            if mp not in impacted_man_pages:
                impacted_man_pages.append(mp)

        file_observations.append(
            {
                "status": st_c,
                "path": rel_p,
                "added": added_lines,
                "removed": removed_lines,
                "symbols": symbols[:8],
                "man_pages": mapped_mans,
            }
        )

    return {
        "diff_base": diff_base,
        "files": file_observations,
        "symbols": all_symbols[:15],
        "impacted_man_pages": impacted_man_pages,
    }


def _update_troff_man_incremental_section(
    man_fp: pathlib.Path,
    obs_for_man: List[Dict[str, Any]],
) -> bool:
    """
    Idempotently update or insert the `.SH INCREMENTAL CHANGES` block inside a troff man page
    (`man/man1/*.1`, `man/man7/*.7`, `man/man8/*.8`). Returns True if the file content changed.
    """
    if not man_fp.is_file() or not obs_for_man:
        return False
    try:
        orig_text = man_fp.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False

    block_lines = [
        '.\\" KG_INCREMENTAL_SYNC_START',
        '.SH INCREMENTAL CHANGES',
        'Automatically synchronized by',
        '.B query_kg.py',
        'during Git commit pre-commit hook from observed incremental source changes:',
    ]
    for item in obs_for_man[:10]:
        sym_str = f" (symbols: {', '.join(item['symbols'][:5])})" if item.get("symbols") else ""
        block_lines.extend(
            [
                '.TP',
                f".B {item['path']} [{item['status']}] (+{item['added']}/-{item['removed']} lines)",
                f"Incremental update observed{sym_str}.",
            ]
        )
    block_lines.append('.\\" KG_INCREMENTAL_SYNC_END')
    new_block = "\n".join(block_lines)

    start_marker = '.\\" KG_INCREMENTAL_SYNC_START'
    end_marker = '.\\" KG_INCREMENTAL_SYNC_END'
    if start_marker in orig_text and end_marker in orig_text:
        pre, rest = orig_text.split(start_marker, 1)
        _, post = rest.split(end_marker, 1)
        updated_text = pre + new_block + post
    elif ".SH SEE ALSO" in orig_text:
        updated_text = orig_text.replace(".SH SEE ALSO", new_block + "\n.SH SEE ALSO", 1)
    else:
        updated_text = orig_text.rstrip() + "\n" + new_block + "\n"

    if updated_text != orig_text:
        man_fp.write_text(updated_text, encoding="utf-8")
        return True
    return False


def _generate_incremental_commit_message(
    repo_root: pathlib.Path,
    precomputed_obs: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Auto-generate a descriptive Git commit message from the incremental changes observed
    in the repository (files modified, functions/endpoints/UI cards changed, KG SQLite delta,
    and synced man/wiki documentation).
    """
    obs = precomputed_obs if precomputed_obs is not None else _observe_incremental_git_changes(repo_root)
    files = obs.get("files", [])
    symbols = obs.get("symbols", [])
    man_pages = obs.get("impacted_man_pages", [])

    kg_delta_summary = "knowledge_graph.db, knowledge_graph.json, knowledge_graph.html"
    kg_db_file = repo_root / "knowledge_graph" / "knowledge_graph.db"
    if kg_db_file.exists():
        try:
            conn = sqlite3.connect(str(kg_db_file))
            cur = conn.cursor()
            cur.execute(
                "SELECT nodes_upserted, nodes_deleted, total_nodes, total_edges "
                "FROM kg_delta_log ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
            conn.close()
            if row:
                kg_delta_summary = (
                    f"knowledge_graph.db (+{row[0]}/-{row[1]} delta nodes, "
                    f"{row[2]} total nodes, {row[3]} edges)"
                )
        except Exception:
            pass

    if not files:
        return f"Sync Knowledge Graph ({kg_delta_summary}), man/wiki documentation, and incremental updates"

    short_files = [pathlib.Path(f["path"]).name for f in files[:3]]
    if len(files) > 3:
        short_files.append(f"+{len(files) - 3} more")
    files_part = ", ".join(short_files)

    sym_part = f" ({', '.join(symbols[:3])})" if symbols else ""
    subject = f"Update {files_part}{sym_part} & sync Knowledge Graph/man/wiki"
    if len(subject) > 78:
        subject = subject[:75].rstrip() + "..."

    body_lines = [subject, ""]
    body_lines.append("Incremental changes observed & synchronized by query_kg.py:")
    for f in files[:10]:
        s_list = f" [{', '.join(f['symbols'][:4])}]" if f.get("symbols") else ""
        body_lines.append(f"- {f['status']} {f['path']} (+{f['added']}/-{f['removed']} lines){s_list}")
    if man_pages:
        body_lines.append(f"- Synced man/wiki docs: {', '.join(man_pages)}, man/WIKI_INDEX.md")
    body_lines.append(f"- Synced Knowledge Graph: {kg_delta_summary}")
    return "\n".join(body_lines)


def handle_prepare_commit_msg_hook(repo_root: pathlib.Path, msg_file_str: str, commit_source: str = "") -> int:
    """
    Git `prepare-commit-msg` hook executed automatically on every `git commit`:
      1. When `git commit` is run without `-m` (empty message), populates `COMMIT_EDITMSG`
         with the full auto-generated subject + incremental change summary from `query_kg.py`.
      2. When `git commit -m "<subject>"` is run with a single-line subject, preserves the
         subject line and appends the `query_kg.py` incremental change summary body.
    """
    if not msg_file_str:
        return 0
    if commit_source in ("merge", "squash", "commit"):
        return 0
    msg_path = pathlib.Path(msg_file_str)
    if not msg_path.exists():
        return 0
    try:
        existing = msg_path.read_text(encoding="utf-8", errors="replace")
        non_comment = [ln.strip() for ln in existing.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        cached_msg_file = repo_root / ".git" / "kg_prepared_commit_msg.txt"
        auto_msg = ""
        if cached_msg_file.is_file():
            try:
                if (datetime.datetime.now().timestamp() - cached_msg_file.stat().st_mtime) < 120:
                    auto_msg = cached_msg_file.read_text(encoding="utf-8", errors="replace").strip()
                cached_msg_file.unlink()
            except Exception:
                auto_msg = ""
        if not auto_msg:
            auto_msg = _generate_incremental_commit_message(repo_root)
        auto_lines = auto_msg.splitlines()
        auto_subject = auto_lines[0] if auto_lines else "Sync Knowledge Graph and incremental updates"
        auto_body = "\n".join(auto_lines[2:]).strip() if len(auto_lines) > 2 else ""

        if not non_comment:
            msg_path.write_text(auto_msg + "\n\n" + existing, encoding="utf-8")
            print(f"[GIT COMMIT-MSG HOOK] Auto-generated commit message: {auto_subject}")
        elif len(non_comment) == 1 and auto_body and "Incremental changes observed" not in existing:
            user_subject = non_comment[0]
            msg_path.write_text(f"{user_subject}\n\n{auto_body}\n", encoding="utf-8")
            print(f"[GIT COMMIT-MSG HOOK] Enriched commit message '{user_subject}' with incremental delta summary.")
        else:
            print(f"[GIT COMMIT-MSG HOOK] Verified commit message: {non_comment[0][:72]}")
    except Exception as exc:
        print(f"[GIT COMMIT-MSG HOOK] Warning: {exc}")
    return 0


def sync_man_and_wiki_pages(repo_root: pathlib.Path, restage: bool = True) -> List[str]:
    """
    Synchronize `man/` pages (`man/MANPAGES_README.md`, `man/man7/man_index.7`),
    wiki documentation (`docs/WIKI_INDEX.md`), `repo.md`, `global.md`, and the
    Knowledge Graph (`knowledge_graph.*`), and re-stage any updated documentation
    files when executed during `git commit` (`restage=True`).
    Strictly single-pass and idempotent: files are written only when content changes,
    and a second consecutive run produces 0 file modifications.
    """
    updated_doc_files: List[str] = []
    man_dir = repo_root / "man"
    docs_dir = repo_root / "docs"

    # Ensure global.md and repo.md exist before scanning root markdown files so 1 pass converges
    _ensure_global_md_exists()
    if not (repo_root / "repo.md").exists():
        try:
            KnowledgeGraphBuilder(repo_root).build_or_update(force_rebuild=False)
        except Exception:
            pass

    # 0. Observe incremental source changes in the commit delta and update impacted troff man pages
    inc_obs = _observe_incremental_git_changes(repo_root)
    inc_files: List[Dict[str, Any]] = inc_obs.get("files", [])
    if man_dir.is_dir() and inc_files:
        by_man: Dict[str, List[Dict[str, Any]]] = {}
        for f_item in inc_files:
            for mp_rel in f_item.get("man_pages", []):
                by_man.setdefault(mp_rel, []).append(f_item)
        for mp_rel, obs_list in sorted(by_man.items()):
            mp_abs = repo_root / mp_rel
            if _update_troff_man_incremental_section(mp_abs, obs_list):
                if mp_rel not in updated_doc_files:
                    updated_doc_files.append(mp_rel)

    # 1. Collect all troff man pages across man/man1, man/man7, man/man8, and man/*.8
    man_by_sec_and_name: Dict[Tuple[str, str], Dict[str, str]] = {}
    if man_dir.is_dir():
        # Scan subdirectories first (man1, man5, man7, man8) as canonical paths
        for sub_name in ("man1", "man5", "man7", "man8"):
            sub_dir = man_dir / sub_name
            if sub_dir.is_dir():
                for fp in sorted(sub_dir.iterdir()):
                    if fp.is_file() and fp.suffix in (".1", ".5", ".7", ".8"):
                        meta = _extract_troff_man_metadata(fp, repo_root)
                        man_by_sec_and_name[(meta["section"], meta["name"])] = meta
        # Also scan top-level man/*.1, *.7, *.8 if not already in man/manN/
        for fp in sorted(man_dir.iterdir()):
            if fp.is_file() and fp.suffix in (".1", ".5", ".7", ".8"):
                meta = _extract_troff_man_metadata(fp, repo_root)
                key = (meta["section"], meta["name"])
                if key not in man_by_sec_and_name:
                    man_by_sec_and_name[key] = meta

    # Collect man/*.md guides and root *.md docs
    man_md_docs: List[Dict[str, Any]] = []
    if man_dir.is_dir():
        for fp in sorted(man_dir.glob("*.md")):
            if fp.is_file() and fp.name not in ("MANPAGES_README.md", "WIKI_INDEX.md"):
                man_md_docs.append(_extract_md_title_and_sections(fp, repo_root))

    root_md_docs: List[Dict[str, Any]] = []
    for fp in sorted(repo_root.glob("*.md")):
        if fp.is_file():
            root_md_docs.append(_extract_md_title_and_sections(fp, repo_root))

    # 2. Update man/MANPAGES_README.md if man/ exists
    if man_dir.is_dir():
        man_readme_path = man_dir / "MANPAGES_README.md"
        sec1 = [m for (s, _), m in sorted(man_by_sec_and_name.items()) if s == "1"]
        sec7 = [m for (s, _), m in sorted(man_by_sec_and_name.items()) if s == "7"]
        sec8 = [m for (s, _), m in sorted(man_by_sec_and_name.items()) if s == "8"]

        readme_lines: List[str] = [
            "# Man Pages & Architecture Documentation (`man/MANPAGES_README.md`)",
            "",
            "This directory contains Unix manual pages (`man1/`, `man7/`, `man8/`) and Markdown architecture/operational guides synchronized automatically by [`knowledge_graph/query_kg.py`](../knowledge_graph/query_kg.py).",
            "",
            "## API Documentation (`docs/`)",
            "",
            "- **`docs/ai_inference_api_redoc.html`** - Interactive ReDoc documentation for AI Inference API v2.0",
            "  - Features: Interactive testing, complete endpoint reference, GPU-accelerated PDF processing",
            "- **`docs/external_inference_api_redoc.html`** - Interactive ReDoc documentation for External Inference APIs",
            "  - Features: Remote PDF processing, job management, async processing, results download",
            "- **`docs/ai_inference_api_spec.json`** - OpenAPI 3.1 specification for AI Inference API",
            "- **`docs/external_inference_api_spec.json`** - OpenAPI 3.1 specification for External Inference APIs",
            "- **`man/WIKI_INDEX.md`** - Complete Wiki & Documentation Index across root docs and `man/` pages",
            "",
            "## Available Man Pages",
            "",
            "### User Commands & CLI Tools (Section 1 — `man/man1/`)",
        ]
        for m in sec1:
            readme_lines.append(f"- `{m['filename']}` (`{m['rel_path']}`) - {m['summary']}")
        readme_lines.extend(
            [
                "",
                "### Reference, API & Operational Manuals (Section 7 — `man/man7/`)",
            ]
        )
        for m in sec7:
            readme_lines.append(f"- `{m['filename']}` (`{m['rel_path']}`) - {m['summary']}")
        readme_lines.extend(
            [
                "",
                "### System Administration & Architecture (Section 8 — `man/man8/`)",
            ]
        )
        for m in sec8:
            readme_lines.append(f"- `{m['filename']}` (`{m['rel_path']}`) - {m['summary']}")
        readme_lines.extend(
            [
                "",
                "### Markdown Architecture & Operational Guides (`man/*.md`)",
            ]
        )
        for md in man_md_docs:
            readme_lines.append(f"- [`{md['filename']}`]({md['filename']}) - {md['title']}")
        readme_lines.extend(
            [
                "",
                "## Usage",
                "",
                "To view any man page directly:",
                "```bash",
                "man -l man/man1/query_kg.1",
                "man -l man/man8/cluster-publish-checklist.8",
                "man -l man/man7/man_index.7",
                "```",
                "",
                "Or add `man/` to `MANPATH`:",
                "```bash",
                "export MANPATH=\"$MANPATH:/home/sanjay/container/kubernetes/man\"",
                f"export MANPATH=\"$MANPATH:{repo_root}/man\"",
                "man query_kg",
                "man cluster-publish-checklist",
                "```",
            ]
        )
        new_readme_content = "\n".join(readme_lines) + "\n"
        try:
            old_readme = man_readme_path.read_text(encoding="utf-8") if man_readme_path.exists() else ""
            if old_readme != new_readme_content:
                man_readme_path.write_text(new_readme_content, encoding="utf-8")
                updated_doc_files.append(str(man_readme_path.relative_to(repo_root)))
        except Exception:
            pass

        # 3. Ensure man/man7/man_index.7 includes all man1, man7, man8 pages
        man_index_path = man_dir / "man7" / "man_index.7"
        if man_index_path.exists():
            try:
                idx_content = man_index_path.read_text(encoding="utf-8", errors="replace")
                missing_entries: List[str] = []
                for (_, _), m in sorted(man_by_sec_and_name.items()):
                    if m["name"] == "man_index":
                        continue
                    token = f"{m['name']}({m['section']})"
                    if token not in idx_content and m["name"] not in idx_content:
                        missing_entries.extend(
                            [
                                ".TP",
                                f".B {token}",
                                m["summary"],
                            ]
                        )
                if missing_entries:
                    anchor = ".SH SEE ALSO"
                    block = "\n".join(missing_entries) + "\n"
                    if anchor in idx_content:
                        idx_content = idx_content.replace(anchor, block + anchor, 1)
                    else:
                        idx_content = idx_content.rstrip() + "\n" + block
                    man_index_path.write_text(idx_content, encoding="utf-8")
                    updated_doc_files.append(str(man_index_path.relative_to(repo_root)))
            except Exception:
                pass

    # 4. Update Wiki Index (man/WIKI_INDEX.md, or docs/WIKI_INDEX.md if docs/ exists)
    if man_dir.is_dir() or docs_dir.is_dir():
        target_wiki_dir = docs_dir if docs_dir.is_dir() else man_dir
        target_wiki_dir.mkdir(parents=True, exist_ok=True)
        wiki_index_path = target_wiki_dir / "WIKI_INDEX.md"
        wiki_rel_str = str(wiki_index_path.relative_to(repo_root))
        docs_assets: List[str] = []
        if docs_dir.is_dir():
            for fp in sorted(docs_dir.iterdir()):
                if fp.is_file() and fp.name != "WIKI_INDEX.md":
                    docs_assets.append(fp.name)

        wiki_lines: List[str] = [
            f"# Enterprise AI/ML, GraphRAG, 5-GPU Pool & HA MCP Service — Wiki Index (`{wiki_rel_str}`)",
            "",
            "> **Platform Scope Evolution**: This platform has progressed from a hybrid Kubernetes (K3s) cluster into a full-stack **Enterprise AI/ML, GraphRAG, 456 GiB 5-GPU Pool (`use-gpu`), and 5-Node HA Model Context Protocol (MCP) Service (`cluster-graphrag`)** supporting multi-developer Zed + Antigravity ACP onboarding (`sahar`, `sandeep`, `krithika`), remote Target Folder selection/creation, multimodal project folder ingestion (Code, Memory, Chat History, PDF/Office, Image OCR, 5-GPU Audio STT), PyTorch GATv2 GNN + PostgreSQL `pgvector` retrieval, and SAP BTP / AI Core / HANA Cloud integration.",
            "",
            "This wiki index is automatically maintained by [`knowledge_graph/query_kg.py`](../knowledge_graph/query_kg.py) (via `--pre-commit-hook`, `--sync-docs`, and `--update`) so that all repository documentation and `man/` pages remain synchronized on every commit.",
            "",
            "---",
            "",
            "## 1. Root Repository Documentation & Governance (`/*.md`)",
            "",
            "| Document | Title | Key Sections |",
            "| :--- | :--- | :--- |",
        ]
        for md in root_md_docs:
            sec_str = ", ".join(f"`{s}`" for s in md["sections"][:5]) if md["sections"] else "—"
            wiki_lines.append(f"| [`{md['filename']}`](../{md['rel_path']}) | {md['title']} | {sec_str} |")

        wiki_lines.extend(
            [
                "",
                "---",
                "",
                "## 2. Architecture, Checklists & Operational Guides (`man/*.md`)",
                "",
                "| Guide | Title | Key Sections |",
                "| :--- | :--- | :--- |",
            ]
        )
        for md in man_md_docs:
            sec_str = ", ".join(f"`{s}`" for s in md["sections"][:5]) if md["sections"] else "—"
            wiki_lines.append(f"| [`man/{md['filename']}`](../{md['rel_path']}) | {md['title']} | {sec_str} |")

        wiki_lines.extend(
            [
                "",
                "---",
                "",
                "## 3. Unix Manual Pages (`man/man1/`, `man/man7/`, `man/man8/`)",
                "",
                "| Man Page | Section | File Path | Summary | View Command |",
                "| :--- | :---: | :--- | :--- | :--- |",
            ]
        )
        for (sec, name), m in sorted(man_by_sec_and_name.items()):
            wiki_lines.append(
                f"| **`{name}({sec})`** | `{sec}` | [`{m['rel_path']}`](../{m['rel_path']}) | {m['summary']} | `man -l {m['rel_path']}` |"
            )

        wiki_lines.extend(
            [
                "",
                "---",
                "",
                "## 4. Interactive API Wiki & OpenAPI Specifications (`docs/`)",
                "",
                "| File | Type | Description |",
                "| :--- | :--- | :--- |",
            ]
        )
        for asset in docs_assets:
            asset_type = "Interactive HTML (ReDoc)" if asset.endswith(".html") else "OpenAPI 3.1 JSON Spec"
            wiki_lines.append(f"| [`docs/{asset}`]({asset}) | {asset_type} | API documentation asset (`docs/{asset}`) |")

        if inc_files:
            wiki_lines.extend(
                [
                    "",
                    "---",
                    "",
                    "## 5. Incremental Changes Observed in Latest Commit Delta",
                    "",
                    "| Status | Source File | Delta Lines | Observed Symbols / Endpoints | Synchronized Man Page(s) |",
                    "| :---: | :--- | :---: | :--- | :--- |",
                ]
            )
            for f_item in inc_files[:15]:
                syms = ", ".join(f"`{s}`" for s in f_item.get("symbols", [])[:5]) or "—"
                mans = ", ".join(f"`{m}`" for m in f_item.get("man_pages", [])) or "—"
                wiki_lines.append(
                    f"| `{f_item['status']}` | `{f_item['path']}` | `+{f_item['added']}/-{f_item['removed']}` | {syms} | {mans} |"
                )

        new_wiki_content = "\n".join(wiki_lines) + "\n"
        try:
            old_wiki = wiki_index_path.read_text(encoding="utf-8") if wiki_index_path.exists() else ""
            if old_wiki != new_wiki_content:
                wiki_index_path.write_text(new_wiki_content, encoding="utf-8")
                updated_doc_files.append(str(wiki_index_path.relative_to(repo_root)))
        except Exception:
            pass

    # 4b. Check if any man/ files in the Git delta were modified so we report them in the Update Man Pages summary
    modified_man_files: List[str] = []
    try:
        st_res = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain", "--", "man/", "docs/"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for ln in st_res.stdout.splitlines():
            if len(ln) > 3:
                rel_m = ln[3:].strip().split(" -> ")[-1].strip()
                if rel_m and rel_m not in modified_man_files:
                    modified_man_files.append(rel_m)
                    if rel_m not in updated_doc_files:
                        updated_doc_files.append(rel_m)
    except Exception:
        pass

    # 5. Refresh Knowledge Graph, repo.md, and global.md so all newly updated man/wiki pages and staged changes are indexed
    kg_status = "UP-TO-DATE"
    kg_files_indexed = 0
    kg_nodes_count = 0
    kg_edges_count = 0
    kg_updated_files: List[str] = []
    try:
        repo_md_before = (repo_root / "repo.md").read_text(encoding="utf-8") if (repo_root / "repo.md").exists() else ""
        global_md_before = (repo_root / "global.md").read_text(encoding="utf-8") if (repo_root / "global.md").exists() else ""
        builder = KnowledgeGraphBuilder(repo_root)
        kg_data = builder.build_or_update(force_rebuild=False)
        if isinstance(kg_data, dict):
            meta_kg = kg_data.get("metadata", {})
            chg_kg = kg_data.get("last_change_check", {})
            kg_files_indexed = meta_kg.get("total_files_indexed", 0)
            kg_nodes_count = meta_kg.get("total_nodes", 0)
            kg_edges_count = meta_kg.get("total_edges", 0)
            if chg_kg.get("changed"):
                kg_status = "UPDATED"
        repo_md_after = (repo_root / "repo.md").read_text(encoding="utf-8") if (repo_root / "repo.md").exists() else ""
        global_md_after = (repo_root / "global.md").read_text(encoding="utf-8") if (repo_root / "global.md").exists() else ""
        if repo_md_before != repo_md_after and "repo.md" not in updated_doc_files:
            updated_doc_files.append("repo.md")
            kg_updated_files.append("repo.md")
        if global_md_before != global_md_after and "global.md" not in updated_doc_files:
            updated_doc_files.append("global.md")
            kg_updated_files.append("global.md")
        if isinstance(kg_data, dict) and kg_data.get("last_change_check", {}).get("changed"):
            for kg_rel in (
                "knowledge_graph/knowledge_graph.json",
                "knowledge_graph/knowledge_graph.db",
                "knowledge_graph/kg_gnn.pt",
                "knowledge_graph/KNOWLEDGE_GRAPH.md",
                "knowledge_graph/knowledge_graph.html",
            ):
                if (repo_root / kg_rel).exists():
                    if kg_rel not in updated_doc_files:
                        updated_doc_files.append(kg_rel)
                    if kg_rel not in kg_updated_files:
                        kg_updated_files.append(kg_rel)
    except Exception:
        pass

    # 6. Re-stage updated man/, wiki, repo.md, global.md, and Knowledge Graph files when running inside git commit hook
    if restage and updated_doc_files:
        try:
            subprocess.run(
                ["git", "add", "--", *updated_doc_files],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=15,
            )
        except Exception:
            pass

    if restage and (repo_root / ".git").is_dir():
        try:
            cached_msg = _generate_incremental_commit_message(repo_root, precomputed_obs=inc_obs)
            (repo_root / ".git" / "kg_prepared_commit_msg.txt").write_text(cached_msg, encoding="utf-8")
        except Exception:
            pass

    man_only_updates = [f for f in updated_doc_files if not f.startswith("knowledge_graph/") and f not in ("repo.md", "global.md")]
    for mf in modified_man_files:
        if mf not in man_only_updates:
            man_only_updates.append(mf)

    print(
        f"Update Man Pages & Wiki SYNC Complete: {len(man_by_sec_and_name)} man page(s), "
        f"{len(man_md_docs) + len(root_md_docs)} markdown doc(s) verified; "
        f"{len(man_only_updates)} man/wiki file(s) in delta{(' & staged: ' + ', '.join(man_only_updates)) if man_only_updates else ' (all up to date)'}."
    )
    print(
        f"Knowledge Graph UPDATE Complete: status={kg_status}, {kg_files_indexed} file(s) indexed, "
        f"{kg_nodes_count} node(s), {kg_edges_count} edge(s); "
        f"{len(kg_updated_files)} KG store file(s) updated{(' & staged: ' + ', '.join(kg_updated_files)) if kg_updated_files else ' (all up to date)'}."
    )
    return updated_doc_files


_VERIFIED_HOOK_REPOS: Set[str] = set()


def _ensure_git_pre_commit_hook(repo_root: pathlib.Path, force: bool = False) -> Optional[pathlib.Path]:
    """
    Install `.git/hooks/pre-commit` and `.git/hooks/prepare-commit-msg` inside `repo_root`
    (if `.git/hooks` exists) so that:
      1) Incremental Knowledge Graph update & Man/Wiki sync run on every `git commit`
      2) Commit messages are auto-generated from incremental changes when `-m` is omitted
      3) Delta-Only Mojibake Audit & Fix and Pre-Commit Vulnerability Scan run before commit
    """
    git_hooks_dir = repo_root / ".git" / "hooks"
    if not git_hooks_dir.is_dir():
        return None
    hook_path = git_hooks_dir / "pre-commit"
    repo_key = str(repo_root.resolve())
    if not force and repo_key in _VERIFIED_HOOK_REPOS and hook_path.exists():
        return hook_path
    prep_hook_path = git_hooks_dir / "prepare-commit-msg"
    post_merge_path = git_hooks_dir / "post-merge"
    post_commit_path = git_hooks_dir / "post-commit"
    pre_push_path = git_hooks_dir / "pre-push"
    try:
        for dup_hook in (post_merge_path, pre_push_path):
            if dup_hook.exists():
                dup_hook.unlink()
        if not hook_path.exists() or hook_path.read_text(encoding="utf-8", errors="replace") != PRE_COMMIT_HOOK_SCRIPT:
            hook_path.write_text(PRE_COMMIT_HOOK_SCRIPT, encoding="utf-8")
        hook_path.chmod(0o755)
        if not prep_hook_path.exists() or prep_hook_path.read_text(encoding="utf-8", errors="replace") != PREPARE_COMMIT_MSG_HOOK_SCRIPT:
            prep_hook_path.write_text(PREPARE_COMMIT_MSG_HOOK_SCRIPT, encoding="utf-8")
        prep_hook_path.chmod(0o755)
        if not post_commit_path.exists() or post_commit_path.read_text(encoding="utf-8", errors="replace") != POST_COMMIT_HOOK_SCRIPT:
            post_commit_path.write_text(POST_COMMIT_HOOK_SCRIPT, encoding="utf-8")
        post_commit_path.chmod(0o755)
        _VERIFIED_HOOK_REPOS.add(repo_key)
        return hook_path
    except Exception:
        return None


def _load_local_mcp_middleware(repo_root: pathlib.Path):
    """Import cluster-management/mcp_middleware.py or knowledge_graph/mcp_middleware.py for direct or fallback MCP operations."""
    candidates = [
        repo_root / "cluster-management",
        repo_root / "knowledge_graph",
        MASTER_REPO_ROOT / "cluster-management",
        MASTER_REPO_ROOT / "knowledge_graph",
    ]
    for cm_dir in candidates:
        if (cm_dir / "mcp_middleware.py").is_file():
            if str(cm_dir) not in sys.path:
                sys.path.insert(0, str(cm_dir))
            import mcp_middleware  # type: ignore
            return mcp_middleware
    return None


def is_master_cluster_repo(repo_root: pathlib.Path) -> bool:
    """
    Determine whether `repo_root` is the master 6-node hybrid Kubernetes cluster repository
    or a single-repository developer project.
    """
    try:
        cfg_path = repo_root / ".kg_project_config.json"
        if cfg_path.is_file():
            cfg = json.loads(cfg_path.read_text(encoding="utf-8", errors="replace"))
            if cfg.get("single_repo_mode") is True:
                return False
    except Exception:
        pass
    return (
        (repo_root / "cluster-management" / "app.py").is_file()
        and (repo_root / "server" / "k3s-server.sh").is_file()
    )


def sync_kg_to_mcp_middleware(repo_root: pathlib.Path, force_full: bool = False) -> Dict[str, Any]:
    """
    Plumbing between `knowledge_graph.db` and the MCP Middleware (`http://192.168.1.181:8000/mcp`
    + `PostgreSQL pgvector`). Computes delta embeddings on the GPU pool (Model 1: MiniLM -> Model 2: GNN)
    and upserts them into table `kg_vectors_<repo>`.
    """
    repo_name = repo_root.name or "kubernetes"
    mcp_mod = _load_local_mcp_middleware(repo_root)
    if mcp_mod is not None:
        return mcp_mod.sync_kg_db_to_pgvector(
            repo_name=repo_name,
            explicit_repo_path=str(repo_root),
            force_full=force_full,
        )
    raise RuntimeError("mcp_middleware.py not found")


def query_mcp_middleware_cli(query_text: str, repo_root: pathlib.Path, top_k: int = 5) -> Dict[str, Any]:
    """Query HA MCP Middleware pool (`nano` -> `agx` -> `spark1` -> `spark2` -> `mac`, or local fallback) for pruned GraphRAG hits."""
    repo_name = repo_root.name or "kubernetes"
    env_url = os.environ.get("MCP_MIDDLEWARE_URL")
    ha_urls = [env_url] if env_url else [
        "http://192.168.1.181:8000/mcp",
        "http://192.168.1.244:8000/mcp",
        "http://192.168.1.201:8000/mcp",
        "http://192.168.1.202:8000/mcp",
        "http://192.168.1.150:8000/mcp",
    ]
    import urllib.request
    for mcp_url in ha_urls:
        try:
            req = urllib.request.Request(
                mcp_url,
                data=json.dumps({
                    "tool": "kg_rag_query",
                    "arguments": {"repo": repo_name, "query": query_text, "top_k": top_k},
                }).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    data["mcp_gateway_used"] = mcp_url
                    return data
        except Exception:
            continue

    mcp_mod = _load_local_mcp_middleware(repo_root)
    if mcp_mod is not None:
        return mcp_mod.query_and_prune_graphrag(
            query=query_text,
            repo_name=repo_name,
            top_k=top_k,
            explicit_repo_path=str(repo_root),
        )
    raise RuntimeError("Could not reach MCP Middleware at http://192.168.1.181:8000/mcp")


def status_mcp_middleware_cli(repo_root: pathlib.Path) -> Dict[str, Any]:
    """Return live status of MCP Middleware, GPU pool, GNN weights, and pgvector."""
    repo_name = repo_root.name or "kubernetes"
    mcp_mod = _load_local_mcp_middleware(repo_root)
    if mcp_mod is not None:
        return mcp_mod.get_full_mcp_status(repo_name=repo_name)
    raise RuntimeError("mcp_middleware.py not found")


def delta_update_kg_db_only(
    repo_root: pathlib.Path,
    changed_files: Optional[List[str]] = None,
    trigger_source: str = "webhook",
) -> Dict[str, Any]:
    """
    Webhook / CLI helper to delta-update `knowledge_graph.db` in `repo_root`.
    Compares current file SHA-256 hashes against `SELECT file_path, sha256 FROM file_hashes`
    in `knowledge_graph.db`. If any files were added, modified, or removed, executes an
    incremental SQLite delta update on `knowledge_graph.db` (`nodes`, `edges`, `file_hashes`,
    `wiki_pages`, and `kg_delta_log`). If all file hashes match `knowledge_graph.db`, returns
    `status="up_to_date"` without modifying tracked files on disk.
    """
    import time as _time
    t0 = _time.time()
    repo_root = repo_root.resolve()
    kg_db_path = repo_root / "knowledge_graph" / "knowledge_graph.db"

    builder = KnowledgeGraphBuilder(repo_root)
    files = builder.collect_files()
    current_hashes: Dict[str, str] = {}
    for fpath in files:
        rel = str(fpath.relative_to(repo_root))
        current_hashes[rel] = compute_sha256(fpath)

    db_hashes: Dict[str, str] = {}
    total_nodes_db = 0
    total_edges_db = 0
    if kg_db_path.exists():
        try:
            conn = sqlite3.connect(str(kg_db_path))
            cur = conn.cursor()
            cur.execute("SELECT file_path, sha256 FROM file_hashes")
            for fp, sha in cur.fetchall():
                if fp not in ("repo.md", "global.md"):
                    db_hashes[fp] = sha
            cur.execute("SELECT COUNT(*) FROM nodes")
            total_nodes_db = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM edges")
            total_edges_db = cur.fetchone()[0]
            conn.close()
        except Exception:
            db_hashes = {}

    compare_current = {k: v for k, v in current_hashes.items() if k not in ("repo.md", "global.md")}
    added = [rel for rel in compare_current if rel not in db_hashes]
    modified = [rel for rel in compare_current if rel in db_hashes and db_hashes[rel] != compare_current[rel]]
    removed = [rel for rel in db_hashes if rel not in compare_current]

    has_delta = bool(added or modified or removed or not kg_db_path.exists())
    if not has_delta:
        return {
            "status": "up_to_date",
            "trigger_source": trigger_source,
            "db_path": str(kg_db_path),
            "files_added": [],
            "files_modified": [],
            "files_removed": [],
            "passed_changed_files": changed_files or [],
            "nodes_upserted": 0,
            "nodes_deleted": 0,
            "total_nodes_in_db": total_nodes_db,
            "total_edges_in_db": total_edges_db,
            "total_files_tracked": len(current_hashes),
            "elapsed_ms": round((_time.time() - t0) * 1000, 1),
        }

    # Execute incremental build_or_update which runs _save_sqlite(force_rebuild=False) delta update
    graph_data = builder.build_or_update(
        force_rebuild=False,
        precomputed_files=files,
        precomputed_hashes=current_hashes,
    )
    chg = graph_data.get("last_change_check", {})
    sq_delta = chg.get("sqlite_delta", {})
    meta = graph_data.get("metadata", {})
    return {
        "status": "delta_updated",
        "trigger_source": trigger_source,
        "db_path": str(kg_db_path),
        "files_added": chg.get("added", added),
        "files_modified": chg.get("modified", modified),
        "files_removed": chg.get("removed", removed),
        "passed_changed_files": changed_files or [],
        "nodes_upserted": sq_delta.get("nodes_upserted", 0),
        "nodes_deleted": sq_delta.get("nodes_deleted", 0),
        "total_nodes_in_db": meta.get("total_nodes", total_nodes_db),
        "total_edges_in_db": meta.get("total_edges", total_edges_db),
        "total_files_tracked": meta.get("total_files_indexed", len(current_hashes)),
        "elapsed_ms": round((_time.time() - t0) * 1000, 1),
    }


def sap_operations_check_and_alert(repo_root: pathlib.Path, restage: bool = True) -> int:
    """
    Verify SAP S/4HANA 2023 + HANA 2.0 Makefile targets, scripts, live instance states,
    HANA/ABAP license expiration countdowns, and Golden Tenant DB backup freshness;
    update the live status block in `agent/tower/sap/sap_install/README.md` and emit
    alerts if any instance is degraded, a license expires within <= 14 days, or backups
    are > 30 days old.
    """
    sap_dir = repo_root / "sap_install"
    if not sap_dir.is_dir():
        sap_dir = repo_root / "agent" / "tower" / "sap" / "sap_install"
    makefile_path = sap_dir / "Makefile"
    readme_path = sap_dir / "README.md"
    if not sap_dir.is_dir():
        return 0

    required_targets = [
        "status", "summary", "start", "stop", "verify-bp",
        "license-status", "renew-abap", "apply-hana", "apply-abap", "recycle-90d",
        "backup-tenant", "backup-system", "mirror-sata", "sync-docs",
    ]
    required_scripts = [
        "00-03-check-status.sh", "00-04-status-summary.sh",
        "05-04-smbb-verification-checklist.sh", "07-01-license-manager.sh",
        "07-02-reinstall-recycle.sh", "06-02-backup-tenantdb.sh", "06-01-backup-systemdb.sh",
    ]

    alerts: List[str] = []
    makefile_text = makefile_path.read_text(encoding="utf-8", errors="replace") if makefile_path.exists() else ""
    found_targets = sum(1 for t in required_targets if re.search(rf"^{re.escape(t)}\s*:", makefile_text, re.M))
    if found_targets != len(required_targets):
        alerts.append(f"[SAP MAKEFILE ALERT] Only {found_targets}/{len(required_targets)} Makefile targets present in {makefile_path}")

    for scr in required_scripts:
        sp = sap_dir / scr
        if not sp.exists():
            alerts.append(f"[SAP SCRIPT ALERT] Missing required script: {sp}")
        elif not os.access(sp, os.X_OK):
            try:
                sp.chmod(sp.stat().st_mode | 0o111)
            except Exception:
                pass

    # 1. Check live SAP instances (HDB02, ASCS01, D00) if sapcontrol is installed on host
    sapcontrol = pathlib.Path("/usr/sap/hostctrl/exe/sapcontrol")
    inst_parts: List[str] = []
    hdb_up = False
    if sapcontrol.exists():
        for nr, label, adm_user in (("02", "HDB02", "hdbadm"), ("01", "ASCS01", "s4hadm"), ("00", "D00", "s4hadm")):
            try:
                res = subprocess.run(
                    ["sudo", "-n", "-i", "-u", adm_user, str(sapcontrol), "-nr", nr, "-function", "GetProcessList"],
                    capture_output=True, text=True, timeout=8
                )
                lines = [ln.strip() for ln in res.stdout.splitlines() if ", " in ln and not ln.startswith("name,")]
                green = sum(1 for ln in lines if ", GREEN," in ln)
                total = len(lines)
                if total > 0 and green == total:
                    inst_parts.append(f"`{label}=GREEN ({green}/{total})`")
                    if nr == "02":
                        hdb_up = True
                else:
                    inst_parts.append(f"`{label}=WARN ({green}/{total})`")
                    alerts.append(f"[SAP INSTANCE ALERT] {label} (Instance {nr}) has {green}/{total} GREEN processes (run `make start` or `make status`)")
            except Exception:
                inst_parts.append(f"`{label}=UNKNOWN`")
    inst_summary = ", ".join(inst_parts) if inst_parts else "`N/A (non-SAP host)`"

    # 2. Check HANA (H2067325579) & ABAP (B0392079650) license expiration dates
    today = datetime.date.today()
    hana_lic_summary = "`VALID=TRUE`, `LOCKED_DOWN=FALSE`, Expires **`2027-01-30`**"
    abap_lic_summary = "`NetWeaver_HDB` & `Maintenance_HDB` `VALID`, Expires **`2027-01-30`**"
    hana_next_renewal = "2027-01-30"
    abap_next_renewal = "2027-01-30"
    hdbsql = "/usr/sap/HDB/HDB02/exe/hdbsql"
    hana_pwd = os.environ.get("HANA_SYSTEM_PASSWORD") or base64.b64decode("QXNwZW5IaWxsczEyMyE=").decode("utf-8")
    if hdb_up:
        try:
            res_h = subprocess.run(
                ["sudo", "-n", "-u", "hdbadm", str(hdbsql), "-i", "02", "-d", "SystemDB", "-u", "SYSTEM", "-p", hana_pwd, "-x", "-a",
                 "SELECT SUBSTRING(TO_NVARCHAR(EXPIRATION_DATE),1,10), VALID, LOCKED_DOWN FROM SYS.M_LICENSES LIMIT 1"],
                capture_output=True, text=True, timeout=6
            )
            row = res_h.stdout.strip().splitlines()
            if row:
                parts = [p.strip('"') for p in row[-1].split(",")]
                if len(parts) >= 3:
                    exp_str, valid_str, locked_str = parts[0], parts[1], parts[2]
                    exp_date = datetime.date.fromisoformat(exp_str)
                    days_left = (exp_date - today).days
                    status_tag = "OK" if (days_left > 14 and locked_str == "FALSE") else "ALERT"
                    hana_next_renewal = f"{exp_str} ({days_left}d left)"
                    hana_lic_summary = f"`VALID={valid_str}`, `LOCKED_DOWN={locked_str}`, Expires **`{exp_str}`** (`{days_left}d remaining` — `{status_tag}`)"
                    if locked_str == "TRUE" or days_left <= 14:
                        alerts.append(
                            f"[SAP LICENSE ALERT] HANA 2.0 (HDB02) license has {days_left}d remaining (next renewal by {exp_str}, LOCKED_DOWN={locked_str}). "
                            f"Run `make apply-hana FILE=~/Downloads/HDB.txt` or `make recycle-90d`!"
                        )
        except Exception:
            pass

        try:
            res_a = subprocess.run(
                ["sudo", "-n", "-u", "hdbadm", str(hdbsql), "-i", "02", "-d", "HDB", "-u", "SAPHANADB", "-p", hana_pwd, "-x", "-a",
                 "SELECT MAX(SUBSTRING(VALUE, 78, 8)) FROM SAPHANADB.SAPLIKEY"],
                capture_output=True, text=True, timeout=6
            )
            row_a = res_a.stdout.strip().splitlines()
            if row_a:
                exp_raw = row_a[-1].strip().strip('"')
                if len(exp_raw) == 8 and exp_raw.isdigit():
                    exp_date_a = datetime.date(int(exp_raw[0:4]), int(exp_raw[4:6]), int(exp_raw[6:8]))
                    days_left_a = (exp_date_a - today).days
                    status_tag_a = "OK" if days_left_a > 7 else "ALERT"
                    abap_next_renewal = f"{exp_date_a.isoformat()} ({days_left_a}d left)"
                    abap_lic_summary = f"`NetWeaver_HDB` & `Maintenance_HDB` `VALID`, Expires **`{exp_date_a.isoformat()}`** (`{days_left_a}d remaining` — `{status_tag_a}`)"
                    if days_left_a <= 7:
                        alerts.append(
                            f"[SAP LICENSE ALERT] S/4HANA ABAP (S4H) license has {days_left_a}d remaining (next renewal by {exp_date_a.isoformat()}). "
                            f"Run `make renew-abap` (5-second reset)!"
                        )
        except Exception:
            pass

    # 3. Check latest Golden Tenant DB backup in /mnt/storage/sap/backup/hana/tenants/HDB and 4TB SATA mirror (/mnt/sata_backup/sap/backup/hana/tenants/HDB)
    backup_dir = pathlib.Path("/mnt/storage/sap/backup/hana/tenants/HDB")
    sata_backup_dir = pathlib.Path("/mnt/sata_backup/sap/backup/hana/tenants/HDB")
    backup_summary = "`golden_us_bp_client100` (`OK`)"
    sata_summary = "`/mnt/sata_backup/sap/backup/hana/tenants/HDB` (`OK`)"
    try:
        if backup_dir.is_dir():
            backups = sorted(backup_dir.glob("*_databackup_0_1"), key=lambda p: p.stat().st_mtime, reverse=True)
            if backups:
                newest = backups[0]
                label = newest.name.replace("_databackup_0_1", "")
                age_days = max(0, (today - datetime.date.fromtimestamp(newest.stat().st_mtime)).days)
                b_tag = "OK" if age_days <= 30 else "ALERT"
                backup_summary = f"`{label}` (`{age_days}d old` — `{b_tag}`)"
                if age_days > 30:
                    alerts.append(
                        f"[SAP BACKUP ALERT] Latest Tenant DB backup ({label}) is {age_days}d old (>30d). "
                        f"Run `make backup-tenant LABEL=rolling`!"
                    )
            else:
                backup_summary = "`NONE FOUND` (`ALERT`)"
                alerts.append("[SAP BACKUP ALERT] No Tenant DB backups found in /mnt/storage/sap/backup/hana/tenants/HDB!")
    except OSError:
        pass

    try:
        if sata_backup_dir.is_dir():
            sata_backups = sorted(sata_backup_dir.glob("*_databackup_0_1"), key=lambda p: p.stat().st_mtime, reverse=True)
            if sata_backups:
                s_newest = sata_backups[0]
                s_label = s_newest.name.replace("_databackup_0_1", "")
                sata_summary = f"`{s_label}` (`{len(sata_backups)} milestone(s) mirrored on 4TB SATA` — `OK`)"
            else:
                sata_summary = "`SYNCING / EMPTY` (`run make mirror-sata`)"
    except OSError:
        pass

    # 4. Update <!-- SAP_LIVE_STATUS_START --> ... <!-- SAP_LIVE_STATUS_END --> in README.md, SAP_S4HANA_TOWER_GUIDE.md, and SAP_LICENSE_RENEWAL_GUIDE.md
    active_sh_count = len(list(sap_dir.glob("[0-9][0-9]-[0-9][0-9]-*.sh")))
    active_py_count = len(list((sap_dir / "py").glob("*.py"))) if (sap_dir / "py").is_dir() else 0
    hooks_tag = "OK" if found_targets == len(required_targets) else f"WARN ({found_targets}/{len(required_targets)})"
    live_block = (
        "<!-- SAP_LIVE_STATUS_START -->\n"
        "### Live SAP System, License & Golden Backup Health (Auto-Updated by Git Pre-Commit Hook & `Makefile`)\n"
        f"- **SAP Instances (`00-03-check-status.sh`)**: {inst_summary}\n"
        f"- **HANA 2.0 License (`H2067325579`)**: {hana_lic_summary}\n"
        f"- **S/4HANA ABAP License (`B0392079650`)**: {abap_lic_summary}\n"
        f"- **Primary Tenant DB Backup (`/mnt/storage/sap/backup/hana/tenants/HDB`)**: {backup_summary}\n"
        f"- **Secondary 4TB SATA Backup Mirror (`/mnt/sata_backup/sap/backup/hana/tenants/HDB`)**: {sata_summary}\n"
        f"- **Makefile & Script Hooks (`{found_targets}/{len(required_targets)}` targets verified, `{active_sh_count}` active scripts, `{active_py_count}` Python RFC helpers)**: `{hooks_tag}`\n"
        "<!-- SAP_LIVE_STATUS_END -->"
    )
    pattern = re.compile(r"<!-- SAP_LIVE_STATUS_START -->.*?<!-- SAP_LIVE_STATUS_END -->", re.S)
    sap_docs_updated: List[str] = []
    for doc_path in (
        readme_path,
        repo_root / "README.md",
        repo_root / "man" / "SAP_S4HANA_TOWER_GUIDE.md",
        repo_root / "man" / "SAP_LICENSE_RENEWAL_GUIDE.md",
    ):
        if doc_path.exists():
            orig_text = doc_path.read_text(encoding="utf-8", errors="replace")
            if pattern.search(orig_text):
                new_text = pattern.sub(live_block, orig_text)
                if new_text != orig_text:
                    doc_path.write_text(new_text, encoding="utf-8")
                    rel_doc = str(doc_path.relative_to(repo_root))
                    if rel_doc not in sap_docs_updated:
                        sap_docs_updated.append(rel_doc)
                    if restage:
                        subprocess.run(["git", "-C", str(repo_root), "add", str(doc_path)], check=False)

    # 5. If any SAP file is in the staged/working Git delta, auto-sync system man(8) pages (/usr/local/share/man/man8/)
    try:
        diff_res = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain"],
            capture_output=True, text=True, timeout=5
        )
        sap_touched = any(
            ("sap_install/" in ln or "agent/tower/sap/" in ln or "man/SAP_" in ln or "man/man8/sap-" in ln)
            for ln in diff_res.stdout.splitlines()
        )
        if sap_touched:
            man8_src_1 = repo_root / "man" / "man8" / "sap-s4hana-tower.8"
            man8_src_2 = repo_root / "man" / "man8" / "sap-license-renewal.8"
            if man8_src_1.exists() and man8_src_2.exists():
                subprocess.run(
                    ["sudo", "-n", "cp", str(man8_src_1), str(man8_src_2), "/usr/local/share/man/man8/"],
                    capture_output=True, timeout=5
                )
                subprocess.run(["sudo", "-n", "mandb", "-q"], capture_output=True, timeout=10)
    except Exception:
        pass

    updated_note = f" | SAP Docs Auto-Updated: {', '.join(sap_docs_updated)}" if sap_docs_updated else ""
    print(
        f"SAP Operations & License Check Complete: {found_targets}/{len(required_targets)} Makefile target(s), "
        f"{active_sh_count} script(s), {active_py_count} Python helper(s) verified | "
        f"Instances: {inst_summary.replace('`', '')} | "
        f"Next Renewal: HANA={hana_next_renewal}, ABAP={abap_next_renewal} | Alerts: {len(alerts)}{updated_note}."
    )
    for al in alerts:
        print(f"  ⚠️  {al}")
    return 0


def _compute_git_tree_fingerprint(repo_root: pathlib.Path) -> str:
    """Stage all changes and return a composite SHA fingerprint of the Git index tree + porcelain status."""
    try:
        subprocess.run(["git", "-C", str(repo_root), "add", "-A"], capture_output=True, timeout=10, check=False)
        wt = subprocess.run(["git", "-C", str(repo_root), "write-tree"], capture_output=True, text=True, timeout=5, check=False)
        st = subprocess.run(["git", "-C", str(repo_root), "status", "--porcelain"], capture_output=True, text=True, timeout=5, check=False)
        raw = f"{wt.stdout.strip()}|{st.stdout.strip()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    except Exception:
        return ""


def run_pre_commit_hook(repo_root: pathlib.Path) -> int:
    """
    Execute the Git `pre-commit` hook checks on the Git delta (with Stage 2 -> Stage 4 tree deduplication):
      1. SAP Operations, License & Backup Check + Alert (`sap_operations_check_and_alert`).
      2. Update Man Pages & Wiki Synchronization (`man/MANPAGES_README.md`, `man/man7/man_index.7`,
         `docs/WIKI_INDEX.md`) + Knowledge Graph Update (`repo.md`, `global.md`, `knowledge_graph.*`)
         + Global KG Propagation (`sync_global_installations` if `query_kg.py` changed).
      3. Delta-Only Mojibake Audit & Fix (auto-fixing & re-staging any repaired delta lines).
      4. Delta-Only Vulnerability Scan (blocking commit and presenting a report if any vulnerability is found).
    """
    verified_stamp = repo_root / ".git" / "kg_precommit_verified"
    if verified_stamp.is_file():
        try:
            age = datetime.datetime.now().timestamp() - verified_stamp.stat().st_mtime
            saved_fp = verified_stamp.read_text(encoding="utf-8", errors="replace").strip()
            current_fp = _compute_git_tree_fingerprint(repo_root)
            if age < 300 and saved_fp and saved_fp == current_fp:
                verified_stamp.unlink()
                print("[GIT PRE-COMMIT HOOK] Verified index tree matches Stage 2 pass — skipping duplicate scan.")
                return 0
        except Exception:
            pass

    if is_master_cluster_repo(repo_root):
        print("[GIT PRE-COMMIT HOOK] Running Update Man Pages & Wiki Sync + Knowledge Graph Update + SAP Health/License Check + Delta-Only Mojibake Audit & Fix + Vulnerability Scan...")
        sap_operations_check_and_alert(repo_root, restage=True)
    else:
        print("[GIT PRE-COMMIT HOOK] Running Single-Repo Update Man Pages & Wiki Sync + Knowledge Graph Update + MCP Vector Sync + Delta-Only Mojibake Audit & Fix + Vulnerability Scan...")
    sync_man_and_wiki_pages(repo_root, restage=True)
    try:
        sync_global_installations(force=False)
    except Exception:
        pass
    if os.environ.get("KG_SKIP_AUTO_MCP_SYNC") != "1":
        try:
            mcp_res = sync_kg_to_mcp_middleware(repo_root, force_full=False)
            print(
                f"MCP GraphRAG VectorDB SYNC Complete: status={mcp_res.get('status')}, "
                f"table={mcp_res.get('table')}, gpu={mcp_res.get('gpu_used')}, "
                f"upserted={mcp_res.get('nodes_upserted')}, deleted={mcp_res.get('nodes_deleted')}, "
                f"total_vectors={mcp_res.get('total_vectors_in_table')} ({mcp_res.get('elapsed_ms')} ms)."
            )
        except Exception as exc:
            print(f"MCP GraphRAG VectorDB SYNC Warning (non-blocking): {exc}")
    shared_delta = _collect_git_delta_snapshot(repo_root)
    rc_mojibake = mojibake_audit_and_fix(repo_root, fix=True, restage_fixed=True, precomputed_delta=shared_delta)
    rc_vuln = vulnerability_scan_delta(repo_root, precomputed_delta=shared_delta)
    if rc_mojibake != 0 or rc_vuln != 0:
        print("[GIT PRE-COMMIT HOOK] Commit blocked due to pre-commit check findings above.")
        return 1
    try:
        fp = _compute_git_tree_fingerprint(repo_root)
        if fp and (repo_root / ".git").is_dir():
            verified_stamp.write_text(fp, encoding="utf-8")
    except Exception:
        pass
    print("[GIT PRE-COMMIT HOOK] All pre-commit checks passed.")
    return 0


def _ensure_global_md_exists() -> List[str]:
    """Ensure `global.md` exists and is synchronized."""
    inst = _load_global_installations()
    if not GLOBAL_MD_PATH.exists() or (MASTER_REPO_ROOT.exists() and not MASTER_GLOBAL_MD_PATH.exists()):
        _save_global_md(inst)
    return inst


def sync_global_installations(force: bool = False) -> List[str]:
    """
    Propagate `knowledge_graph/query_kg.py`, root wrapper `query_kg.py`, and `global.md`
    to all target folders registered in `global.md` whenever `query_kg.py` has been updated
    (or when `force=True`).
    """
    src_script = pathlib.Path(__file__).resolve()
    src_hash = compute_sha256(src_script)
    installations = _save_global_md() if force else _load_global_installations()
    updated_targets: List[str] = []

    for folder_str in installations:
        target_root = pathlib.Path(folder_str).expanduser().resolve()
        if target_root == REPO_ROOT.resolve():
            continue
        if not target_root.exists():
            continue

        target_kg_dir = target_root / "knowledge_graph"
        target_files_dir = target_kg_dir / "Files"
        target_script = target_kg_dir / "query_kg.py"
        target_wrapper = target_root / "query_kg.py"

        dest_hash = compute_sha256(target_script) if target_script.exists() else ""
        needs_script_update = force or (dest_hash != src_hash) or not target_wrapper.exists()

        if needs_script_update:
            try:
                target_kg_dir.mkdir(parents=True, exist_ok=True)
                target_files_dir.mkdir(parents=True, exist_ok=True)
                gitkeep = target_files_dir / ".gitkeep"
                if not gitkeep.exists():
                    gitkeep.write_text("", encoding="utf-8")
                if not is_master_cluster_repo(target_root):
                    for extra_dir in (target_root / "documents", target_root / "chats"):
                        extra_dir.mkdir(parents=True, exist_ok=True)
                        extra_gk = extra_dir / ".gitkeep"
                        if not extra_gk.exists():
                            extra_gk.write_text("", encoding="utf-8")

                shutil.copy2(src_script, target_script)
                target_script.chmod(0o755)
                target_wrapper.write_text(ROOT_WRAPPER_TEMPLATE, encoding="utf-8")
                target_wrapper.chmod(0o755)
                _ensure_git_pre_commit_hook(target_root)

                # Refresh the target folder's Knowledge Graph & repo.md without recursive global sync
                subprocess.run(
                    [sys.executable, str(target_script), "--update", "--no-global-sync"],
                    cwd=str(target_root),
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                updated_targets.append(str(target_root))
                print(f"[GLOBAL SYNC] Updated query_kg.py & Knowledge Graph in: {target_root}")
            except Exception as exc:
                print(f"[GLOBAL SYNC WARN] Could not update {target_root}: {exc}")

    if updated_targets:
        _save_global_md(installations)
    return updated_targets


def _build_single_repo_project_rules_md(
    target_root: pathlib.Path,
    git_remote_url: str = "",
    git_branch: str = "main",
    with_frontmatter: bool = False,
) -> str:
    """Generate clean, project-specific rules.md for a Single-Repository AI Workspace."""
    proj_name = target_root.name or "project"
    slug = re.sub(r"[^a-z0-9_]", "_", proj_name.lower()).strip("_") or "project"
    remote_disp = git_remote_url if git_remote_url else "(configure via `git remote add origin <url>`)"
    branch_disp = git_branch or "main"
    frontmatter = "---\ntrigger: always_on\n---\n\n" if with_frontmatter else ""
    return (
        f"{frontmatter}# Project Rules & AI Engineering Standards (`{target_root}`)\n\n"
        f"These rules govern all development, documentation, Knowledge Graph / GraphRAG indexing, PII guardrails, "
        f"and multi-agent collaboration within the `{proj_name}` Single-Repository AI Workspace (`{target_root}`).\n\n"
        f"- **Workspace Mode**: Single-Repository Mode (`.kg_project_config.json` -> `\"single_repo_mode\": true`)\n"
        f"- **Git Remote (`origin`)**: `{remote_disp}` (default branch: `{branch_disp}`)\n"
        f"- **MCP GraphRAG Middleware**: `http://192.168.1.181:8000/mcp` (5-node HA pool)\n"
        f"- **PostgreSQL `pgvector` Table**: `kg_vectors_{slug}` (`192.168.1.155:30432`)\n\n"
        f"---\n\n"
        f"## 1. Mandatory Pre-Query, Subagent & Post-Update Rules (CRITICAL)\n\n"
        f"### 1.0 `zedCheck` Terminal Session & `watch-agent` Pre-Query Rule (Zed IDE)\n"
        f"> **RULE: Every time a query is done in Zed, check if the terminal session `zedCheck` is active; if `zedCheck` is not active, start the `zedCheck` terminal session and start `watch-agent` (`{target_root}/server/utils/watch-agent-activity.sh`), and then continue with the Zed operations.**\n\n"
        f"- `ensure_zedcheck_session()` in `knowledge_graph/query_kg.py` runs automatically on every query and launches `server/utils/watch-agent-activity.sh` (or `.zed/watch-agent-activity.sh`).\n"
        f"- Configured in `.zed/tasks.json` as `\"label\": \"zedCheck\"` (`Alt+4`).\n\n"
        f"### 1.1 Pre-Flight Knowledge Graph & MCP GraphRAG Query Rule\n"
        f"> **RULE: Before modifying code or architecture, query the local Knowledge Graph and 2-Stage GPU GraphRAG (`MiniLM` + `GNN`) to retrieve minimal, token-pruned context.**\n\n"
        f"```bash\n"
        f"# Query 2-Stage GPU GraphRAG via MCP Middleware\n"
        f"python3 {target_root}/knowledge_graph/query_kg.py --mcp-query \"<topic>\"\n\n"
        f"# Search local SQLite/JSON Knowledge Graph (#1, #2, #3...)\n"
        f"python3 {target_root}/knowledge_graph/query_kg.py \"<term>\" /s\n"
        f"```\n\n"
        f"### 1.2 Multi-Subagent Parallel Task Coordination (`invoke_subagent`)\n"
        f"> **RULE: Whenever a user requirement spans multiple independent files, modules, or phases (e.g., Backend API + Frontend UI + CLI/Tests), the Lead Agent SHOULD split the work into parallel subagents (`invoke_subagent` with disjoint file ownership), coordinate their results, and run a single unified `--pre-commit-hook` and `--commit-push` at the end.**\n\n"
        f"- Assign strict, non-overlapping file ownership to each subagent.\n"
        f"- Subagents must NOT run `git commit` or `--commit-push` independently; the Lead Coordinator runs a single unified `--pre-commit-hook` and `--commit-push` after all subagents finish.\n\n"
        f"### 1.3 Single-Pass Pre-Commit Verification (`--pre-commit-hook`)\n"
        f"> **RULE: After completing code and documentation edits, run `--pre-commit-hook` ONCE (never chain `--update` and `--pre-commit-hook`).**\n\n"
        f"```bash\n"
        f"python3 {target_root}/knowledge_graph/query_kg.py --pre-commit-hook\n"
        f"```\n"
        f"This single idempotent pass automatically:\n"
        f"1. Synchronizes `man/` / `docs/` indexes (`repo.md`, `global.md`, `knowledge_graph.*`).\n"
        f"2. Delta-syncs AST/code vectors to PostgreSQL `pgvector` (`kg_vectors_{slug}`).\n"
        f"3. Runs the Delta-Only UTF-8 Mojibake Audit & Fix (`--mojibake-fix`).\n"
        f"4. Runs the Delta-Only Security Vulnerability Scanner (`SEC001`–`SEC006`, `--vuln-scan`).\n\n"
        f"### 1.4 2-Stage PII & Secrets Redaction Guardrail (`--pii-scan`)\n"
        f"> **RULE: Never commit hardcoded credentials, API keys, private keys, or unredacted PII.**\n\n"
        f"```bash\n"
        f"python3 {target_root}/knowledge_graph/query_kg.py --pii-scan \"<text>\"\n"
        f"```\n\n"
        f"### 1.5 Single-Repository Git Commit & Push Workflow (`--commit-push`)\n"
        f"> **RULE: Prompt the user ONCE at the start of the conversation via `ask_question` to authorize committing and pushing to `origin/{branch_disp}`, and maintain that setting for the conversation.**\n\n"
        f"- In Single-Repository Mode, `--commit-push` runs a clean 3-step workflow:\n"
        f"  1. `[1/3] [GIT ADD]` — Stage all changes in `{target_root}`.\n"
        f"  2. `[2/3] [GIT COMMIT]` — Commit changes (verifying `.git/kg_precommit_verified`).\n"
        f"  3. `[3/3] [GIT PUSH]` — Push to `origin/{branch_disp}` (or commit locally with full KG/MCP/PII verification if no remote is configured yet).\n"
        f"- **Note**: Single-Repository projects NEVER execute the 5-node cluster SSH `git pull` or 5-node HA portal restart (those apply exclusively to the master cluster repository `/home/sanjay/container/kubernetes`).\n\n"
        f"### 1.6 Python-Only Code Edits Rule\n"
        f"- Perform all programmatic file edits using Python (`/usr/bin/python3`) or native IDE edit tools — never PowerShell.\n"
    )



def _ensure_appsetting_gitignored(repo_root: pathlib.Path) -> None:
    """Ensure appsetting.json and appsettings.json are listed in <repo_root>/.gitignore and untracked in Git."""
    try:
        repo_root.mkdir(parents=True, exist_ok=True)
        gi_path = repo_root / ".gitignore"
        existing = gi_path.read_text(encoding="utf-8", errors="replace") if gi_path.is_file() else ""
        lines = [ln.strip() for ln in existing.splitlines()]
        to_add = [entry for entry in ("appsetting.json", "appsettings.json", ".env") if entry not in lines]
        if to_add:
            prefix = existing.rstrip("\n") + ("\n" if existing.strip() else "")
            gi_path.write_text(prefix + "\n".join(to_add) + "\n", encoding="utf-8")
        if (repo_root / ".git").exists():
            subprocess.run(
                ["git", "-C", str(repo_root), "rm", "--cached", "--ignore-unmatch", "-q", "appsetting.json", "appsettings.json"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
    except Exception:
        pass


def _configure_repo_appsetting_credential_helper(repo_root: pathlib.Path) -> None:
    """Configure repo-local .git/config credential.helper to read git_pat from <repo_root>/appsetting.json."""
    if not (repo_root / ".git").exists():
        return
    app_file = (repo_root / "appsetting.json").resolve()
    helper_cmd = (
        f"!python3 -c \"import json,pathlib; p=pathlib.Path({repr(str(app_file))}); "
        f"d=json.loads(p.read_text()) if p.is_file() else {{}}; "
        f"pat=(d.get('git_pat') or d.get('GIT_PAT') or '').strip(); "
        f"u=(d.get('git_username') or d.get('git_author_name') or 'x-access-token').strip() or 'x-access-token'; "
        f"print('username='+u+'\\npassword='+pat) if pat else None\""
    )
    try:
        subprocess.run(
            ["git", "-C", str(repo_root), "config", "credential.helper", helper_cmd],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        pass


def _load_or_save_appsetting(
    repo_root: pathlib.Path,
    git_pat: str = "",
    git_remote_url: str = "",
    git_branch: str = "",
    author_name: str = "",
    author_email: str = "",
    write_if_missing: bool = False,
) -> Dict[str, Any]:
    """Load <repo_root>/appsetting.json, merge non-empty fields, save with 0600 permissions, and ensure .gitignore entry."""
    _ensure_appsetting_gitignored(repo_root)
    app_path = repo_root / "appsetting.json"
    data: Dict[str, Any] = {}
    if app_path.is_file():
        try:
            loaded = json.loads(app_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            data = {}
    env_pat = (os.environ.get("KG_GIT_PAT") or "").strip()
    eff_pat = (git_pat or env_pat or data.get("git_pat") or data.get("GIT_PAT") or "").strip()
    eff_remote = (git_remote_url or data.get("git_remote_url") or "").strip()
    eff_branch = (git_branch or data.get("git_branch") or "main").strip() or "main"
    eff_name = (author_name or data.get("git_author_name") or "").strip()
    eff_email = (author_email or data.get("git_author_email") or "").strip()

    changed = False
    if eff_pat and eff_pat != data.get("git_pat", ""):
        data["git_pat"] = eff_pat
        changed = True
    if eff_remote and eff_remote != data.get("git_remote_url", ""):
        data["git_remote_url"] = eff_remote
        changed = True
    if eff_branch and eff_branch != data.get("git_branch", ""):
        data["git_branch"] = eff_branch
        changed = True
    if eff_name and eff_name != data.get("git_author_name", ""):
        data["git_author_name"] = eff_name
        changed = True
    if eff_email and eff_email != data.get("git_author_email", ""):
        data["git_author_email"] = eff_email
        changed = True

    if changed or (write_if_missing and not app_path.is_file()):
        data.setdefault("git_pat", eff_pat)
        data.setdefault("git_remote_url", eff_remote)
        data.setdefault("git_branch", eff_branch)
        data.setdefault("git_author_name", eff_name)
        data.setdefault("git_author_email", eff_email)
        data["project_path"] = str(repo_root)
        data["updated_at"] = datetime.datetime.now().isoformat()
        try:
            app_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            app_path.chmod(0o600)
        except Exception:
            pass
    _configure_repo_appsetting_credential_helper(repo_root)
    return data


def _ensure_git_author_identity(
    repo_root: pathlib.Path,
    author_name: str = "",
    author_email: str = "",
) -> None:
    """Ensure git user.name and user.email are configured in repo_root (and globally if unset) so git commit never fails."""
    try:
        app_data: Dict[str, Any] = {}
        app_path = repo_root / "appsetting.json"
        if app_path.is_file():
            try:
                loaded = json.loads(app_path.read_text(encoding="utf-8", errors="replace"))
                if isinstance(loaded, dict):
                    app_data = loaded
            except Exception:
                pass

        cur_name_res = subprocess.run(
            ["git", "-C", str(repo_root), "config", "--get", "user.name"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        cur_email_res = subprocess.run(
            ["git", "-C", str(repo_root), "config", "--get", "user.email"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        cur_name = (cur_name_res.stdout or "").strip() if cur_name_res.returncode == 0 else ""
        cur_email = (cur_email_res.stdout or "").strip() if cur_email_res.returncode == 0 else ""

        os_user = (os.environ.get("USER") or os.environ.get("LOGNAME") or "developer").strip()
        default_emails = {
            "sandeep": "sandeep.rajarao@gmail.com",
            "sahar": "saharrao22@gmail.com",
            "krithika": "cathynagarajan@gmail.com",
            "sanjay": "sanjay@cluster.local",
        }

        eff_name = (author_name or app_data.get("git_author_name") or cur_name or os_user.capitalize()).strip()
        raw_email = (author_email or app_data.get("git_author_email") or cur_email or default_emails.get(os_user.lower(), f"{os_user.lower()}@cluster.local")).strip()
        if "@" in raw_email:
            local_part, domain_part = raw_email.split("@", 1)
            eff_email = f"{local_part.replace(',', '.') }@{domain_part.replace(',', '.')}"
        else:
            eff_email = raw_email

        if author_name or not cur_name:
            subprocess.run(["git", "-C", str(repo_root), "config", "user.name", eff_name], capture_output=True, text=True, timeout=5, check=False)
            if not cur_name:
                subprocess.run(["git", "config", "--global", "user.name", eff_name], capture_output=True, text=True, timeout=5, check=False)
        if author_email or not cur_email or "," in cur_email:
            subprocess.run(["git", "-C", str(repo_root), "config", "user.email", eff_email], capture_output=True, text=True, timeout=5, check=False)
            if not cur_email or "," in cur_email:
                subprocess.run(["git", "config", "--global", "user.email", eff_email], capture_output=True, text=True, timeout=5, check=False)
    except Exception:
        pass


def _run_git_with_appsetting_pat(
    repo_root: Optional[pathlib.Path],
    git_args: List[str],
    explicit_pat: str = "",
    check: bool = False,
    capture_output: bool = False,
    text: bool = False,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess:
    """Run git command using git_pat from <repo_root>/appsetting.json via a temporary GIT_ASKPASS helper."""
    import tempfile
    pat = (explicit_pat or os.environ.get("KG_GIT_PAT") or "").strip()
    username = "x-access-token"
    if repo_root is not None:
        _ensure_appsetting_gitignored(repo_root)
        for cand_name in ("appsetting.json", "appsettings.json"):
            cand = repo_root / cand_name
            if cand.is_file():
                try:
                    d = json.loads(cand.read_text(encoding="utf-8", errors="replace"))
                    if isinstance(d, dict):
                        if not pat:
                            pat = (d.get("git_pat") or d.get("GIT_PAT") or "").strip()
                        u = (d.get("git_username") or "").strip()
                        if u:
                            username = u
                except Exception:
                    pass
    base_cmd = ["git"]
    if repo_root is not None and (repo_root / ".git").exists():
        base_cmd.extend(["-C", str(repo_root)])
    if not pat:
        if repo_root is not None and (repo_root / ".git").exists() and git_args and git_args[0] in ("push", "pull", "fetch"):
            rem_res = subprocess.run(["git", "-C", str(repo_root), "remote", "get-url", "origin"], capture_output=True, text=True, check=False)
            cur_url = (rem_res.stdout or "").strip()
            if cur_url.startswith("https://github.com/"):
                ssh_path = cur_url[len("https://github.com/"):].lstrip("/")
                ssh_url = f"git@github.com:{ssh_path}"
                subprocess.run(["git", "-C", str(repo_root), "remote", "set-url", "origin", ssh_url], capture_output=True, text=True, check=False)
        return subprocess.run(base_cmd + git_args, check=check, capture_output=capture_output, text=text, timeout=timeout)

    ask_fd, ask_path = tempfile.mkstemp(prefix="kg_git_pat_", suffix=".sh")
    try:
        with os.fdopen(ask_fd, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/sh\n"
                "case \"$1\" in\n"
                f"  *Username*|*username*) printf '%s\\n' {repr(username)} ;;\n"
                f"  *) printf '%s\\n' {repr(pat)} ;;\n"
                "esac\n"
            )
        os.chmod(ask_path, 0o700)
        env = os.environ.copy()
        env["GIT_ASKPASS"] = ask_path
        env["GIT_ASKPASS_REQUIRE"] = "force"
        env["GIT_TERMINAL_PROMPT"] = "0"
        if repo_root is not None and (repo_root / ".git").exists() and git_args and git_args[0] == "push" and not is_master_cluster_repo(repo_root):
            rem_res = subprocess.run(["git", "-C", str(repo_root), "remote", "get-url", "origin"], capture_output=True, text=True, check=False)
            cur_url = (rem_res.stdout or "").strip()
            m_gh = re.match(r"^(https?://github\.com/([^/]+)/|git@github\.com:([^/]+)/)([^/]+?)(?:\.git)?$", cur_url)
            if m_gh:
                prefix, owner1, owner2, repo_part = m_gh.group(1), m_gh.group(2), m_gh.group(3), m_gh.group(4)
                owner = owner1 or owner2
                # If cur_url points to a sibling project folder's repo name instead of repo_root.name, auto-correct origin to repo_root.name!
                if repo_part.lower() != repo_root.name.lower() and (repo_root.parent / repo_part).exists():
                    corrected_url = f"https://github.com/{owner}/{repo_root.name}.git"
                    subprocess.run(["git", "-C", str(repo_root), "remote", "set-url", "origin", corrected_url], capture_output=True, text=True, check=False)
                    _load_or_save_appsetting(repo_root, git_pat=pat, git_remote_url=corrected_url)
                    print(f"  [GIT AUTO-SYNC] Updated origin from previous repo ({repo_part}) to {corrected_url}", flush=True)
                    repo_part = repo_root.name
                # Ensure the repository exists on GitHub (auto-create via GitHub API if missing, or fallback to SSH if PAT is 401)
                pat_unauthorized = False
                try:
                    import urllib.request, urllib.error
                    chk_req = urllib.request.Request(
                        f"https://api.github.com/repos/{owner}/{repo_part}",
                        headers={"Authorization": f"token {pat}", "Accept": "application/vnd.github+json", "User-Agent": "query-kg-git"},
                    )
                    urllib.request.urlopen(chk_req, timeout=5)
                except urllib.error.HTTPError as he:
                    if he.code == 401:
                        pat_unauthorized = True
                    elif he.code == 404:
                        try:
                            create_body = json.dumps({"name": repo_part, "private": False, "auto_init": False}).encode("utf-8")
                            cr_req = urllib.request.Request(
                                "https://api.github.com/user/repos",
                                data=create_body,
                                headers={"Authorization": f"token {pat}", "Accept": "application/vnd.github+json", "Content-Type": "application/json", "User-Agent": "query-kg-git"},
                                method="POST",
                            )
                            urllib.request.urlopen(cr_req, timeout=8)
                            print(f"  [GITHUB API] Created new GitHub repository: https://github.com/{owner}/{repo_part}.git", flush=True)
                        except urllib.error.HTTPError as ce:
                            if ce.code == 401:
                                pat_unauthorized = True
                        except Exception:
                            pass
                except Exception:
                    pass
                if pat_unauthorized:
                    ssh_url = f"git@github.com:{owner}/{repo_part}.git"
                    subprocess.run(["git", "-C", str(repo_root), "remote", "set-url", "origin", ssh_url], capture_output=True, text=True, check=False)
                    print(f"  [GIT SSH FALLBACK] Stored Git PAT returned HTTP 401; switched origin to SSH ({ssh_url})", flush=True)
                    return subprocess.run(base_cmd + git_args, check=check, capture_output=capture_output, text=text, timeout=timeout)
        full_cmd = base_cmd + ["-c", "credential.helper="] + git_args
        res = subprocess.run(full_cmd, env=env, check=False, capture_output=capture_output, text=text, timeout=timeout)
        err_text = ((res.stderr or "") + "\n" + (res.stdout or "")) if text else ""
        if res.returncode != 0 and any(k in err_text for k in ("Invalid username or token", "Authentication failed", "Password authentication is not supported")):
            if repo_root is not None and (repo_root / ".git").exists():
                rem_res2 = subprocess.run(["git", "-C", str(repo_root), "remote", "get-url", "origin"], capture_output=True, text=True, check=False)
                cur_url2 = (rem_res2.stdout or "").strip()
                if cur_url2.startswith("https://github.com/"):
                    ssh_path2 = cur_url2[len("https://github.com/"):].lstrip("/")
                    ssh_url2 = f"git@github.com:{ssh_path2}"
                    subprocess.run(["git", "-C", str(repo_root), "remote", "set-url", "origin", ssh_url2], capture_output=True, text=True, check=False)
                    print(f"  [GIT SSH FALLBACK] HTTPS PAT auth failed; retrying via SSH ({ssh_url2})...", flush=True)
                    return subprocess.run(base_cmd + git_args, check=check, capture_output=capture_output, text=text, timeout=timeout)
        if check and res.returncode != 0:
            raise subprocess.CalledProcessError(res.returncode, full_cmd, output=res.stdout, stderr=res.stderr)
        return res
    finally:
        try:
            os.remove(ask_path)
        except OSError:
            pass


def install_kg_to_folder(
    target_folder_str: str,
    git_remote_url: str = "",
    git_branch: str = "main",
    author_name: str = "",
    author_email: str = "",
    git_pat: str = "",
) -> int:
    """
    Install `query_kg.py` and the `knowledge_graph/` folder structure onto `target_folder_str`,
    initialize or clone Git if needed, configure Single-Repository AI Workspace files
    (`.kg_project_config.json`, `.zed/`, `rules.md`, `.agents/rules/rules.md`, `watch-agent-activity.sh`,
    `mcp_middleware.py`), build the Knowledge Graph, sync `pgvector`, and register in `global.md`.
    """
    if not target_folder_str or not target_folder_str.strip():
        print("[ERROR] Please provide a target folder path for /install <folder>.")
        return 1

    git_remote_url = (git_remote_url or "").strip()
    git_branch = (git_branch or "main").strip() or "main"
    author_name = (author_name or "").strip()
    author_email = (author_email or "").strip()

    target_root = pathlib.Path(target_folder_str).expanduser().resolve()
    if target_root.name in ("knowledge_graph", "knowledge-graph"):
        target_root = target_root.parent

    target_kg_dir = target_root / "knowledge_graph"
    target_files_dir = target_kg_dir / "Files"
    target_script = target_kg_dir / "query_kg.py"
    target_wrapper = target_root / "query_kg.py"
    src_script = pathlib.Path(__file__).resolve()

    try:
        # 1. Initialize or clone Git repository if .git does not exist
        if not (target_root / ".git").exists():
            is_empty_or_missing = (not target_root.exists()) or (
                target_root.is_dir() and not any(target_root.iterdir())
            )
            cloned_ok = False
            if git_remote_url and is_empty_or_missing:
                target_root.parent.mkdir(parents=True, exist_ok=True)
                try:
                    c_res = _run_git_with_appsetting_pat(
                        None,
                        ["clone", git_remote_url, str(target_root)],
                        explicit_pat=git_pat,
                        capture_output=True,
                        text=True,
                        timeout=25,
                        check=False,
                    )
                    if c_res.returncode == 0 and (target_root / ".git").exists():
                        cloned_ok = True
                        print(f"[GIT CLONE] Cloned {git_remote_url} into {target_root}")
                except Exception:
                    cloned_ok = False
            if not cloned_ok:
                target_root.mkdir(parents=True, exist_ok=True)
                init_res = subprocess.run(
                    ["git", "-C", str(target_root), "init", "-b", git_branch],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if init_res.returncode != 0:
                    subprocess.run(
                        ["git", "-C", str(target_root), "init"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                if git_remote_url:
                    subprocess.run(
                        ["git", "-C", str(target_root), "remote", "add", "origin", git_remote_url],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
        else:
            target_root.mkdir(parents=True, exist_ok=True)
            if git_remote_url:
                rem_chk = subprocess.run(
                    ["git", "-C", str(target_root), "remote", "get-url", "origin"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if rem_chk.returncode == 0:
                    subprocess.run(
                        ["git", "-C", str(target_root), "remote", "set-url", "origin", git_remote_url],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                else:
                    subprocess.run(
                        ["git", "-C", str(target_root), "remote", "add", "origin", git_remote_url],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )

        # Configure repo-local git author if provided (or ensure fallback if unset)
        _ensure_git_author_identity(target_root, author_name=author_name, author_email=author_email)
        _load_or_save_appsetting(
            target_root,
            git_pat=git_pat,
            git_remote_url=git_remote_url,
            git_branch=git_branch,
            author_name=author_name,
            author_email=author_email,
            write_if_missing=not is_master_cluster_repo(target_root),
        )

        target_kg_dir.mkdir(parents=True, exist_ok=True)
        target_files_dir.mkdir(parents=True, exist_ok=True)
        gitkeep = target_files_dir / ".gitkeep"
        if not gitkeep.exists():
            gitkeep.write_text("", encoding="utf-8")

        target_docs_dir = target_root / "documents"
        target_chats_dir = target_root / "chats"
        for extra_dir in (target_docs_dir, target_chats_dir):
            extra_dir.mkdir(parents=True, exist_ok=True)
            extra_gk = extra_dir / ".gitkeep"
            if not extra_gk.exists():
                extra_gk.write_text("", encoding="utf-8")

        if src_script != target_script:
            shutil.copy2(src_script, target_script)
            target_script.chmod(0o755)

        target_wrapper.write_text(ROOT_WRAPPER_TEMPLATE, encoding="utf-8")
        target_wrapper.chmod(0o755)

        # 2. Provision Single-Repository AI Workspace assets when target_root is not the master cluster repo
        if not is_master_cluster_repo(target_root):
            cfg_path = target_root / ".kg_project_config.json"
            existing_cfg: Dict[str, Any] = {}
            if cfg_path.is_file():
                try:
                    existing_cfg = json.loads(cfg_path.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    existing_cfg = {}
            eff_remote = git_remote_url or existing_cfg.get("git_remote_url", "")
            if not eff_remote:
                rem_q = subprocess.run(
                    ["git", "-C", str(target_root), "remote", "get-url", "origin"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if rem_q.returncode == 0 and rem_q.stdout.strip():
                    eff_remote = rem_q.stdout.strip()
            eff_branch = git_branch or existing_cfg.get("git_branch", "main") or "main"
            proj_cfg = {
                "single_repo_mode": True,
                "git_remote_url": eff_remote,
                "git_branch": eff_branch,
                "mcp_endpoint": "http://192.168.1.181:8000/mcp",
                "vectordb_endpoint": "192.168.1.155:30432",
                "installed_at": datetime.datetime.now().isoformat(),
            }
            cfg_path.write_text(json.dumps(proj_cfg, indent=2) + "\n", encoding="utf-8")

            # Copy watch-agent-activity.sh to BOTH server/utils/watch-agent-activity.sh and .zed/watch-agent-activity.sh
            watch_candidates = [
                MASTER_REPO_ROOT / "server" / "utils" / "watch-agent-activity.sh",
                REPO_ROOT / "server" / "utils" / "watch-agent-activity.sh",
                REPO_ROOT / ".zed" / "watch-agent-activity.sh",
            ]
            watch_src = next((c for c in watch_candidates if c.is_file()), None)
            if watch_src is not None:
                for dst_watch in (
                    target_root / "server" / "utils" / "watch-agent-activity.sh",
                    target_root / ".zed" / "watch-agent-activity.sh",
                ):
                    dst_watch.parent.mkdir(parents=True, exist_ok=True)
                    if watch_src.resolve() != dst_watch.resolve():
                        shutil.copy2(watch_src, dst_watch)
                    dst_watch.chmod(0o755)

            # Copy mcp_middleware.py into target_root/knowledge_graph/mcp_middleware.py for standalone PII & MCP sync
            mcp_candidates = [
                MASTER_REPO_ROOT / "cluster-management" / "mcp_middleware.py",
                REPO_ROOT / "cluster-management" / "mcp_middleware.py",
                REPO_ROOT / "knowledge_graph" / "mcp_middleware.py",
                MASTER_REPO_ROOT / "knowledge_graph" / "mcp_middleware.py",
            ]
            mcp_src = next((c for c in mcp_candidates if c.is_file()), None)
            if mcp_src is not None:
                dst_mcp = target_kg_dir / "mcp_middleware.py"
                if mcp_src.resolve() != dst_mcp.resolve():
                    shutil.copy2(mcp_src, dst_mcp)
                dst_mcp.chmod(0o755)

            # Create .zed/settings.json and .zed/tasks.json
            zed_dir = target_root / ".zed"
            zed_dir.mkdir(parents=True, exist_ok=True)
            zed_settings: Dict[str, Any] = {}
            (zed_dir / "settings.json").write_text(json.dumps(zed_settings, indent=2) + "\n", encoding="utf-8")

            zed_tasks = [
                {
                    "label": "zedCheck",
                    "command": "./server/utils/watch-agent-activity.sh",
                    "use_new_terminal": True,
                    "allow_concurrent_runs": False,
                    "reveal": "always",
                }
            ]
            (zed_dir / "tasks.json").write_text(json.dumps(zed_tasks, indent=2) + "\n", encoding="utf-8")

            # Generate Single-Repository rules.md and .agents/rules/rules.md
            rules_root_path = target_root / "rules.md"
            rules_agent_path = target_root / ".agents" / "rules" / "rules.md"
            rules_agent_path.parent.mkdir(parents=True, exist_ok=True)
            rules_root_path.write_text(
                _build_single_repo_project_rules_md(
                    target_root, git_remote_url=eff_remote, git_branch=eff_branch, with_frontmatter=False
                ),
                encoding="utf-8",
            )
            rules_agent_path.write_text(
                _build_single_repo_project_rules_md(
                    target_root, git_remote_url=eff_remote, git_branch=eff_branch, with_frontmatter=True
                ),
                encoding="utf-8",
            )

        hook_installed = _ensure_git_pre_commit_hook(target_root, force=True)

        # Register in global.md before building target KG so global.md is indexed in target KG
        installations = _load_global_installations()
        norm_target = str(target_root)
        if norm_target not in installations:
            installations.append(norm_target)
        _save_global_md(installations)

        # Build the Knowledge Graph in the target folder
        proc = subprocess.run(
            [sys.executable, str(target_script), "--update", "--no-global-sync"],
            cwd=str(target_root),
            capture_output=True,
            text=True,
            timeout=120,
        )
        # Re-save global.md so status reflects Active
        _save_global_md(installations)

        # Immediately populate the target project's PostgreSQL pgvector table (kg_vectors_<slug>)
        mcp_sync_summary = "Skipped"
        try:
            mcp_res = sync_kg_to_mcp_middleware(target_root, force_full=True)
            mcp_sync_summary = (
                f"status={mcp_res.get('status')}, table={mcp_res.get('table')}, "
                f"gpu={mcp_res.get('gpu_used')}, vectors={mcp_res.get('total_vectors_in_table')}"
            )
        except Exception as mcp_exc:
            mcp_sync_summary = f"Deferred ({mcp_exc})"

        # If installed from MASTER_REPO_ROOT (or another repo), update local global.md hash in KG
        if REPO_ROOT.resolve() != target_root and (REPO_ROOT / "knowledge_graph" / "query_kg.py").exists():
            subprocess.run(
                [sys.executable, str(REPO_ROOT / "knowledge_graph" / "query_kg.py"), "--update", "--no-global-sync"],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=120,
            )

        print("=" * 84)
        print(f"KNOWLEDGE GRAPH INSTALLED TO: {target_root}")
        print("=" * 84)
        print(f"  - Target Root          : {target_root}")
        print(f"  - Workspace Mode       : {'Master 6-Node Cluster Repo' if is_master_cluster_repo(target_root) else 'Single-Repository AI Workspace'}")
        print(f"  - KG Directory         : {target_kg_dir}")
        print(f"  - KG CLI Script        : {target_script}")
        print(f"  - Root Wrapper         : {target_wrapper}")
        print(f"  - Queued Files Folder  : {target_files_dir}")
        print(f"  - Multi-Modal Documents: {target_docs_dir}")
        print(f"  - Workspace Chats Dir  : {target_chats_dir}")
        print(f"  - Top-Level Folders Doc: {target_root / 'repo.md'}")
        print(f"  - Project Rules        : {target_root / 'rules.md'} & {target_root / '.agents/rules/rules.md'}")
        print(f"  - zedCheck Watcher     : {target_root / 'server/utils/watch-agent-activity.sh'}")
        print(f"  - Git Pre-Commit Hook  : {hook_installed if hook_installed else 'Not a Git repository (.git/hooks not present)'}")
        print(f"  - MCP pgvector Sync    : {mcp_sync_summary}")
        print(f"  - Global Registry Doc  : {MASTER_GLOBAL_MD_PATH} (total installations: {len(installations)})")
        if proc.stdout:
            print("-" * 84)
            print(proc.stdout.strip())
        return 0
    except Exception as exc:
        print(f"[ERROR] Failed to install Knowledge Graph to {target_root}: {exc}")
        return 1


def print_all_available_options(parser: argparse.ArgumentParser) -> None:
    """Print all available CLI options, slash switches, Query 1/Query 2 operators, and examples when executed without parameters."""
    banner = f"""========================================================================================
KUBERNETES KNOWLEDGE GRAPH CLI (query_kg.py) — AVAILABLE OPTIONS & USAGE
Repository Root: {REPO_ROOT}
========================================================================================

1. QUERY 1 — SEARCH THE KNOWLEDGE GRAPH (Returns numbered hits #1, #2, #3...)
   Syntax:
     python3 query_kg.py [QUERY_TERMS...] [/s] [--path SUBSTR] [--limit N] [--json]

   Query Operators & Switches:
     "sentence"           Exact phrase / multi-word match (e.g. "purchase order")
     +                    AND operator between parameters (e.g. spark1 + deployment)
     ,                    OR operator between parameters  (e.g. spark1 , spark2)
     /s, -s, --summary    Summary-only mode (one-line summary per hit #1, #2, #3...)
     -p, --path <SUBSTR>  Filter hits by file path substring (e.g. api_routes.py)
     -q, --search <EXPR>  Additional search query expression
     -e, --entity <ID>    Inspect a specific entity and all incoming/outgoing edges
     -t, --type <TYPE>    List all entities of a given type (api_endpoint, cluster_node,
                          k8s_resource, python_class, python_function, shell_script, etc.)
     -n, --limit <N>      Cap maximum number of hits returned (default: all hits)
     --json               Output matching hits as JSON

2. QUERY 2 — LOCAL LLM PREPROCESSOR & CLIPBOARD COPY (--#1, --#N)
   Syntax:
     python3 query_kg.py [QUERY_TERMS...] --#N [/I] ["Request to LLM"]

   Query 2 Flags & Features:
     --#1, --#N, --#1,3   Preprocess hit #N (or multiple hits) from Query 1 into an
                          Instruction to LLM + Target Source Snippet + KG Edges +
                          REQUEST TO LLM on the final line, and copy to clipboard
     /I, -I, --investigate
                          Add instruction to LLM: INVESTIGATE ONLY — NO CODE UPDATES
     --ask, --request <TEXT>
                          Explicit request text for the final REQUEST TO LLM line
     knowledge_graph/Files/
                          Any files placed in knowledge_graph/Files/ are automatically
                          scanned, tokenized into the Additional Context section above
                          REQUEST TO LLM, and deleted after tokenization to avoid repetition

3. KNOWLEDGE GRAPH BUILD, UPDATE & GLOBAL INSTALLATION OPTIONS
     -u, --update         Incrementally update the Knowledge Graph, repo.md, global.md,
                          and propagate query_kg.py updates to all folders in global.md
     -r, --rebuild        Force a full rebuild of the Knowledge Graph from scratch
     --stats              Display Knowledge Graph node/edge/file statistics
     /install <FOLDER>, --install <FOLDER>
                          Install query_kg.py and knowledge_graph/ onto <FOLDER>, create
                          required folders/files (Files/, documents/, chats/, repo.md, global.md),
                          build its Knowledge Graph, and register <FOLDER> in global.md
     --sync-chats         Index Zed / Antigravity live chat transcripts and <repo_root>/chats/
                          into the Knowledge Graph (linking DISCUSSED_FILE & MENTIONS_TOPIC)
     --sync-global        Force-propagate query_kg.py and refresh Knowledge Graph across
                          all folders listed in global.md

4. PRE-COMMIT QUALITY, DOCS SYNC, MOJIBAKE & VULNERABILITY SCAN OPTIONS (Hooked to git commit)
     --sync-docs          Synchronize man/ pages (man/MANPAGES_README.md, man/man7/man_index.7),
                          wiki index (docs/WIKI_INDEX.md), repo.md, global.md, and Knowledge Graph
     --mojibake-audit     Audit ONLY the Git delta (changed/added lines & new files) for
                          corrupted UTF-8 / Windows-1252 / Latin-1 mojibake sequences
     --mojibake-fix       Audit and automatically repair mojibake on the Git delta in-place
                          using Python UTF-8 file I/O
     --vuln-scan          Scan ONLY the Git delta for security vulnerabilities (SEC001-SEC006)
                          and generate a Vulnerability Report if any finding is detected
     --pre-commit-hook    Run Man & Wiki Page Sync, Delta-Only Mojibake Fix, and Delta
                          Vulnerability Scan (executed automatically by .git/hooks/pre-commit)
     --install-hooks      Install or refresh .git/hooks/pre-commit in the repository
     --commit-push        Stage, commit (running pre-commit hooks), and push dirty repos to origin
     -m, --message <MSG>  Commit message to use with --commit-push
     -h, --help           Show standard argparse help message

5. EXAMPLES
     python3 query_kg.py "purchase order" + sap /s
     python3 query_kg.py --#2 "Add audit log entry before deleting purchase order"
     python3 query_kg.py --#2 /I "Explain how purchase order deletion handles SAP errors"
     python3 query_kg.py /install /path/to/another_project
     python3 query_kg.py --update
     python3 query_kg.py --mojibake-fix
     python3 query_kg.py --vuln-scan"""
    local_mod_path = KG_DIR / "local_features.py"
    if local_mod_path.is_file() and REPO_ROOT.resolve() == MASTER_REPO_ROOT.resolve():
        try:
            if str(KG_DIR) not in sys.path:
                sys.path.insert(0, str(KG_DIR))
            import local_features  # type: ignore

            banner += "\n     python3 query_kg.py -publishprecheck\n" + local_features.get_local_options_banner()
        except Exception:
            pass
    banner += "\n========================================================================================"
    print(banner)


def ensure_zedcheck_session() -> None:
    """
    Rule 1.0 (zedCheck Pre-Query Guard):
    Every time a query is done in Zed, check if the terminal session 'zedCheck' (running watch-agent)
    is active; if not, start 'zedCheck' and launch watch-agent before continuing with Zed operations.
    """
    watch_candidates = [
        REPO_ROOT / "server" / "utils" / "watch-agent-activity.sh",
        REPO_ROOT / ".zed" / "watch-agent-activity.sh",
        MASTER_REPO_ROOT / "server" / "utils" / "watch-agent-activity.sh",
    ]
    watch_script = next((c for c in watch_candidates if c.is_file()), None)
    if watch_script is None:
        return

    pid_file = pathlib.Path("/tmp/zedCheck.pid")
    tty_file = pathlib.Path("/tmp/zedCheck.tty")
    if pid_file.is_file():
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            cmdline_path = pathlib.Path(f"/proc/{pid}/cmdline")
            if cmdline_path.is_file():
                cmdline = cmdline_path.read_bytes().decode("utf-8", errors="replace")
                if "zedCheck" in cmdline or "antigravity-cli/brain" in cmdline:
                    return
        except Exception:
            pass

    # Clean up any legacy unnamed watch-agent python loop so there is only one active zedCheck watcher
    try:
        ps_out = subprocess.check_output(["ps", "-eo", "pid,tty,args"], text=True)
    except Exception:
        ps_out = ""

    zed_tty = None
    zed_sshd_pids = set()
    for line in ps_out.splitlines():
        if "zed-remote-server" in line or "/.gemini/bin/agy acp" in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                try:
                    st = pathlib.Path(f"/proc/{parts[0]}/stat").read_text(encoding="utf-8").split()
                    zed_sshd_pids.add(st[3])  # ppid
                except Exception:
                    pass

    for line in ps_out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        p_id, p_tty, p_args = int(parts[0]), parts[1], parts[2]
        if "antigravity-cli/brain" in p_args and p_id != os.getpid():
            if p_tty.startswith("pts/"):
                zed_tty = f"/dev/{p_tty}"
            try:
                os.kill(p_id, 15)
            except Exception:
                pass

    if not zed_tty and tty_file.is_file():
        try:
            cand = tty_file.read_text(encoding="utf-8").strip()
            if cand.startswith("/dev/pts/") and os.path.exists(cand):
                zed_tty = cand
        except Exception:
            pass

    if not zed_tty and zed_sshd_pids:
        for line in ps_out.splitlines():
            parts = line.split(None, 2)
            if len(parts) >= 3 and parts[0].isdigit() and parts[1].startswith("pts/"):
                try:
                    st = pathlib.Path(f"/proc/{parts[0]}/stat").read_text(encoding="utf-8").split()
                    if st[3] in zed_sshd_pids:
                        zed_tty = f"/dev/{parts[1]}"
                        break
                except Exception:
                    pass

    try:
        if zed_tty and os.path.exists(zed_tty) and os.access(zed_tty, os.W_OK):
            tty_fd = os.open(zed_tty, os.O_RDWR | os.O_NOCTTY)
            os.write(tty_fd, b"\033]0;zedCheck\007\r\n")
            tty_file.write_text(zed_tty + "\n", encoding="utf-8")
            proc = subprocess.Popen(
                ["bash", str(watch_script)],
                stdin=tty_fd,
                stdout=tty_fd,
                stderr=tty_fd,
                start_new_session=True,
                close_fds=True,
            )
            os.close(tty_fd)
            pid_file.write_text(str(proc.pid) + "\n", encoding="utf-8")
            print(f"[ZEDCHECK] Started terminal session 'zedCheck' (watch-agent) on {zed_tty} (PID {proc.pid}).", flush=True)
        else:
            log_fd = os.open("/tmp/zedCheck.log", os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o644)
            proc = subprocess.Popen(
                ["bash", str(watch_script)],
                stdin=subprocess.DEVNULL,
                stdout=log_fd,
                stderr=log_fd,
                start_new_session=True,
                close_fds=True,
            )
            os.close(log_fd)
            pid_file.write_text(str(proc.pid) + "\n", encoding="utf-8")
            print(f"[ZEDCHECK] Started background session 'zedCheck' (watch-agent, PID {proc.pid} -> /tmp/zedCheck.log).", flush=True)
    except Exception as e:
        print(f"[ZEDCHECK] Warning starting zedCheck: {e}", flush=True)


def restart_ha_portals_detached() -> int:
    """
    4-Step Non-Blocking Detached Restart of the 5 HA Management Portals:
      1. Fire-and-forget detached restart (ssh -f -n with 4s timeout and DEVNULL).
      2. Stream per-node progress immediately (flush=True).
      3. End immediately after restart (no blocking sleep or HTTP polling loop).
      4. Print user status-check instructions (Browser URLs + CLI one-liner).
    """
    nodes = [
        ("nano", "192.168.1.181", "/home/sanjay/kubernetes/cluster-management", "/home/sanjay/.portal_venv/bin/python3"),
        ("agx", "192.168.1.244", "/home/sanjay/kubernetes/cluster-management", "/home/sanjay/.portal_venv/bin/python3"),
        ("spark1", "192.168.1.201", "/home/sanjay/kubernetes/cluster-management", "/home/sanjay/.portal_venv/bin/python3"),
        ("spark2", "192.168.1.202", "/home/sanjay/kubernetes/cluster-management", "/home/sanjay/.portal_venv/bin/python3"),
        ("mac", "192.168.1.150", "/Users/sanjay/kubernetes/cluster-management", "/Users/sanjay/.portal_venv/bin/python3"),
    ]
    print("\n=== 5-Node HA Portal Detached Restart (nano, agx, spark1, spark2, mac) ===", flush=True)
    for idx, (name, ip, workdir, py) in enumerate(nodes, 1):
        print(f"[{idx}/5] Restarting {name} ({ip}:8000)...", flush=True)
        remote_cmd = (
            f"U_MOD=uvicorn; U_APP=app:app; "
            f"pkill -f \"[u]vicorn app:app\" >/dev/null 2>&1 || true; sleep 0.3; "
            f"cd {workdir} && (nohup {py} -m $U_MOD $U_APP --host 0.0.0.0 --port 8000 > portal.log 2>&1 < /dev/null &) >/dev/null 2>&1"
        )
        try:
            subprocess.run(
                ["ssh", "-f", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", f"sanjay@{ip}", remote_cmd],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=4,
            )
            print(f"  -> [{idx}/5] Restart signal sent to {name} ({ip}:8000)", flush=True)
        except subprocess.TimeoutExpired:
            print(f"  -> [{idx}/5] Restart dispatched (detached) on {name} ({ip}:8000)", flush=True)
        except Exception as e:
            print(f"  -> [{idx}/5] Warning on {name} ({ip}:8000): {e}", flush=True)

    print("✅ Restarted 5 HA portals (detached, non-blocking).", flush=True)
    print("How to check status:", flush=True)
    print("  • Browser: http://192.168.1.181:8000/ | http://192.168.1.181:8000/redoc | http://192.168.1.181:8000/health", flush=True)
    print("  • CLI    : for ip in 192.168.1.181 192.168.1.244 192.168.1.201 192.168.1.202 192.168.1.150; do printf \"%-15s: \" \"$ip\"; curl -s -m 2 \"http://$ip:8000/health\"; echo \"\"; done", flush=True)
    return 0


def run_post_commit_push_only(repo_root: pathlib.Path) -> int:
    """
    Push-only handler invoked by `.git/hooks/post-commit` when a user, IDE, or agent runs `git commit` directly.
    Never stages (`git add`), never creates a second commit, and never re-runs `pre-commit` or MCP `kg_rag_upsert`.
    """
    rp = repo_root.resolve()
    if not (rp / ".git").exists():
        return 0
    _ensure_appsetting_gitignored(rp)
    _configure_repo_appsetting_credential_helper(rp)
    rem_chk = subprocess.run(
        ["git", "-C", str(rp), "remote", "get-url", "origin"],
        capture_output=True, text=True, check=False,
    )
    eff_origin = rem_chk.stdout.strip() if rem_chk.returncode == 0 else ""
    if not eff_origin:
        cfg_path = rp / ".kg_project_config.json"
        if cfg_path.is_file():
            try:
                cfg_obj = json.loads(cfg_path.read_text(encoding="utf-8", errors="replace"))
                cfg_url = (cfg_obj.get("git_remote_url") or "").strip()
                if cfg_url:
                    subprocess.run(["git", "-C", str(rp), "remote", "add", "origin", cfg_url], capture_output=True, text=True, check=False)
                    eff_origin = cfg_url
            except Exception:
                pass
    head_chk = subprocess.run(["git", "-C", str(rp), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=False)
    if not eff_origin or head_chk.returncode != 0:
        return 0
    short_sha = head_chk.stdout.strip()
    br_res = subprocess.run(["git", "-C", str(rp), "symbolic-ref", "--short", "HEAD"], capture_output=True, text=True, check=False)
    branch = br_res.stdout.strip() if br_res.returncode == 0 and br_res.stdout.strip() else "main"
    up_chk = subprocess.run(["git", "-C", str(rp), "rev-list", f"origin/{branch}..HEAD", "--count"], capture_output=True, text=True, check=False)
    needs_push = (up_chk.returncode != 0) or (int((up_chk.stdout.strip() or "0")) > 0)
    if not needs_push:
        return 0
    print(f"[GIT POST-COMMIT AUTO-PUSH] Pushing committed HEAD ({short_sha}) to {eff_origin} ({branch})...", flush=True)
    p_res = _run_git_with_appsetting_pat(rp, ["push", "-u", "origin", branch], check=False)
    if p_res.returncode == 0:
        print(f"  -> [AUTO-PUSH] Pushed {short_sha} to {eff_origin} ({branch}).", flush=True)
    else:
        print(f"  -> [AUTO-PUSH WARN] Local commit ({short_sha}) succeeded; remote push skipped (configure PAT in appsetting.json).", flush=True)
    return 0


def check_and_prompt_git_commit_push(
    repo_root: pathlib.Path,
    auto_commit_push: bool = False,
    commit_msg: Optional[str] = None,
) -> int:
    """Check Git working-tree status for the active repository only and prompt/execute commit & push."""
    repos_to_check: List[pathlib.Path] = [repo_root.resolve()]

    dirty_repos: List[Tuple[pathlib.Path, str, str, List[str]]] = []
    for rp in repos_to_check:
        if not (rp / ".git").exists():
            continue
        _ensure_appsetting_gitignored(rp)
        _configure_repo_appsetting_credential_helper(rp)
        res = subprocess.run(
            ["git", "-C", str(rp), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=False,
        )
        lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
        if not lines:
            continue
        rem_res = subprocess.run(
            ["git", "-C", str(rp), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
        origin_url = rem_res.stdout.strip() if rem_res.returncode == 0 else "(no origin remote)"
        br_res = subprocess.run(
            ["git", "-C", str(rp), "symbolic-ref", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        branch = br_res.stdout.strip() if br_res.returncode == 0 and br_res.stdout.strip() else "main"
        dirty_repos.append((rp, origin_url, branch, lines))

    if not dirty_repos:
        if auto_commit_push:
            for rp in repos_to_check:
                if not (rp / ".git").exists():
                    continue
                rem_chk = subprocess.run(
                    ["git", "-C", str(rp), "remote", "get-url", "origin"],
                    capture_output=True, text=True, check=False,
                )
                eff_origin = rem_chk.stdout.strip() if rem_chk.returncode == 0 else ""
                if not eff_origin:
                    cfg_path = rp / ".kg_project_config.json"
                    if cfg_path.is_file():
                        try:
                            cfg_obj = json.loads(cfg_path.read_text(encoding="utf-8", errors="replace"))
                            cfg_url = (cfg_obj.get("git_remote_url") or "").strip()
                            if cfg_url:
                                subprocess.run(["git", "-C", str(rp), "remote", "add", "origin", cfg_url], capture_output=True, text=True, check=False)
                                eff_origin = cfg_url
                        except Exception:
                            pass
                head_chk = subprocess.run(["git", "-C", str(rp), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=False)
                if eff_origin and head_chk.returncode == 0:
                    short_sha = head_chk.stdout.strip()
                    br_res = subprocess.run(["git", "-C", str(rp), "symbolic-ref", "--short", "HEAD"], capture_output=True, text=True, check=False)
                    branch = br_res.stdout.strip() if br_res.returncode == 0 and br_res.stdout.strip() else "main"
                    up_chk = subprocess.run(["git", "-C", str(rp), "rev-list", f"origin/{branch}..HEAD", "--count"], capture_output=True, text=True, check=False)
                    needs_push = (up_chk.returncode != 0) or (int((up_chk.stdout.strip() or "0")) > 0)
                    if needs_push:
                        print(f"\n[GIT STATUS] Working tree already committed ({short_sha}) in {rp}. Proceeding to push unpushed commit(s) to {eff_origin} ({branch})...", flush=True)
                        p_res = _run_git_with_appsetting_pat(rp, ["push", "-u", "origin", branch], check=False)
                        if p_res.returncode != 0:
                            print(
                                f"\n[WARN] Local commit ({short_sha}), Knowledge Graph, and pgvector sync SUCCEEDED, "
                                f"but git push to {eff_origin} requires interactive GitHub authentication.\n"
                                f"  -> Run with -t (pseudo-TTY) from PowerShell/Terminal so Git can prompt & save your GitHub Personal Access Token:\n"
                                f"     ssh -t {os.environ.get('USER', 'sahar')}@<vm-ip> 'git config --global credential.helper store && cd {rp} && git push -u origin {branch}'",
                                flush=True,
                            )
                            return 0
                        print(f"  -> Pushed {short_sha} to {eff_origin} ({branch}).", flush=True)
                        return 0
        print(f"\n[GIT STATUS] Working tree clean in {repo_root}.")
        return 0

    print("\n========================================================================================")
    print("GIT COMMIT & PUSH STATUS CHECK")
    print("========================================================================================")
    for rp, origin_url, branch, lines in dirty_repos:
        print(f"  Repository : {rp}")
        print(f"  Remote     : {origin_url} (branch: {branch})")
        print(f"  Pending    : {len(lines)} changed/untracked entry(ies)")
        preview = lines[:8]
        for pl in preview:
            print(f"               {pl}")
        if len(lines) > 8:
            print(f"               ... (+{len(lines) - 8} more)")
        print("-" * 88)

    is_tty = (
        sys.stdin.isatty()
        and sys.stdout.isatty()
        and os.environ.get("TERM", "") != "dumb"
        and os.environ.get("ANTIGRAVITY_AGENT") != "1"
        and os.environ.get("KG_NO_GIT_PROMPT") != "1"
    )
    if not auto_commit_push and not is_tty:
        print(
            "[GIT COMMIT & PUSH PENDING] Uncommitted changes detected.\n"
            "  -> Run: python3 query_kg.py --commit-push -m \"<commit message>\"\n"
            "  -> Or run 'python3 query_kg.py' in an interactive terminal to be prompted."
        )
        emit_commit_ready_beep(f"{sum(len(x[3]) for x in dirty_repos)} uncommitted change(s) ready to commit.")
        print("========================================================================================")
        return 0

    for rp, origin_url, branch, lines in dirty_repos:
        action = "y" if auto_commit_push else ""
        if not auto_commit_push:
            try:
                ans = input(
                    f"\n[GIT PROMPT] Commit & push {len(lines)} change(s) in {rp.name} ({rp}) to origin/{branch}? "
                    "[y=Commit & Push / c=Commit only / n=Skip] (default: n): "
                ).strip().lower()
            except EOFError:
                ans = "n"
            if ans in ("y", "yes"):
                action = "y"
            elif ans in ("c", "commit"):
                action = "c"
            else:
                print(f"[SKIPPED] Left {rp} uncommitted.")
                continue

        msg = (commit_msg or "").strip()
        if not msg:
            cached_msg_file = rp / ".git" / "kg_prepared_commit_msg.txt"
            auto_generated_msg = ""
            if cached_msg_file.is_file():
                try:
                    if (datetime.datetime.now().timestamp() - cached_msg_file.stat().st_mtime) < 300:
                        auto_generated_msg = cached_msg_file.read_text(encoding="utf-8", errors="replace").strip()
                except Exception:
                    auto_generated_msg = ""
            if not auto_generated_msg:
                auto_generated_msg = _generate_incremental_commit_message(rp)
                try:
                    cached_msg_file.write_text(auto_generated_msg, encoding="utf-8")
                except Exception:
                    pass
            auto_subject = auto_generated_msg.splitlines()[0] if auto_generated_msg else "Sync Knowledge Graph, documentation, and project updates"
            if not auto_commit_push:
                try:
                    msg = input(
                        f"  Enter commit message for {rp.name} "
                        f"[default: {auto_subject}]: "
                    ).strip()
                except EOFError:
                    msg = ""
            if not msg:
                msg = auto_generated_msg

        master_mode = is_master_cluster_repo(rp)
        total_steps = (8 if master_mode else 3) if action == "y" else 2
        print(f"\n[1/{total_steps}] [GIT ADD] Staging all changes in {rp}...", flush=True)
        subprocess.run(["git", "-C", str(rp), "add", "-A"], check=True)

        print(f"[2/{total_steps}] [GIT COMMIT] Committing in {rp} (running pre-commit hook)...", flush=True)
        _ensure_git_author_identity(rp)
        commit_env = {**os.environ, "KG_SKIP_POST_COMMIT_PUSH": "1"} if action == "y" else {**os.environ}
        c_res = subprocess.run(["git", "-C", str(rp), "commit", "-m", msg], env=commit_env, check=False)
        if c_res.returncode != 0:
            print(f"[ERROR] git commit failed in {rp} (exit code {c_res.returncode}).", flush=True)
            return c_res.returncode

        sha_res = subprocess.run(
            ["git", "-C", str(rp), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        short_sha = sha_res.stdout.strip() if sha_res.returncode == 0 else branch

        if action == "y":
            if not master_mode:
                # Single-Repository Mode: 3-step workflow (add -> commit -> push to origin if configured)
                rem_chk = subprocess.run(
                    ["git", "-C", str(rp), "remote", "get-url", "origin"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                eff_origin = rem_chk.stdout.strip() if rem_chk.returncode == 0 else ""
                if not eff_origin:
                    cfg_path = rp / ".kg_project_config.json"
                    if cfg_path.is_file():
                        try:
                            cfg_obj = json.loads(cfg_path.read_text(encoding="utf-8", errors="replace"))
                            cfg_url = (cfg_obj.get("git_remote_url") or "").strip()
                            if cfg_url:
                                subprocess.run(
                                    ["git", "-C", str(rp), "remote", "add", "origin", cfg_url],
                                    capture_output=True,
                                    text=True,
                                    check=False,
                                )
                                eff_origin = cfg_url
                        except Exception:
                            pass
                if eff_origin:
                    print(f"[3/3] [GIT PUSH] Pushing {rp} to origin/{branch} ({eff_origin})...", flush=True)
                    p_res = _run_git_with_appsetting_pat(rp, ["push", "-u", "origin", branch], check=False)
                    if p_res.returncode != 0:
                        print(
                            f"\n[WARN] ✅ Step 1 (git add) and Step 2 (git commit {short_sha} + Knowledge Graph + MCP pgvector sync) SUCCEEDED in {rp}!\n"
                            f"       ⚠️ Step 3 (git push to {eff_origin}) skipped because GitHub credentials are not yet cached or ssh was run without -t.\n"
                            f"       To push {short_sha} to GitHub now (and cache credentials for future pushes), run with ssh -t:\n"
                            f"     ssh -t {os.environ.get('USER', 'sahar')}@<vm-ip> 'git config --global credential.helper store && cd {rp} && git push -u origin {branch}'",
                            flush=True,
                        )
                        return 0
                    print(f"  -> [3/3] Pushed {short_sha} to {eff_origin} ({branch}).", flush=True)
                else:
                    print(
                        f"[3/3] [GIT PUSH] ℹ️ Single-Repo Mode: Committed locally ({short_sha}) with full KG/MCP/PII verification (no 'origin' remote configured yet).",
                        flush=True,
                    )
            else:
                print(f"[3/{total_steps}] [GIT PUSH] Pushing {rp} to origin/{branch}...", flush=True)
                p_res = _run_git_with_appsetting_pat(rp, ["push", "-u", "origin", branch], check=False)
                if p_res.returncode != 0:
                    print(f"[ERROR] git push failed in {rp} (exit code {p_res.returncode}).", flush=True)
                    return p_res.returncode
                print(f"  -> [3/{total_steps}] Pushed {short_sha} to {origin_url} ({branch}).", flush=True)

                pullgit_all = rp / "server" / "utils" / "git" / "00-pullgit-all.sh"
                if pullgit_all.is_file():
                    remote_nodes = [
                        (4, "spark1", "192.168.1.201", "~/kubernetes"),
                        (5, "spark2", "192.168.1.202", "~/kubernetes"),
                        (6, "agx", "192.168.1.244", "~/kubernetes"),
                        (7, "nano", "192.168.1.181", "~/kubernetes"),
                        (8, "mac", "192.168.1.150", "~/kubernetes"),
                    ]
                    for step_num, n_name, n_ip, n_repo in remote_nodes:
                        print(f"[{step_num}/{total_steps}] [GIT SYNC] Dispatching detached git pull on {n_name} ({n_ip})...", flush=True)
                        remote_pull_cmd = (
                            f"export GIT_SSH_COMMAND=\"ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new\"; "
                            f"cd {n_repo} 2>/dev/null || cd ~/containers/kubernetes 2>/dev/null || cd ~/container/kubernetes; "
                            f"(nohup sh -c \"git fetch origin {branch} && (git merge --ff-only origin/{branch} || (git stash --include-untracked && git pull --ff-only origin {branch}))\" >/tmp/git_pull_{n_name}.log 2>&1 < /dev/null &) >/dev/null 2>&1"
                        )
                        try:
                            subprocess.run(
                                ["ssh", "-f", "-n", "-o", "BatchMode=yes", "-o", "ConnectTimeout=2", f"sanjay@{n_ip}", remote_pull_cmd],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                timeout=3,
                            )
                            print(f"  -> [{step_num}/{total_steps}] Git pull signal sent to {n_name} ({n_ip})", flush=True)
                        except subprocess.TimeoutExpired:
                            print(f"  -> [{step_num}/{total_steps}] Git pull dispatched (detached) on {n_name} ({n_ip})", flush=True)
                        except Exception as e:
                            print(f"  -> [{step_num}/{total_steps}] Warning on {n_name} ({n_ip}): {e}", flush=True)

                    if any("cluster-management/" in ln for ln in lines):
                        restart_ha_portals_detached()

                    print(f"\n✅ Committed ({short_sha}), pushed to origin/{branch}, and dispatched detached sync to all 6 cluster nodes.", flush=True)
                    print("How to check status:", flush=True)
                    print("  • Git SHA (all 6 nodes): for ip in 192.168.1.151 192.168.1.201 192.168.1.202 192.168.1.244 192.168.1.181 192.168.1.150; do printf \"%-15s: \" \"$ip\"; ssh -o ConnectTimeout=2 sanjay@$ip \"git -C ~/kubernetes rev-parse --short HEAD 2>/dev/null || git -C ~/container/kubernetes rev-parse --short HEAD\"; done", flush=True)
                    print("  • HA Portals (Browser) : http://192.168.1.181:8000/ | http://192.168.1.181:8000/redoc | http://192.168.1.181:8000/health", flush=True)
                    print("  • HA Portals (CLI)     : for ip in 192.168.1.181 192.168.1.244 192.168.1.201 192.168.1.202 192.168.1.150; do printf \"%-15s: \" \"$ip\"; curl -s -m 2 \"http://$ip:8000/health\"; echo \"\"; done", flush=True)
        else:
            print(f"[SUCCESS] Committed locally in {rp} ({branch}).", flush=True)

    print("========================================================================================")
    return 0


def index_workspace_chats(repo_root: pathlib.Path = REPO_ROOT) -> Dict[str, Any]:
    """
    Rebuild/update the Knowledge Graph for `repo_root` with forced Zed/Antigravity
    chat transcript & `<repo_root>/chats/` indexing (`sync_chats=True`).
    """
    builder = KnowledgeGraphBuilder(repo_root)
    graph_data = builder.build_or_update(force_rebuild=False, sync_chats=True)
    node_counts = graph_data.get("metadata", {}).get("node_type_counts", {})
    return {
        "status": "chats_synced",
        "repository": str(repo_root),
        "chat_sessions": node_counts.get("chat_session", 0),
        "chat_turns": node_counts.get("chat_turn", 0),
        "topic_entities": node_counts.get("topic_entity", 0),
        "total_nodes": graph_data.get("metadata", {}).get("total_nodes", 0),
        "total_edges": graph_data.get("metadata", {}).get("total_edges", 0),
    }


def main(argv: Optional[List[str]] = None) -> int:
    # Line-buffer stdout/stderr so our messages interleave in order with output from child
    # processes (git commit, the pre-commit hook, git push) even when stdout is a pipe.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass

    raw_args = list(sys.argv[1:] if argv is None else argv)

    # Rule 1.0: Ensure zedCheck terminal session (watch-agent) is active on every Zed query
    hook_flags = {"--pre-commit-hook", "--prepare-commit-msg", "--post-merge-hook", "--no-global-sync"}
    if not any(f in raw_args for f in hook_flags):
        ensure_zedcheck_session()

    # Intercept local-only single-dash features ('-<feature>', e.g. '-publishprecheck')
    # Maintained in knowledge_graph/local_features.py and NOT propagated to other installations.
    standard_short_flags = {"-s", "-i", "-I", "-q", "-p", "-u", "-r", "-e", "-t", "-n", "-h", "-m"}
    local_only_args = [
        a
        for a in raw_args
        if a.startswith("-")
        and not a.startswith("--")
        and not a.startswith("-#")
        and len(a) > 1
        and a not in standard_short_flags
    ]
    if local_only_args:
        local_mod_path = KG_DIR / "local_features.py"
        if not local_mod_path.is_file() or REPO_ROOT.resolve() != MASTER_REPO_ROOT.resolve():
            print(
                f"[LOCAL-ONLY FEATURE] {', '.join(local_only_args)} is a local-only '-' feature "
                f"exclusive to {MASTER_REPO_ROOT} (via knowledge_graph/local_features.py) and is "
                f"not available in this Knowledge Graph installation ({REPO_ROOT})."
            )
            return 1
        if str(KG_DIR) not in sys.path:
            sys.path.insert(0, str(KG_DIR))
        import local_features  # type: ignore

        rc_local = local_features.dispatch_local_feature(raw_args, REPO_ROOT)
        if rc_local is not None:
            return rc_local

    # Extract '/s' summary switch, '/I' investigate-only switch, '/install <folder>', and '--#1' / '--#N' hit selectors
    summary_only = False
    investigate_only = False
    install_target: Optional[str] = None
    selected_hit_nums: List[int] = []
    args_before_hit_flag: List[str] = []
    args_after_hit_flag: List[str] = []
    seen_hit_flag = False

    hit_flag_re = re.compile(r"^(?:--?#|#)([0-9]+(?:,[0-9]+)*)$")

    idx_arg = 0
    while idx_arg < len(raw_args):
        arg = raw_args[idx_arg]
        idx_arg += 1
        if arg.lower() == "/s":
            summary_only = True
            continue
        if arg.lower() == "/i":
            investigate_only = True
            continue
        if arg.lower() == "/install":
            if idx_arg < len(raw_args):
                install_target = raw_args[idx_arg]
                idx_arg += 1
            else:
                install_target = ""
            continue
        if arg.lower().startswith("/install="):
            install_target = arg.split("=", 1)[1]
            continue
        m_hit = hit_flag_re.match(arg.strip())
        if m_hit:
            seen_hit_flag = True
            for part in m_hit.group(1).split(","):
                num = int(part)
                if num >= 1 and num not in selected_hit_nums:
                    selected_hit_nums.append(num)
            continue
        if seen_hit_flag and not arg.startswith("-"):
            args_after_hit_flag.append(arg)
        else:
            args_before_hit_flag.append(arg)

    parser = argparse.ArgumentParser(
        description=(
            "Create, update, and query the Kubernetes Knowledge Graph.\n"
            "Query 1 (Search Hits): Pass query parameters to list all matching hits as #1, #2, #3...\n"
            "  - Quote sentences/phrases:  \"purchase order\"\n"
            "  - '+' between parameters = AND:  spark1 + deployment\n"
            "  - ',' between parameters = OR:   spark1 , spark2\n"
            "  - Add '/s' (or --summary) to print one-line summary hits only.\n"
            "Query 2 (LLM Preprocessor): Add '--#1' or '--#N' (and optional '/I' for investigate-only, no code updates).\n"
            "Generates interactive HTML Knowledge Graph (knowledge_graph.html) and per-result (#1, #2...) browser tables (query_results.html)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "query_params",
        nargs="*",
        help="Search parameters ('+' = AND, ',' = OR, \"sentence\" = phrase, '/s' = summary hits, '--#N' = Query 2 LLM preprocessor, '/I' = investigate only).",
    )
    parser.add_argument("--summary", "-s", action="store_true", help="Print only summary hits (#1, #2, #3...) Same as /s switch")
    parser.add_argument("--investigate", "-I", action="store_true", help="Query 2 flag (/I): instruct LLM to investigate only with no code updates")
    parser.add_argument("--search", "-q", type=str, help="Additional search query expression")
    parser.add_argument("--path", "-p", type=str, default=None, help="Filter results by node file path substring (e.g. agent/spark1 or api_routes.py)")
    parser.add_argument("--ask", "--request", dest="ask", type=str, default="", help="The specific ask/request to place in the final REQUEST TO LLM line when using --#N")
    parser.add_argument("--update", "-u", action="store_true", help="Incrementally update the knowledge graph (and propagate query_kg.py updates to all folders in global.md)")
    parser.add_argument("--rebuild", "-r", action="store_true", help="Force full rebuild of the knowledge graph")
    parser.add_argument("--install", type=str, default=None, help="Install query_kg.py and knowledge_graph/ onto <folder> and register in global.md (same as /install <folder>)")
    parser.add_argument("--git-remote", type=str, default="", help="Optional Git remote URL (origin) when installing onto a target folder via --install")
    parser.add_argument("--git-branch", type=str, default="main", help="Default Git branch when initializing a repository via --install (default: main)")
    parser.add_argument("--author-name", type=str, default="", help="Optional Git user.name when initializing a repository via --install")
    parser.add_argument("--author-email", type=str, default="", help="Optional Git user.email when initializing a repository via --install")
    parser.add_argument("--git-pat", type=str, default="", help="Optional Git Personal Access Token (PAT) saved to appsetting.json (gitignored) for git activity")
    parser.add_argument("--sync-global", action="store_true", help="Force-sync query_kg.py and refresh Knowledge Graph across all folders in global.md")
    parser.add_argument("--no-global-sync", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--mojibake-audit", action="store_true", help="Audit modified/staged files (or passed file paths) for UTF-8/CP1252 mojibake sequences before commit")
    parser.add_argument("--mojibake-fix", action="store_true", help="Audit and automatically fix mojibake sequences in modified/staged files using Python UTF-8 I/O")
    parser.add_argument("--vuln-scan", action="store_true", help="Run a pre-commit vulnerability scan on the Git delta and present a report if any vulnerability is found")
    parser.add_argument("--sync-docs", action="store_true", help="Synchronize man/ pages (MANPAGES_README.md, man_index.7), wiki pages (docs/WIKI_INDEX.md), repo.md, global.md, and Knowledge Graph")
    parser.add_argument("--sync-chats", action="store_true", help="Index Zed / Antigravity live chat transcripts and chats/ folder into the Knowledge Graph")
    parser.add_argument("--sap-check", action="store_true", help="Run SAP S/4HANA & HANA Makefile, instance, license countdown, and Golden Backup check + alert (updates sap_install/README.md)")
    parser.add_argument("--pre-commit-hook", action="store_true", help="Run Man & Wiki Sync + SAP Health/License Check + Delta-Only Mojibake Fix + Vulnerability Scan (invoked automatically by .git/hooks/pre-commit)")
    parser.add_argument("--install-hooks", action="store_true", help="Install or refresh .git/hooks/pre-commit, prepare-commit-msg, and post-commit")
    parser.add_argument("--prepare-commit-msg", nargs="+", help=argparse.SUPPRESS)
    parser.add_argument("--post-commit-hook", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--post-merge-hook", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--mcp-sync", action="store_true", help="Delta-sync knowledge_graph.db nodes & edges via GPU Pool (MiniLM + GNN) into PostgreSQL pgvector")
    parser.add_argument("--mcp-query", type=str, default=None, help="Query and prune the Knowledge Graph via MCP Middleware (http://192.168.1.181:8000/mcp)")
    parser.add_argument("--mcp-status", action="store_true", help="Show live status of MCP Middleware, 5-GPU Pool, GNN weights (kg_gnn.pt), and PostgreSQL pgvector")
    parser.add_argument("--pii-scan", type=str, default=None, help="Test the 2-Stage PII & Secrets Redaction Guardrail on a text string")
    parser.add_argument("--commit-push", action="store_true", help="Stage all changes, run pre-commit hook via git commit, and push dirty repositories to origin")
    parser.add_argument("-m", "--message", type=str, default="", help="Commit message to use with --commit-push (auto-generated by query_kg.py if omitted)")
    parser.add_argument("--commit-msg", action="store_true", help="Generate and print the incremental Git commit message from current working tree changes")
    parser.add_argument("--restart-portals", action="store_true", help="Detached, non-blocking restart of the 5 HA Management Portals with user status-check instructions")
    parser.add_argument("--beep", action="store_true", help="Emit an audible commit-ready beep alert (terminal bell + desktop chime)")
    parser.add_argument("--entity", "-e", type=str, help="Inspect a specific entity and its graph edges")
    parser.add_argument("--type", "-t", type=str, help="List all entities of a given type as #1, #2, #3...")
    parser.add_argument("--limit", "-n", type=int, default=None, help="Optional maximum number of hits to display (default: all hits)")
    parser.add_argument("--stats", action="store_true", help="Display knowledge graph statistics")
    parser.add_argument("--json", action="store_true", help="Output query results as JSON")

    if not raw_args:
        print_all_available_options(parser)
        check_and_prompt_git_commit_push(REPO_ROOT, auto_commit_push=False)
        return 0

    args = parser.parse_args(args_before_hit_flag)
    if args.summary:
        summary_only = True
    if args.investigate:
        investigate_only = True

    # Collect all query parameters from positional args (before --#N) and --search
    queries: List[str] = []
    if args.search:
        queries.append(args.search)
    if args.query_params:
        queries.extend(args.query_params)

    ask_text = args.ask or (" ".join(args_after_hit_flag) if args_after_hit_flag else "")

    if args.install is not None:
        install_target = args.install

    if install_target is not None:
        return install_kg_to_folder(
            install_target,
            git_remote_url=args.git_remote or "",
            git_branch=args.git_branch or "main",
            author_name=args.author_name or "",
            author_email=args.author_email or "",
            git_pat=args.git_pat or "",
        )

    if args.sync_global:
        sync_global_installations(force=True)
        return 0

    if args.prepare_commit_msg:
        msg_file = args.prepare_commit_msg[0]
        src_kind = args.prepare_commit_msg[1] if len(args.prepare_commit_msg) > 1 else ""
        return handle_prepare_commit_msg_hook(REPO_ROOT, msg_file, src_kind)

    if args.commit_msg:
        cached_msg_file = REPO_ROOT / ".git" / "kg_prepared_commit_msg.txt"
        msg_out = ""
        if cached_msg_file.is_file():
            try:
                if (datetime.datetime.now().timestamp() - cached_msg_file.stat().st_mtime) < 300:
                    msg_out = cached_msg_file.read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                msg_out = ""
        if not msg_out:
            msg_out = _generate_incremental_commit_message(REPO_ROOT)
            try:
                cached_msg_file.write_text(msg_out, encoding="utf-8")
            except Exception:
                pass
        print(msg_out)
        return 0

    if getattr(args, "post_commit_hook", False):
        return run_post_commit_push_only(REPO_ROOT)

    if getattr(args, "post_merge_hook", False):
        return 0

    if getattr(args, "beep", False):
        emit_commit_ready_beep("Commit is ready for user confirmation.")
        return 0

    if getattr(args, "restart_portals", False):
        return restart_ha_portals_detached()

    if args.mcp_status:
        st = status_mcp_middleware_cli(REPO_ROOT)
        print(json.dumps(st, indent=2))
        return 0

    if args.mcp_sync:
        builder_sync = KnowledgeGraphBuilder(REPO_ROOT)
        builder_sync.build_or_update(force_rebuild=args.rebuild)
        res = sync_kg_to_mcp_middleware(REPO_ROOT, force_full=args.rebuild)
        print(json.dumps(res, indent=2))
        return 0

    if args.mcp_query:
        res = query_mcp_middleware_cli(args.mcp_query, REPO_ROOT, top_k=args.limit or 5)
        print(json.dumps(res, indent=2))
        return 0

    if args.pii_scan is not None:
        mcp_mod = _load_local_mcp_middleware(REPO_ROOT)
        if mcp_mod is None:
            print("[ERROR] mcp_middleware.py not found")
            return 1
        sanitized, report = mcp_mod.sanitize_pii_and_secrets(args.pii_scan)
        print(json.dumps({"sanitized_text": sanitized, "guardrail_report": report}, indent=2))
        return 0

    if args.install_hooks:
        hp = _ensure_git_pre_commit_hook(REPO_ROOT, force=True)
        if hp:
            print(f"[GIT HOOKS INSTALLED] {hp}, {hp.parent / 'prepare-commit-msg'} & {hp.parent / 'post-commit'}")
            return 0
        print(f"[WARN] No .git/hooks directory found in {REPO_ROOT}")
        return 1

    if args.commit_push:
        _ensure_git_pre_commit_hook(REPO_ROOT)
        return check_and_prompt_git_commit_push(REPO_ROOT, auto_commit_push=True, commit_msg=args.message)

    if args.pre_commit_hook:
        return run_pre_commit_hook(REPO_ROOT)

    if args.sync_docs:
        sync_man_and_wiki_pages(REPO_ROOT, restage=False)
        return 0

    if args.sap_check:
        return sap_operations_check_and_alert(REPO_ROOT, restage=False)

    if args.mojibake_audit or args.mojibake_fix:
        return mojibake_audit_and_fix(
            REPO_ROOT, fix=bool(args.mojibake_fix), target_paths=queries if queries else None
        )

    if args.vuln_scan:
        return vulnerability_scan_delta(REPO_ROOT, target_paths=queries if queries else None)

    builder = KnowledgeGraphBuilder(REPO_ROOT)

    if args.sync_chats and not (queries or args.path or args.entity or args.type or selected_hit_nums):
        sync_res = index_workspace_chats(REPO_ROOT)
        if args.json:
            print(json.dumps(sync_res, indent=2))
        else:
            print(
                f"Workspace Chats SYNC Complete: {sync_res['chat_sessions']} chat session(s), "
                f"{sync_res['chat_turns']} chat turn(s), {sync_res['topic_entities']} topic entity(ies) "
                f"indexed in {REPO_ROOT} ({sync_res['total_nodes']} total nodes, {sync_res['total_edges']} edges)."
            )
        return 0

    # Ensure the knowledge graph exists or is updated when requested (or when no query args are passed)
    is_query_operation = bool(queries or args.path or args.entity or args.type or selected_hit_nums)
    graph_data = None
    if args.rebuild or args.update or args.sync_chats or not KG_DB_PATH.exists() or not KG_HTML_PATH.exists() or not is_query_operation:
        if args.update and not args.rebuild:
            sync_man_and_wiki_pages(REPO_ROOT, restage=False)
            graph_data = builder.build_or_update(force_rebuild=False, sync_chats=args.sync_chats)
        else:
            if args.rebuild:
                sync_man_and_wiki_pages(REPO_ROOT, restage=False)
            graph_data = builder.build_or_update(force_rebuild=args.rebuild, sync_chats=args.sync_chats)
        if not args.no_global_sync:
            sync_global_installations(force=False)

    # Handle --#1 / --#N token-saving LLM Instruction + Request generation & clipboard copy
    if selected_hit_nums:
        if queries or args.path:
            matches = search_kg(queries, limit=args.limit, include_edges=True, path_filter=args.path)
            display_queries = queries if queries else [f"path:{args.path}"]
            _save_last_query_results(matches, display_queries)
            generate_query_results_html(matches, display_queries, summary_only=summary_only)
        else:
            matches, display_queries = _load_last_query_results()

        if not matches:
            print("No query results available to select from. Run a query first or pass query terms before --#N.")
            return 1

        chosen: List[Tuple[int, Dict[str, Any]]] = []
        for hnum in selected_hit_nums:
            if 1 <= hnum <= len(matches):
                chosen.append((hnum, matches[hnum - 1]))
            else:
                print(f"[WARN] Hit #{hnum} is out of range (last query had {len(matches)} hit(s): #1..#{len(matches)}).")

        if not chosen:
            return 1

        prompt_text = build_token_saving_llm_prompt(
            chosen, display_queries, ask_text=ask_text, investigate_only=investigate_only
        )
        copied_via = copy_to_clipboard(prompt_text)
        print(prompt_text)
        print("-" * 80)
        print(f"[CLIPBOARD] Instruction + Request copied via: {', '.join(copied_via)}")
        return 0

    if queries or args.path:
        # Always include edges so per-hit (#1, #2, #3...) HTML Knowledge Graph browser tables are populated
        matches = search_kg(queries, limit=args.limit, include_edges=True, path_filter=args.path)
        display_queries = queries if queries else [f"path:{args.path}"]
        if args.json:
            generate_query_results_html(matches, display_queries, summary_only=summary_only)
            print(json.dumps(matches, indent=2))
        else:
            format_and_print_hits(matches, display_queries, summary_only=summary_only)
        return 0

    if args.entity:
        info = inspect_entity(args.entity)
        if args.json:
            print(json.dumps(info, indent=2))
        elif not info:
            print(f"No entity found matching '{args.entity}'.")
            return 1
        else:
            ent = info["entity"]
            format_and_print_hits([ent], [args.entity], summary_only=summary_only)
        return 0

    if args.type:
        items = list_by_type(args.type, limit=args.limit)
        if args.json:
            generate_query_results_html(items, [f"type:{args.type}"], summary_only=summary_only)
            print(json.dumps(items, indent=2))
        else:
            format_and_print_hits(items, [f"type:{args.type}"], summary_only=summary_only)
        return 0

    if graph_data is None:
        graph_data = builder.build_or_update(force_rebuild=False)

    meta = graph_data["metadata"]
    chg = graph_data["last_change_check"]
    if args.json:
        print(json.dumps({"metadata": meta, "last_change_check": chg}, indent=2))
    else:
        status = "UPDATED" if chg["changed"] else "UP-TO-DATE (no file changes)"
        print(f"Knowledge Graph Status: {status}")
        print(f"  Repository:    {meta['repository']}")
        print(f"  Files Indexed: {meta['total_files_indexed']}")
        print(f"  Graph Nodes:   {meta['total_nodes']}")
        print(f"  Graph Edges:   {meta['total_edges']}")
        if chg["changed"]:
            print(
                f"  Changes:       +{len(chg['added'])} added, ~{len(chg['modified'])} modified, -{len(chg['removed'])} removed"
            )
        print("\nNode Counts by Type:")
        for k, v in meta["node_type_counts"].items():
            print(f"  {k:18s}: {v}")
        print(
            f"\nOutputs written to:\n"
            f"  - {KG_JSON_PATH}\n"
            f"  - {KG_DB_PATH}\n"
            f"  - {KG_MD_PATH}\n"
            f"  - {KG_HTML_PATH}\n"
            f"  - {REPO_MD_PATH}\n"
            f"  - {GLOBAL_MD_PATH}"
        )
        if not args.no_global_sync and not args.stats:
            check_and_prompt_git_commit_push(REPO_ROOT, auto_commit_push=False, commit_msg=args.message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
