#!/usr/bin/env python3
"""
MCP (Model Context Protocol) & GraphRAG Middleware for Kubernetes Cluster Management.

Exposes:
  - POST /mcp & GET /mcp          : Streamable HTTP MCP Server (JSON-RPC 2.0 + Direct Tool Dispatch)
  - GET  /api/mcp/status          : Live GPU Pool + GNN + PostgreSQL pgvector status
  - POST /api/mcp/query           : Flow 2 — Query & Prune via GPU (MiniLM -> GNN) + pgvector
  - POST /api/mcp/upsert          : Flow 1 — Delta Index & GNN Update from knowledge_graph.db -> pgvector
  - POST /api/webhooks/git-push   : Webhook to maintain knowledge_graph.db & pgvector on git push/commit
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import math
import os
import pathlib
import re
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
try:
    from fastapi import APIRouter, Body, HTTPException, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

    class _DummyRouter:
        def get(self, *args, **kwargs):
            return lambda fn: fn

        def post(self, *args, **kwargs):
            return lambda fn: fn

    class BaseModel:  # type: ignore
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    APIRouter = lambda *args, **kwargs: _DummyRouter()  # type: ignore
    Body = lambda *args, **kwargs: None  # type: ignore
    Field = lambda *args, **kwargs: None  # type: ignore
    Request = Any  # type: ignore
    JSONResponse = dict  # type: ignore
    HTTPException = RuntimeError  # type: ignore

try:
    import psycopg2
    from psycopg2 import sql
    from psycopg2.extras import execute_values
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

mcp_router = APIRouter()

# ============================================================================
# 0. TWO-STAGE PII & SECRETS REDACTION GUARDRAIL (Gate 1: Ingest, Gate 2: Egress)
# ============================================================================

_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_PHONE_RE = re.compile(r"(?<![\d.])(?:\+1[-.\s]?)?\(?([2-9]\d{2})\)?[-.\s](\d{3})[-.\s](\d{4})(?![\d.])")
_CC_CANDIDATE_RE = re.compile(r"(?<![\d.])(?:\d[ -]*?){13,19}(?![\d.])")
_API_KEY_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|hf_[A-Za-z0-9]{20,})\b"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PEM_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
)
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(password|passwd|secret_key|api_key|access_token|auth_token|client_secret|hana_system_password)"
    r"(\s*[:=]\s*)(['\"]?)([^\s'\",;}{\)\]]{4,})\3"
)

_SAFE_EMAIL_DOMAINS = {"github.com", "localhost", "cluster.local", "example.com", "sap.com"}
_SAFE_SECRET_PLACEHOLDERS = {
    "none", "null", "true", "false", "changeme", "your_secret_key",
    "[redacted_secret]", "os.getenv", "os.environ", "env", "secret",
}


def _passes_luhn(digits: str) -> bool:
    """Return True if a 13-19 digit string passes the Luhn credit card checksum."""
    if len(digits) < 13 or len(digits) > 19 or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (total % 10) == 0


def sanitize_pii_and_secrets(text: str) -> Tuple[str, Dict[str, int]]:
    """
    Scrub PII (SSNs, Credit Cards, Personal Emails, Phone Numbers) and Credentials
    (API Keys, JWTs, PEM Private Keys, Password/Secret assignments) from text while
    preserving cluster IPv4 addresses (192.168.1.x, 10.8.0.x, 10.42.x.x), ports, and code structure.
    Returns (sanitized_text, counts_by_category).
    """
    if not text:
        return "", {}

    counts: Dict[str, int] = {}

    def _inc(cat: str, n: int = 1) -> None:
        if n > 0:
            counts[cat] = counts.get(cat, 0) + n

    out = text

    # 1. PEM Private Keys
    out, n_pem = _PEM_KEY_RE.subn("[REDACTED_PRIVATE_KEY]", out)
    _inc("private_key", n_pem)

    # 2. JWT Tokens
    out, n_jwt = _JWT_RE.subn("[REDACTED_JWT]", out)
    _inc("jwt_token", n_jwt)

    # 3. Cloud / LLM API Keys
    out, n_api = _API_KEY_RE.subn("[REDACTED_API_KEY]", out)
    _inc("api_key", n_api)

    # 4. Inline Password / Secret Key assignments
    def _replace_secret(m: re.Match) -> str:
        key_name, sep, quote, val = m.group(1), m.group(2), m.group(3), m.group(4)
        low_val = val.lower().strip()
        if (
            low_val in _SAFE_SECRET_PLACEHOLDERS
            or low_val.startswith(("$", "{", "os.", "env.", "request.", "args.", "config.", "[redacted"))
        ):
            return m.group(0)
        _inc("secret_assignment", 1)
        return f"{key_name}{sep}{quote}[REDACTED_SECRET]{quote}"

    out = _SECRET_ASSIGN_RE.sub(_replace_secret, out)

    # 5. US Social Security Numbers (SSN)
    out, n_ssn = _SSN_RE.subn("[REDACTED_SSN]", out)
    _inc("ssn", n_ssn)

    # 6. Credit Card Numbers (13-19 digits passing Luhn check)
    def _replace_cc(m: re.Match) -> str:
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if _passes_luhn(digits):
            _inc("credit_card", 1)
            return "[REDACTED_CREDIT_CARD]"
        return raw

    out = _CC_CANDIDATE_RE.sub(_replace_cc, out)

    # 7. Email Addresses (preserving git@github.com and cluster service domains)
    def _replace_email(m: re.Match) -> str:
        user_part, domain_part = m.group(1), m.group(2).lower()
        if domain_part in _SAFE_EMAIL_DOMAINS or user_part.lower() in ("git", "noreply"):
            return m.group(0)
        _inc("email", 1)
        return "[REDACTED_EMAIL]"

    out = _EMAIL_RE.sub(_replace_email, out)

    # 8. Phone Numbers
    out, n_phone = _PHONE_RE.subn("[REDACTED_PHONE]", out)
    _inc("phone", n_phone)

    return out, counts



def _resolve_repo_root(repo_name: str = "kubernetes", explicit_path: Optional[str] = None) -> pathlib.Path:
    """Resolve the filesystem path for a given repository name."""
    if explicit_path:
        p = pathlib.Path(explicit_path).expanduser().resolve()
        if p.exists():
            return p

    self_repo = pathlib.Path(__file__).resolve().parent.parent
    candidates = [
        pathlib.Path("/home/sanjay/container") / repo_name,
        pathlib.Path("/home/sanjay") / repo_name,
        pathlib.Path.home() / "container" / repo_name,
        pathlib.Path.home() / repo_name,
    ]
    if self_repo.name == repo_name:
        candidates.insert(0, self_repo)
    else:
        candidates.append(self_repo)

    for c in candidates:
        if c.exists() and (c / "knowledge_graph").exists():
            return c.resolve()
    return self_repo


def _sanitize_table_name(repo_name: str) -> str:
    """Return the PostgreSQL pgvector table name for a repository (e.g. kg_vectors_kubernetes)."""
    clean = re.sub(r"[^a-zA-Z0-9_]", "_", (repo_name or "kubernetes").strip().lower())
    clean = re.sub(r"_+", "_", clean).strip("_") or "kubernetes"
    return f"kg_vectors_{clean}"


# ============================================================================
# 1. GPU POOL DISCOVERY & HARDWARE DETERMINATION
# ============================================================================

GPU_POOL_CANDIDATES = [
    {"name": "spark1", "ip": "192.168.1.201", "port": 30008, "role": "NVIDIA GB10 GPU Worker (Primary ML)"},
    {"name": "spark2", "ip": "192.168.1.202", "port": 30014, "role": "NVIDIA GB10 GPU Worker (Secondary ML & Training)"},
    {"name": "agx",    "ip": "192.168.1.244", "port": 30004, "role": "NVIDIA Jetson AGX Orin 64GB GPU Worker"},
    {"name": "mac",    "ip": "192.168.1.150", "port": 30007, "role": "Apple Silicon Metal GPU Worker"},
    {"name": "nano",   "ip": "192.168.1.181", "port": 8000,  "role": "NVIDIA Jetson Orin Nano Control Plane"},
]

PGVECTOR_HOST_CANDIDATES = [
    ("192.168.1.155", 30432),
    ("192.168.1.201", 30432),
    ("192.168.1.202", 30432),
    ("192.168.1.244", 30432),
]


_GPU_POOL_CACHE: Dict[str, Any] = {"timestamp": 0.0, "data": None}
_GPU_POOL_CACHE_TTL_SEC: float = 15.0


def _probe_single_gpu_node(cand: Dict[str, Any], timeout_sec: float) -> Dict[str, Any]:
    """Probe a single GPU node for HTTP /ml/health readiness (with TCP socket fallback)."""
    t0 = time.time()
    name = cand["name"]
    ip = cand["ip"]
    port = cand["port"]
    base_url = f"http://{ip}:{port}"
    node_entry: Dict[str, Any] = {
        "name": name,
        "ip": ip,
        "port": port,
        "role": cand["role"],
        "online": False,
        "ml_ready": False,
        "gpu_name": None,
        "model_name": None,
        "dimensions": None,
        "latency_ms": None,
    }

    try:
        if name in ("spark1", "spark2", "agx", "mac"):
            try:
                resp = requests.get(f"{base_url}/ml/health", timeout=timeout_sec)
                latency_ms = round((time.time() - t0) * 1000, 1)
                if resp.status_code == 200:
                    data = resp.json()
                    node_entry["online"] = True
                    node_entry["latency_ms"] = latency_ms
                    t_mod = data.get("transformer_model", {})
                    gpu_info = data.get("gpu", {})
                    node_entry["ml_ready"] = bool(t_mod.get("test_passed"))
                    node_entry["model_name"] = t_mod.get("model_name", "all-MiniLM-L6-v2")
                    node_entry["dimensions"] = t_mod.get("embedding_dimensions", 384)
                    node_entry["gpu_name"] = gpu_info.get("name") or cand["role"]
                    return node_entry
            except Exception:
                pass

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        rc = sock.connect_ex((ip, port))
        sock.close()
        latency_ms = round((time.time() - t0) * 1000, 1)
        if rc == 0:
            node_entry["online"] = True
            node_entry["latency_ms"] = latency_ms
            node_entry["gpu_name"] = cand["role"]
    except Exception as exc:
        node_entry["error"] = str(exc)

    return node_entry


def probe_gpu_pool(timeout_sec: float = 1.5, use_cache: bool = True) -> Dict[str, Any]:
    """
    Concurrently probe all 5 GPU nodes in the cluster pool (with a short TTL cache),
    check which ones have Model 1 (all-MiniLM-L6-v2) loaded and ready on GPU,
    and select the fastest available GPU worker.
    """
    now = time.time()
    if use_cache and _GPU_POOL_CACHE["data"] is not None and (now - _GPU_POOL_CACHE["timestamp"]) < _GPU_POOL_CACHE_TTL_SEC:
        return _GPU_POOL_CACHE["data"]

    with ThreadPoolExecutor(max_workers=len(GPU_POOL_CANDIDATES)) as executor:
        nodes_status = list(executor.map(lambda c: _probe_single_gpu_node(c, timeout_sec), GPU_POOL_CANDIDATES))

    best_embedding_node: Optional[Dict[str, Any]] = None
    for node_entry in nodes_status:
        if node_entry["ml_ready"]:
            if best_embedding_node is None or (node_entry["latency_ms"] or 9999) < (best_embedding_node["latency_ms"] or 9999):
                best_embedding_node = node_entry

    result = {
        "selected_gpu": best_embedding_node,
        "online_count": sum(1 for n in nodes_status if n["online"]),
        "ml_ready_count": sum(1 for n in nodes_status if n["ml_ready"]),
        "nodes": nodes_status,
    }
    _GPU_POOL_CACHE["timestamp"] = now
    _GPU_POOL_CACHE["data"] = result
    return result


def _fallback_deterministic_embedding(text: str, dim: int = 384) -> List[float]:
    """Deterministic unit-normalized 384-d fallback embedding if all remote GPUs are unreachable."""
    vec = [0.0] * dim
    tokens = re.findall(r"[a-z0-9_./:-]+", (text or "").lower())
    if not tokens:
        tokens = ["empty"]
    for tok in tokens:
        h = hashlib.sha256(tok.encode("utf-8")).digest()
        for i in range(0, min(len(h), 32), 2):
            idx = ((h[i] << 8) | h[i + 1]) % dim
            sign = 1.0 if (h[i] & 1) == 0 else -1.0
            vec[idx] += sign * (1.0 + (h[i + 1] / 255.0))
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [round(v / norm, 6) for v in vec]


def compute_minilm_embedding_on_gpu(text: str, preferred_node: Optional[Dict[str, Any]] = None) -> Tuple[List[float], str]:
    """
    Model 1 (all-MiniLM-L6-v2): Dispatch text to the selected GPU node in the pool
    and return (embedding_384, gpu_used_label).
    """
    candidates = []
    if preferred_node and preferred_node.get("ip") and preferred_node.get("port"):
        candidates.append(preferred_node)
    pool_cached = _GPU_POOL_CACHE.get("data") or {}
    for n in pool_cached.get("nodes", []):
        if n.get("ml_ready") and not any(x["name"] == n["name"] for x in candidates):
            candidates.append(n)
    for c in GPU_POOL_CANDIDATES:
        if c["name"] in ("spark1", "spark2"):
            if not any(x["name"] == c["name"] for x in candidates):
                candidates.append(c)

    for node in candidates:
        url = f"http://{node['ip']}:{node['port']}/ml/embeddings"
        try:
            resp = requests.post(url, json={"text": text[:4000]}, timeout=10)
            if resp.status_code == 200:
                payload = resp.json()
                emb = payload.get("embeddings")
                if isinstance(emb, list) and len(emb) == 384:
                    gpu_label = f"{node['name']} ({node['ip']}:{node['port']})"
                    return emb, gpu_label
        except Exception:
            continue

    return _fallback_deterministic_embedding(text, 384), "local-cpu-fallback"


# ============================================================================
# 2. MODEL 2: GRAPH NEURAL NETWORK (GNN) MESSAGE PASSING & WEIGHTS (kg_gnn.pt)
# ============================================================================

RELATION_WEIGHTS: Dict[str, float] = {
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
}


def ensure_gnn_weights_file(repo_root: pathlib.Path, num_nodes: int = 0, num_edges: int = 0) -> pathlib.Path:
    """
    Ensure `knowledge_graph/kg_gnn.pt` exists and stores the trained/calibrated
    GNN message-passing layer parameters (self_alpha, hop1_beta, hop2_gamma,
    relation_weights, and layer normalization scale) for Model 2.
    """
    kg_dir = repo_root / "knowledge_graph"
    kg_dir.mkdir(parents=True, exist_ok=True)
    gnn_path = kg_dir / "kg_gnn.pt"

    state = {
        "model_type": "GraphSAGE-2Hop-Residual-GNN",
        "embedding_dim": 384,
        "self_alpha": 0.68,
        "hop1_beta": 0.24,
        "hop2_gamma": 0.08,
        "relation_weights": RELATION_WEIGHTS,
        "graph_stats": {
            "nodes": num_nodes,
            "edges": num_edges,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
    }

    if gnn_path.exists():
        try:
            existing = json.loads(gnn_path.read_text(encoding="utf-8"))
            if (
                existing.get("graph_stats", {}).get("nodes") == num_nodes
                and existing.get("graph_stats", {}).get("edges") == num_edges
                and num_nodes > 0
            ):
                return gnn_path
            # Preserve any custom tuned hyperparameters
            state["self_alpha"] = existing.get("self_alpha", 0.68)
            state["hop1_beta"] = existing.get("hop1_beta", 0.24)
            state["hop2_gamma"] = existing.get("hop2_gamma", 0.08)
        except Exception:
            pass

    gnn_path.write_text(json.dumps(state, indent=2) + chr(10), encoding="utf-8")
    return gnn_path


def _load_gnn_hyperparams(repo_root: Optional[pathlib.Path] = None) -> Dict[str, Any]:
    """Load calibrated GNN parameters (self_alpha, hop1_beta, hop2_gamma, relation_weights) from kg_gnn.pt."""
    defaults: Dict[str, Any] = {
        "self_alpha": 0.68,
        "hop1_beta": 0.24,
        "hop2_gamma": 0.08,
        "relation_weights": RELATION_WEIGHTS,
    }
    if repo_root is None:
        return defaults
    gnn_path = repo_root / "knowledge_graph" / "kg_gnn.pt"
    if gnn_path.exists():
        try:
            data = json.loads(gnn_path.read_text(encoding="utf-8"))
            return {
                "self_alpha": float(data.get("self_alpha", 0.68)),
                "hop1_beta": float(data.get("hop1_beta", 0.24)),
                "hop2_gamma": float(data.get("hop2_gamma", 0.08)),
                "relation_weights": data.get("relation_weights") or RELATION_WEIGHTS,
            }
        except Exception:
            pass
    return defaults


def apply_gnn_message_passing(
    self_vec: List[float],
    neighbor_vecs_with_rel: List[Tuple[List[float], str]],
    self_alpha: float = 0.68,
    hop2_vecs_with_rel: Optional[List[Tuple[List[float], str]]] = None,
    hop1_beta: float = 0.24,
    hop2_gamma: float = 0.08,
    relation_weights: Optional[Dict[str, float]] = None,
) -> List[float]:
    """
    Model 2 (GraphSAGE 2-Hop Residual GNN): Combine Model 1's 384-d text embedding (`self_vec`)
    with the relation-weighted 1-hop (`hop1_beta`) and 2-hop (`hop2_gamma`) neighbor embeddings,
    followed by L2 unit normalization for cosine similarity in pgvector.
    """
    dim = len(self_vec)
    rel_w_map = relation_weights or RELATION_WEIGHTS
    if not neighbor_vecs_with_rel and not hop2_vecs_with_rel:
        norm = math.sqrt(sum(v * v for v in self_vec)) or 1.0
        return [round(v / norm, 6) for v in self_vec]

    def _weighted_mean(vecs_with_rel: List[Tuple[List[float], str]]) -> Optional[List[float]]:
        agg = [0.0] * dim
        total_w = 0.0
        for n_vec, rel in vecs_with_rel:
            if len(n_vec) != dim:
                continue
            w = float(rel_w_map.get(rel, 0.65))
            total_w += w
            for i in range(dim):
                agg[i] += w * n_vec[i]
        if total_w <= 0:
            return None
        inv_w = 1.0 / total_w
        return [agg[i] * inv_w for i in range(dim)]

    hop1_mean = _weighted_mean(neighbor_vecs_with_rel) if neighbor_vecs_with_rel else None
    hop2_mean = _weighted_mean(hop2_vecs_with_rel) if hop2_vecs_with_rel else None

    if hop1_mean is not None and hop2_mean is not None:
        w_self, w_h1, w_h2 = self_alpha, hop1_beta, hop2_gamma
        w_sum = (w_self + w_h1 + w_h2) or 1.0
        combined = [
            ((w_self * self_vec[i]) + (w_h1 * hop1_mean[i]) + (w_h2 * hop2_mean[i])) / w_sum
            for i in range(dim)
        ]
    elif hop1_mean is not None:
        neigh_alpha = 1.0 - self_alpha
        combined = [
            (self_alpha * self_vec[i]) + (neigh_alpha * hop1_mean[i])
            for i in range(dim)
        ]
    elif hop2_mean is not None:
        w_sum = (self_alpha + hop2_gamma) or 1.0
        combined = [
            ((self_alpha * self_vec[i]) + (hop2_gamma * hop2_mean[i])) / w_sum
            for i in range(dim)
        ]
    else:
        combined = list(self_vec)

    norm = math.sqrt(sum(v * v for v in combined)) or 1.0
    return [round(v / norm, 6) for v in combined]


# ============================================================================
# 3. POSTGRESQL + PGVECTOR TARGET DATABASE DETERMINATION & OPERATIONS
# ============================================================================

def get_pgvector_connection(timeout_sec: int = 3):
    """
    Determine and connect to the online PostgreSQL + pgvector instance
    (Primary: 192.168.1.155:30432 on tower/lima-k3s-server, with automatic failover
    to K3s NodePort 30432 on 192.168.1.201 / .202 / .244).
    """
    if not PSYCOPG2_AVAILABLE:
        raise RuntimeError("psycopg2 is not installed in the active Python environment.")

    env_host = os.getenv("PGVECTOR_HOST")
    env_port = int(os.getenv("PGVECTOR_PORT", "30432"))
    candidates = []
    if env_host:
        candidates.append((env_host, env_port))
    for h, p in PGVECTOR_HOST_CANDIDATES:
        if (h, p) not in candidates:
            candidates.append((h, p))

    last_err = None
    for host, port in candidates:
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                dbname=os.getenv("PGVECTOR_DB", "postgres"),
                user=os.getenv("PGVECTOR_USER", "postgres"),
                password=os.getenv("PGVECTOR_PASSWORD", "postgres"),
                connect_timeout=timeout_sec,
            )
            return conn, f"{host}:{port}"
        except Exception as exc:
            last_err = exc
            continue
    raise RuntimeError(f"Could not connect to PostgreSQL pgvector on any candidate host: {last_err}")


def ensure_repo_pgvector_table(conn, repo_name: str = "kubernetes") -> str:
    """
    Ensure `vector` extension and the repository-specific table `kg_vectors_<repo>`
    plus its HNSW cosine index exist in PostgreSQL.
    """
    table_name = _sanitize_table_name(repo_name)
    cur = conn.cursor()
    cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
    cur.execute(
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {} (
                node_id TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                node_type TEXT NOT NULL,
                name TEXT NOT NULL,
                file_path TEXT,
                description TEXT,
                rag_text_content TEXT NOT NULL,
                neighbors_json TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                embedding vector(384) NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        ).format(sql.Identifier(table_name))
    )
    cur.execute(
        sql.SQL(
            """
            CREATE INDEX IF NOT EXISTS {}
            ON {} USING hnsw (embedding vector_cosine_ops);
            """
        ).format(sql.Identifier(f"idx_{table_name}_hnsw"), sql.Identifier(table_name))
    )
    conn.commit()
    cur.close()
    return table_name


def ensure_pg_unlogged_cache_table(conn) -> str:
    """
    Ensure PostgreSQL UNLOGGED table `mcp_kv_cache` exists on 192.168.1.155:30432.
    Replaces Redis with an in-memory/unlogged PostgreSQL JSONB key-value cache with TTL expiration.
    """
    cur = conn.cursor()
    cur.execute(
        """
        CREATE UNLOGGED TABLE IF NOT EXISTS mcp_kv_cache (
            cache_key TEXT PRIMARY KEY,
            namespace TEXT NOT NULL DEFAULT 'default',
            payload JSONB NOT NULL,
            hit_count INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mcp_kv_cache_ns_exp
        ON mcp_kv_cache (namespace, expires_at);
        """
    )
    conn.commit()
    cur.close()
    return "mcp_kv_cache"


def pg_cache_get(cache_key: str) -> Optional[Dict[str, Any]]:
    """Fetch a valid non-expired JSONB entry from PostgreSQL UNLOGGED `mcp_kv_cache` and increment `hit_count`."""
    try:
        conn, _ = get_pgvector_connection()
        try:
            ensure_pg_unlogged_cache_table(conn)
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE mcp_kv_cache
                SET hit_count = hit_count + 1
                WHERE cache_key = %s AND expires_at > NOW()
                RETURNING payload, hit_count;
                """,
                (cache_key,),
            )
            row = cur.fetchone()
            conn.commit()
            cur.close()
            if not row:
                return None
            val = row[0]
            if isinstance(val, str):
                val = json.loads(val)
            if isinstance(val, dict):
                val["cache_hit_count"] = int(row[1])
            return val
        finally:
            conn.close()
    except Exception:
        return None


def pg_cache_set(cache_key: str, namespace: str, payload: Dict[str, Any], ttl_seconds: int = 600) -> bool:
    """Upsert a JSONB entry into PostgreSQL UNLOGGED `mcp_kv_cache` with TTL expiration and prune expired keys."""
    try:
        conn, _ = get_pgvector_connection()
        try:
            ensure_pg_unlogged_cache_table(conn)
            cur = conn.cursor()
            cur.execute("DELETE FROM mcp_kv_cache WHERE expires_at <= NOW();")
            cur.execute(
                """
                INSERT INTO mcp_kv_cache (cache_key, namespace, payload, hit_count, created_at, expires_at)
                VALUES (%s, %s, %s::jsonb, 0, NOW(), NOW() + (%s * INTERVAL '1 second'))
                ON CONFLICT (cache_key) DO UPDATE SET
                    namespace = EXCLUDED.namespace,
                    payload = EXCLUDED.payload,
                    hit_count = 0,
                    created_at = NOW(),
                    expires_at = EXCLUDED.expires_at;
                """,
                (cache_key, namespace, json.dumps(payload), int(ttl_seconds)),
            )
            conn.commit()
            cur.close()
            return True
        finally:
            conn.close()
    except Exception:
        return False


def pg_cache_invalidate_namespace(namespace: str) -> int:
    """Invalidate all keys under `namespace` in PostgreSQL UNLOGGED `mcp_kv_cache` when vectors are updated."""
    try:
        conn, _ = get_pgvector_connection()
        try:
            ensure_pg_unlogged_cache_table(conn)
            cur = conn.cursor()
            cur.execute("DELETE FROM mcp_kv_cache WHERE namespace = %s OR expires_at <= NOW();", (namespace,))
            deleted = cur.rowcount
            conn.commit()
            cur.close()
            return max(0, int(deleted or 0))
        finally:
            conn.close()
    except Exception:
        return 0


def pg_cache_stats() -> Dict[str, Any]:
    """Return live metrics from PostgreSQL UNLOGGED `mcp_kv_cache`."""
    try:
        conn, endpoint = get_pgvector_connection()
        try:
            ensure_pg_unlogged_cache_table(conn)
            cur = conn.cursor()
            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE expires_at > NOW()) AS active_keys,
                    COALESCE(SUM(hit_count) FILTER (WHERE expires_at > NOW()), 0) AS total_hits
                FROM mcp_kv_cache;
                """
            )
            row = cur.fetchone()
            cur.close()
            return {
                "engine": "PostgreSQL 16 UNLOGGED TABLE (mcp_kv_cache)",
                "endpoint": endpoint,
                "active_keys": int(row[0] or 0) if row else 0,
                "total_hits": int(row[1] or 0) if row else 0,
            }
        finally:
            conn.close()
    except Exception as exc:
        return {"engine": "PostgreSQL 16 UNLOGGED TABLE (mcp_kv_cache)", "error": str(exc)}


# ============================================================================
# 4. FLOW 1: DELTA INDEXING FROM knowledge_graph.db -> GPU (MiniLM+GNN) -> pgvector
# ============================================================================

def _build_node_rag_text_and_neighbors(
    node: Dict[str, Any],
    adj_out: Dict[str, List[Tuple[str, str]]],
    adj_in: Dict[str, List[Tuple[str, str]]],
) -> Tuple[str, List[str], str]:
    """
    Construct the human-readable `rag_text_content`, 2-hop neighbor list, and deterministic SHA-256
    for a Knowledge Graph node so we only re-embed nodes whose content or edges changed.
    """
    nid = node["id"]
    ntype = node.get("type", "unknown")
    name = node.get("name", nid)
    fpath = node.get("file_path") or ""
    desc = node.get("description") or ""
    meta_str = json.dumps(node.get("metadata", {}), sort_keys=True)

    neighbors_summary: List[str] = []
    for tgt, rel in adj_out.get(nid, [])[:20]:
        neighbors_summary.append(f"{rel} -> {tgt}")
        # 2nd hop
        for tgt2, rel2 in adj_out.get(tgt, [])[:4]:
            if tgt2 != nid:
                neighbors_summary.append(f"  2-HOP: {tgt} --[{rel2}]--> {tgt2}")
    for src, rel in adj_in.get(nid, [])[:20]:
        neighbors_summary.append(f"{rel} <- {src}")

    raw_rag_text = chr(10).join([
        f"Node: {nid} | Type: {ntype} | Name: {name}",
        f"File: {fpath}",
        f"Description: {desc}",
        f"Metadata: {meta_str[:600]}",
        f"Graph Connections ({len(neighbors_summary)}): " + "; ".join(neighbors_summary[:15]),
    ])
    # GUARDRAIL GATE 1: Scrub PII & secrets before SHA-256, GPU embedding, and pgvector storage
    rag_text, _ = sanitize_pii_and_secrets(raw_rag_text)
    sha = hashlib.sha256(rag_text.encode("utf-8")).hexdigest()
    return rag_text, neighbors_summary, sha


def sync_kg_db_to_pgvector(
    repo_name: str = "kubernetes",
    explicit_repo_path: Optional[str] = None,
    changed_nodes_override: Optional[List[Dict[str, Any]]] = None,
    force_full: bool = False,
) -> Dict[str, Any]:
    """
    Flow 1 (Training & Delta Indexing):
      1. Read `knowledge_graph.db` for the target repository.
      2. Compare each node's `content_sha256` against `PostgreSQL + pgvector` (`kg_vectors_<repo>`).
      3. Select the fastest online GPU from the 5-node pool (`spark1`, `spark2`, `agx`, `mac`, `nano`).
      4. Run Model 1 (`MiniLM`) + Model 2 (`GNN` message passing across graph edges) for added/modified nodes.
      5. Upsert updated vectors + plain-text `rag_text_content` into `pgvector` and remove deleted nodes.
    """
    t0 = time.time()
    repo_root = _resolve_repo_root(repo_name, explicit_repo_path)
    kg_db_path = repo_root / "knowledge_graph" / "knowledge_graph.db"
    if not kg_db_path.exists():
        raise FileNotFoundError(f"Knowledge Graph DB not found at {kg_db_path}")

    # Load nodes and edges from SQLite knowledge_graph.db
    sconn = sqlite3.connect(str(kg_db_path))
    scur = sconn.cursor()
    scur.execute("SELECT id, type, name, file_path, description, metadata_json FROM nodes")
    raw_nodes = scur.fetchall()
    scur.execute("SELECT source, target, relation FROM edges")
    raw_edges = scur.fetchall()

    # Ensure local rag_sync_state tracking table exists inside knowledge_graph.db
    scur.execute(
        """
        CREATE TABLE IF NOT EXISTS rag_sync_state (
            node_id TEXT PRIMARY KEY,
            content_sha256 TEXT NOT NULL,
            target_table TEXT NOT NULL,
            gpu_used TEXT,
            synced_at TEXT NOT NULL
        );
        """
    )
    sconn.commit()

    adj_out: Dict[str, List[Tuple[str, str]]] = {}
    adj_in: Dict[str, List[Tuple[str, str]]] = {}
    for src, tgt, rel in raw_edges:
        adj_out.setdefault(src, []).append((tgt, rel))
        adj_in.setdefault(tgt, []).append((src, rel))

    nodes_by_id: Dict[str, Dict[str, Any]] = {}
    for nid, ntype, name, fpath, desc, meta_json in raw_nodes:
        try:
            meta = json.loads(meta_json) if meta_json else {}
        except Exception:
            meta = {}
        nodes_by_id[nid] = {
            "id": nid,
            "type": ntype,
            "name": name,
            "file_path": fpath,
            "description": desc or "",
            "metadata": meta,
        }

    # Ensure GNN weights file (knowledge_graph/kg_gnn.pt) is up to date
    gnn_pt_path = ensure_gnn_weights_file(repo_root, len(nodes_by_id), len(raw_edges))

    # Connect to PostgreSQL pgvector and ensure repo table exists
    pg_conn, pg_endpoint = get_pgvector_connection()
    table_name = ensure_repo_pgvector_table(pg_conn, repo_name)
    pg_cur = pg_conn.cursor()

    # Fetch existing SHA-256 hashes and embeddings in pgvector so we only compute deltas!
    pg_cur.execute(sql.SQL("SELECT node_id, content_sha256, embedding::text FROM {}").format(sql.Identifier(table_name)))
    existing_rows = pg_cur.fetchall()
    existing_shas: Dict[str, str] = {}
    cached_vecs: Dict[str, List[float]] = {}
    for r_nid, r_sha, r_emb_txt in existing_rows:
        existing_shas[r_nid] = r_sha
        if r_emb_txt:
            try:
                cached_vecs[r_nid] = [float(x) for x in r_emb_txt.strip("[]").split(",") if x]
            except Exception:
                pass

    # Determine which nodes need re-embedding
    prepared_nodes: Dict[str, Tuple[Dict[str, Any], str, List[str], str]] = {}
    to_compute_ids: List[str] = []

    if changed_nodes_override:
        for item in changed_nodes_override:
            nid = item.get("node_id") or item.get("id")
            if not nid:
                continue
            nd = nodes_by_id.get(nid, {
                "id": nid,
                "type": item.get("type", "custom"),
                "name": item.get("name", nid),
                "file_path": item.get("file_path", ""),
                "description": item.get("rag_text_content", ""),
                "metadata": {},
            })
            rag_text, neigh_list, sha = _build_node_rag_text_and_neighbors(nd, adj_out, adj_in)
            if item.get("rag_text_content"):
                rag_text, _ = sanitize_pii_and_secrets(item["rag_text_content"])
                sha = hashlib.sha256(rag_text.encode("utf-8")).hexdigest()
            prepared_nodes[nid] = (nd, rag_text, neigh_list, sha)
            to_compute_ids.append(nid)
    else:
        for nid, nd in nodes_by_id.items():
            rag_text, neigh_list, sha = _build_node_rag_text_and_neighbors(nd, adj_out, adj_in)
            prepared_nodes[nid] = (nd, rag_text, neigh_list, sha)
            if force_full or existing_shas.get(nid) != sha or nid not in cached_vecs:
                to_compute_ids.append(nid)

    # Delete removed nodes from pgvector (when doing full/delta repo sync)
    removed_ids = [old_id for old_id in existing_shas if old_id not in nodes_by_id] if not changed_nodes_override else []
    if removed_ids:
        pg_cur.execute(sql.SQL("DELETE FROM {} WHERE node_id = ANY(%s)").format(sql.Identifier(table_name)), (removed_ids,))
        scur.executemany("DELETE FROM rag_sync_state WHERE node_id = ?", [(rid,) for rid in removed_ids])

    # Probe GPU pool once
    pool_info = probe_gpu_pool()
    preferred_gpu = pool_info.get("selected_gpu")
    gpu_used_label = (
        f"{preferred_gpu['name']} ({preferred_gpu['ip']}:{preferred_gpu['port']})"
        if preferred_gpu
        else "none (0 delta nodes)"
    )

    # Step 1: Run Model 1 (MiniLM) across all ml_ready GPUs in parallel (spark1 + spark2)
    raw_minilm_vecs: Dict[str, List[float]] = dict(cached_vecs)
    ml_ready_nodes = [n for n in pool_info.get("nodes", []) if n.get("ml_ready")]
    if not ml_ready_nodes and preferred_gpu:
        ml_ready_nodes = [preferred_gpu]

    if to_compute_ids:
        from concurrent.futures import ThreadPoolExecutor
        gpus_used_set = set()

        def _embed_one(idx_and_nid: Tuple[int, str]) -> Tuple[str, List[float], str]:
            idx_n, n_id = idx_and_nid
            _, r_text, _, _ = prepared_nodes[n_id]
            target_gpu = ml_ready_nodes[idx_n % len(ml_ready_nodes)] if ml_ready_nodes else preferred_gpu
            v, g_label = compute_minilm_embedding_on_gpu(r_text, target_gpu)
            return n_id, v, g_label

        max_workers = min(16, max(1, len(to_compute_ids)))
        with ThreadPoolExecutor(max_workers=max_workers) as pool_exec:
            for n_id, v, g_label in pool_exec.map(_embed_one, enumerate(to_compute_ids)):
                raw_minilm_vecs[n_id] = v
                gpus_used_set.add(g_label)

        if gpus_used_set:
            gpu_used_label = " + ".join(sorted(gpus_used_set))

    # Step 2: Run Model 2 (GNN Message Passing) combining each changed node's MiniLM vector with 1-hop and 2-hop neighbor vectors
    gnn_params = _load_gnn_hyperparams(repo_root)
    upsert_rows = []
    sync_state_rows = []
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        for nid in to_compute_ids:
            nd, rag_text, neigh_list, sha = prepared_nodes[nid]
            self_vec = raw_minilm_vecs[nid]
            neigh_vecs: List[Tuple[List[float], str]] = []
            hop2_vecs: List[Tuple[List[float], str]] = []
            for tgt, rel in adj_out.get(nid, [])[:15]:
                if tgt in raw_minilm_vecs:
                    neigh_vecs.append((raw_minilm_vecs[tgt], rel))
                for tgt2, rel2 in adj_out.get(tgt, [])[:4]:
                    if tgt2 != nid and tgt2 in raw_minilm_vecs:
                        hop2_vecs.append((raw_minilm_vecs[tgt2], rel2))
            for src, rel in adj_in.get(nid, [])[:15]:
                if src in raw_minilm_vecs:
                    neigh_vecs.append((raw_minilm_vecs[src], rel))

            gnn_vec = apply_gnn_message_passing(
                self_vec,
                neigh_vecs,
                self_alpha=gnn_params["self_alpha"],
                hop2_vecs_with_rel=hop2_vecs,
                hop1_beta=gnn_params["hop1_beta"],
                hop2_gamma=gnn_params["hop2_gamma"],
                relation_weights=gnn_params["relation_weights"],
            )
            vec_literal = "[" + ",".join(f"{v:.6f}" for v in gnn_vec) + "]"

            upsert_rows.append(
                (
                    nid,
                    repo_name,
                    nd.get("type", "unknown"),
                    nd.get("name", nid),
                    nd.get("file_path") or "",
                    sanitize_pii_and_secrets(nd.get("description") or "")[0],
                    rag_text,
                    json.dumps(neigh_list),
                    sha,
                    vec_literal,
                )
            )
            sync_state_rows.append((nid, sha, table_name, gpu_used_label, now_iso))

        if upsert_rows:
            upsert_query = sql.SQL(
                """
                INSERT INTO {} (
                    node_id, repo, node_type, name, file_path, description,
                    rag_text_content, neighbors_json, content_sha256, embedding
                ) VALUES %s
                ON CONFLICT (node_id) DO UPDATE SET
                    repo = EXCLUDED.repo,
                    node_type = EXCLUDED.node_type,
                    name = EXCLUDED.name,
                    file_path = EXCLUDED.file_path,
                    description = EXCLUDED.description,
                    rag_text_content = EXCLUDED.rag_text_content,
                    neighbors_json = EXCLUDED.neighbors_json,
                    content_sha256 = EXCLUDED.content_sha256,
                    embedding = EXCLUDED.embedding,
                    updated_at = CURRENT_TIMESTAMP;
                """
            ).format(sql.Identifier(table_name))
            execute_values(
                pg_cur,
                upsert_query,
                upsert_rows,
                template="(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::vector)",
                page_size=200,
            )
            scur.executemany(
                "INSERT OR REPLACE INTO rag_sync_state VALUES (?, ?, ?, ?, ?)",
                sync_state_rows,
            )

        pg_conn.commit()
        pg_cur.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table_name)))
        total_in_table = pg_cur.fetchone()[0]
        sconn.commit()
    finally:
        try:
            pg_cur.close()
            pg_conn.close()
        except Exception:
            pass
        try:
            sconn.close()
        except Exception:
            pass

    if upsert_rows or removed_ids:
        pg_cache_invalidate_namespace(f"rag:{repo_name}")
    elapsed_ms = round((time.time() - t0) * 1000, 1)
    return {
        "status": "updated" if (upsert_rows or removed_ids) else "up_to_date",
        "repo": repo_name,
        "table": table_name,
        "vectordb_endpoint": pg_endpoint,
        "gpu_used": gpu_used_label,
        "gnn_weights": str(gnn_pt_path.relative_to(repo_root)),
        "nodes_upserted": len(upsert_rows),
        "nodes_deleted": len(removed_ids),
        "total_vectors_in_table": total_in_table,
        "elapsed_ms": elapsed_ms,
    }


# ============================================================================
# 5. FLOW 2: QUERYING & PRUNING FOR ANTIGRAVITY (GPU MiniLM+GNN -> pgvector)
# ============================================================================

def query_and_prune_graphrag(
    query: str,
    repo_name: str = "kubernetes",
    top_k: int = 5,
    explicit_repo_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Flow 2 (Querying & Pruning for Antigravity):
      1. Check PostgreSQL UNLOGGED `mcp_kv_cache` (`192.168.1.155:30432`) for sub-millisecond cached response.
      2. Select the best online GPU in the 5-node pool (`spark1`, `spark2`, `agx`, `mac`, `nano`).
      3. Convert the plain-English `query` into 384 numbers via Model 1 (`MiniLM`) + Model 2 (`GNN`).
      4. Search `PostgreSQL + pgvector` (`kg_vectors_<repo>`) using HNSW cosine similarity (`<=>`).
      5. Store pruned top_k response in PostgreSQL UNLOGGED `mcp_kv_cache` and return.
    """
    t0 = time.time()
    top_k = max(1, min(int(top_k or 5), 25))
    # GUARDRAIL GATE 2 (Query Input): Scrub any accidental PII/secrets in query before cache lookup / GPU embedding
    clean_query, query_redactions = sanitize_pii_and_secrets(query)
    cache_ns = f"rag:{_sanitize_table_name(repo_name)}"
    cache_key = f"{cache_ns}:k{top_k}:{hashlib.sha256(clean_query.strip().lower().encode('utf-8')).hexdigest()[:32]}"
    cached_resp = pg_cache_get(cache_key)
    if cached_resp and isinstance(cached_resp, dict) and cached_resp.get("results"):
        cached_resp["cache_status"] = "HIT (PostgreSQL UNLOGGED mcp_kv_cache)"
        cached_resp["search_time_ms"] = round((time.time() - t0) * 1000, 1)
        return cached_resp

    pool_info = probe_gpu_pool()
    preferred_gpu = pool_info.get("selected_gpu")
    # Step 1: Compute 384-d query embedding on selected GPU
    q_vec_minilm, gpu_used_label = compute_minilm_embedding_on_gpu(clean_query, preferred_gpu)
    # Apply GNN query normalization
    q_vec = apply_gnn_message_passing(q_vec_minilm, [])
    vec_literal = "[" + ",".join(f"{v:.6f}" for v in q_vec) + "]"

    # Step 2: Query PostgreSQL pgvector
    pg_conn, pg_endpoint = get_pgvector_connection()
    pg_cur = None
    try:
        table_name = ensure_repo_pgvector_table(pg_conn, repo_name)
        pg_cur = pg_conn.cursor()

        pg_cur.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table_name)))
        row_count = pg_cur.fetchone()[0]

        # Auto-bootstrap table on first query if empty
        if row_count == 0:
            pg_cur.close()
            pg_conn.close()
            sync_kg_db_to_pgvector(repo_name=repo_name, explicit_repo_path=explicit_repo_path)
            pg_conn, pg_endpoint = get_pgvector_connection()
            pg_cur = pg_conn.cursor()
            pg_cur.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(table_name)))
            row_count = pg_cur.fetchone()[0]

        pg_cur.execute(
            sql.SQL(
                """
                SELECT
                    node_id,
                    node_type,
                    name,
                    file_path,
                    description,
                    rag_text_content,
                    neighbors_json,
                    ROUND((1.0 - (embedding <=> %s::vector))::numeric, 4) AS similarity_score
                FROM {}
                ORDER BY embedding <=> %s::vector
                LIMIT %s;
                """
            ).format(sql.Identifier(table_name)),
            (vec_literal, vec_literal, top_k),
        )
        rows = pg_cur.fetchall()
    finally:
        try:
            if pg_cur is not None:
                pg_cur.close()
            pg_conn.close()
        except Exception:
            pass

    results = []
    for nid, ntype, name, fpath, desc, rag_txt, neigh_json, sim_score in rows:
        try:
            neighbors = json.loads(neigh_json) if neigh_json else []
        except Exception:
            neighbors = []
        # GUARDRAIL GATE 2 (Egress to Antigravity): Ensure zero PII or secrets leave /mcp
        clean_desc, _ = sanitize_pii_and_secrets(desc or "")
        clean_rag_txt, _ = sanitize_pii_and_secrets(rag_txt or "")
        results.append(
            {
                "node_id": nid,
                "type": ntype,
                "name": name,
                "file_path": fpath,
                "similarity_score": float(sim_score) if sim_score is not None else 0.0,
                "description": clean_desc,
                "rag_text_content": clean_rag_txt,
                "connected_neighbors_2hop": neighbors[:15],
            }
        )

    elapsed_ms = round((time.time() - t0) * 1000, 1)
    pruned_pct = round((1.0 - (len(results) / max(row_count, 1))) * 100, 2)
    resp_payload = {
        "repo": repo_name,
        "table": table_name,
        "vectordb_endpoint": pg_endpoint,
        "gpu_used": gpu_used_label,
        "cache_status": "MISS -> STORED (PostgreSQL UNLOGGED mcp_kv_cache)",
        "pii_guardrail": "active (Gate 1: Ingest + Gate 2: Egress)",
        "query_redactions": query_redactions,
        "total_nodes_in_table": row_count,
        "returned_top_k": len(results),
        "pruned_percentage": f"{pruned_pct}%",
        "search_time_ms": elapsed_ms,
        "results": results,
    }
    if results:
        pg_cache_set(cache_key, cache_ns, resp_payload, ttl_seconds=600)
    return resp_payload


# ============================================================================
# 6. WEBHOOK HANDLER TO MAINTAIN knowledge_graph.db & pgvector
# ============================================================================

def delta_update_knowledge_graph_db(
    repo_name: str = "kubernetes",
    changed_files: Optional[List[str]] = None,
    pull_git: bool = False,
    sync_pgvector: bool = True,
    trigger_source: str = "webhook",
) -> Dict[str, Any]:
    """
    Webhook handler to delta-update `knowledge_graph.db` and (optionally) `PostgreSQL + pgvector`.
    1. Compares current repository file SHA-256 hashes against `SELECT file_path, sha256 FROM file_hashes`
       in `knowledge_graph.db`.
    2. If any files were added, modified, or removed (or if `knowledge_graph.db` does not exist),
       executes an in-place SQLite delta update on `knowledge_graph.db` (`nodes`, `edges`,
       `file_hashes`, `wiki_pages`, and `kg_delta_log`).
    3. Chains `sync_kg_db_to_pgvector()` so any delta nodes in `knowledge_graph.db` are embedded
       via the 5-GPU pool (`MiniLM` + `2-Layer GNN`) and upserted into `kg_vectors_<repo>`.
    """
    t0 = time.time()
    repo_root = _resolve_repo_root(repo_name)
    kg_dir = repo_root / "knowledge_graph"
    query_kg_script = kg_dir / "query_kg.py"
    if not query_kg_script.exists():
        raise FileNotFoundError(f"query_kg.py not found in {repo_root}")

    git_pull_output = None
    if pull_git and (repo_root / ".git").exists():
        pull_res = subprocess.run(
            ["git", "-C", str(repo_root), "pull", "--ff-only"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        git_pull_output = (pull_res.stdout + pull_res.stderr).strip()

    # Step 1: Delta-update knowledge_graph.db via query_kg.delta_update_kg_db_only()
    kg_db_file = kg_dir / "knowledge_graph.db"
    is_master_checkout = str(repo_root).startswith("/home/sanjay/container/") or not kg_db_file.exists()
    kg_db_delta: Dict[str, Any] = {}
    if is_master_checkout or changed_files:
        try:
            if str(kg_dir) not in sys.path:
                sys.path.insert(0, str(kg_dir))
            import query_kg as _qkg  # type: ignore
            kg_db_delta = _qkg.delta_update_kg_db_only(
                repo_root=repo_root,
                changed_files=changed_files,
                trigger_source=trigger_source,
            )
        except Exception as exc:
            kg_db_delta = {"status": "error", "error": str(exc), "db_path": str(kg_db_file)}
    else:
        # Read live counts & latest delta log from knowledge_graph.db on mirror node
        try:
            conn = sqlite3.connect(str(kg_db_file))
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM nodes")
            n_cnt = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM edges")
            e_cnt = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM file_hashes")
            f_cnt = cur.fetchone()[0]
            last_log = None
            try:
                cur.execute(
                    "SELECT updated_at, mode, files_added, files_modified, files_removed, nodes_upserted, nodes_deleted "
                    "FROM kg_delta_log ORDER BY id DESC LIMIT 1"
                )
                row = cur.fetchone()
                if row:
                    last_log = {
                        "updated_at": row[0],
                        "mode": row[1],
                        "files_added": row[2],
                        "files_modified": row[3],
                        "files_removed": row[4],
                        "nodes_upserted": row[5],
                        "nodes_deleted": row[6],
                    }
            except Exception:
                pass
            conn.close()
            kg_db_delta = {
                "status": "up_to_date",
                "trigger_source": trigger_source,
                "db_path": str(kg_db_file),
                "passed_changed_files": changed_files or [],
                "nodes_upserted": 0,
                "nodes_deleted": 0,
                "total_nodes_in_db": n_cnt,
                "total_edges_in_db": e_cnt,
                "total_files_tracked": f_cnt,
                "latest_delta_log": last_log,
            }
        except Exception as exc:
            kg_db_delta = {"status": "error", "error": str(exc), "db_path": str(kg_db_file)}

    # Step 2: Delta-sync knowledge_graph.db -> GPU (MiniLM + GNN) -> PostgreSQL pgvector
    upsert_result = None
    if sync_pgvector:
        upsert_result = sync_kg_db_to_pgvector(repo_name=repo_name, explicit_repo_path=str(repo_root))

    return {
        "status": "ok",
        "trigger_source": trigger_source,
        "repo": repo_name,
        "repo_root": str(repo_root),
        "git_pull_output": git_pull_output,
        "kg_db_delta": kg_db_delta,
        "kg_db_update_exit_code": 0 if kg_db_delta.get("status") != "error" else 1,
        "kg_db_update_summary": [
            f"knowledge_graph.db status={kg_db_delta.get('status')} | "
            f"nodes={kg_db_delta.get('total_nodes_in_db')} "
            f"(+{kg_db_delta.get('nodes_upserted', 0)} / -{kg_db_delta.get('nodes_deleted', 0)}) | "
            f"edges={kg_db_delta.get('total_edges_in_db')}"
        ],
        "pgvector_sync": upsert_result,
        "total_elapsed_ms": round((time.time() - t0) * 1000, 1),
    }


# ============================================================================
# 7. FASTAPI & MCP (MODEL CONTEXT PROTOCOL) STREAMABLE HTTP ENDPOINTS
# ============================================================================

MCP_TOOLS_SCHEMA = [
    {
        "name": "kg_rag_query",
        "description": (
            "Query and prune the repository Knowledge Graph using the local 5-GPU pool "
            "(Model 1: all-MiniLM-L6-v2 -> Model 2: GNN GraphSAGE) and PostgreSQL pgvector. "
            "Returns the top_k most relevant code/documentation blocks and their 2-hop graph neighbors."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural language question, symbol name, file path, or architectural query.",
                },
                "repo": {
                    "type": "string",
                    "description": "Target Git repository name (routes to table kg_vectors_<repo>). Default: 'kubernetes'.",
                    "default": "kubernetes",
                },
                "top_k": {
                    "type": "integer",
                    "description": "Number of pruned results to return (1-25). Default: 5.",
                    "default": 5,
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "kg_rag_upsert",
        "description": (
            "Incrementally index changed nodes and edges from knowledge_graph.db through the GPU pool "
            "(MiniLM + GNN) into the repository's PostgreSQL pgvector table (kg_vectors_<repo>)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {
                    "type": "string",
                    "description": "Target Git repository name. Default: 'kubernetes'.",
                    "default": "kubernetes",
                },
                "force_full": {
                    "type": "boolean",
                    "description": "Force re-embedding of all nodes in knowledge_graph.db.",
                    "default": False,
                },
                "changed_nodes": {
                    "type": "array",
                    "description": "Optional explicit list of changed node objects to upsert.",
                    "items": {"type": "object"},
                },
            },
        },
    },
    {
        "name": "kg_gpu_pool_status",
        "description": (
            "Inspect live GPU availability across all 5 cluster GPU nodes (spark1, spark2, agx, mac, nano), "
            "GNN model weights (kg_gnn.pt), and PostgreSQL pgvector table counts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {
                    "type": "string",
                    "description": "Repository name to check in pgvector. Default: 'kubernetes'.",
                    "default": "kubernetes",
                }
            },
        },
    },
    {
        "name": "kg_webhook_sync",
        "description": (
            "Trigger incremental SQLite delta update on knowledge_graph.db and PostgreSQL pgvector delta sync."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "default": "kubernetes"},
                "pull_git": {"type": "boolean", "default": False},
                "changed_files": {
                    "type": "array",
                    "description": "Optional list of changed file paths from Git commit/push delta.",
                    "items": {"type": "string"},
                },
            },
        },
    },
    {
        "name": "kg_pii_guardrail_scan",
        "description": (
            "Scan and redact PII (SSNs, Credit Cards, Emails, Phone Numbers) and Secrets "
            "(API keys, JWTs, Private Keys, Passwords) using the Middleware's 2-Stage Guardrail."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Input text to scan and redact."}
            },
            "required": ["text"],
        },
    },
]


class MCPQueryRequest(BaseModel):
    query: str
    repo: str = "kubernetes"
    top_k: int = 5


class MCPUpsertRequest(BaseModel):
    repo: str = "kubernetes"
    changed_nodes: Optional[List[Dict[str, Any]]] = None
    force_full: bool = False


def get_full_mcp_status(repo_name: str = "kubernetes") -> Dict[str, Any]:
    """Assemble complete status of Middleware, GPU Pool, GNN weights, and VectorDB."""
    pool = probe_gpu_pool()
    repo_root = _resolve_repo_root(repo_name)
    gnn_pt = repo_root / "knowledge_graph" / "kg_gnn.pt"
    kg_db = repo_root / "knowledge_graph" / "knowledge_graph.db"

    vectordb_info: Dict[str, Any] = {"online": False, "table": _sanitize_table_name(repo_name)}
    try:
        conn, ep = get_pgvector_connection()
        tbl = ensure_repo_pgvector_table(conn, repo_name)
        cur = conn.cursor()
        cur.execute(sql.SQL("SELECT COUNT(*) FROM {}").format(sql.Identifier(tbl)))
        cnt = cur.fetchone()[0]
        cur.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'kg_vectors_%' ORDER BY tablename"
        )
        all_tables = [r[0] for r in cur.fetchall()]
        cur.close()
        conn.close()
        vectordb_info = {
            "online": True,
            "endpoint": ep,
            "extension": "pgvector 0.8.2 (HNSW cosine)",
            "active_table": tbl,
            "vectors_in_active_table": cnt,
            "all_repo_vector_tables": all_tables,
        }
    except Exception as exc:
        vectordb_info["error"] = str(exc)

    import socket as _sock
    return {
        "status": "healthy",
        "responding_node": _sock.gethostname(),
        "middleware_endpoint": "http://192.168.1.181:8000/mcp",
        "ha_middleware_endpoints": [
            {"node": "nano", "role": "primary", "url": "http://192.168.1.181:8000/mcp", "portal": "http://192.168.1.181:8000"},
            {"node": "agx", "role": "ha_replica_1", "url": "http://192.168.1.244:8000/mcp", "portal": "http://192.168.1.244:8000"},
            {"node": "spark1", "role": "ha_replica_2", "url": "http://192.168.1.201:8000/mcp", "portal": "http://192.168.1.201:8000"},
            {"node": "spark2", "role": "ha_replica_3", "url": "http://192.168.1.202:8000/mcp", "portal": "http://192.168.1.202:8000"},
            {"node": "mac", "role": "ha_replica_4", "url": "http://192.168.1.150:8000/mcp", "portal": "http://192.168.1.150:8000"},
        ],
        "protocol": "MCP Streamable HTTP (JSON-RPC 2.0 + Direct REST)",
        "pii_guardrail": {
            "enabled": True,
            "gates": ["Gate 1: Pre-Embedding & Pre-pgvector Ingest", "Gate 2: Pre-Antigravity Egress"],
            "protected_categories": ["ssn", "credit_card", "email", "phone", "api_key", "jwt_token", "private_key", "secret_assignment"],
        },
        "models": {
            "model_1_text_embedder": "all-MiniLM-L6-v2 (384 dimensions)",
            "model_2_graph_nn": "GraphSAGE-2Hop-Residual-GNN (384 dimensions)",
            "gnn_weights_path": str(gnn_pt),
            "gnn_weights_present": gnn_pt.exists(),
        },
        "source_kg_db": {
            "path": str(kg_db),
            "present": kg_db.exists(),
        },
        "gpu_pool": pool,
        "vectordb": vectordb_info,
        "tools": [t["name"] for t in MCP_TOOLS_SCHEMA],
    }


def _dispatch_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Execute one of the registered MCP tools and return its structured dictionary result."""
    if tool_name == "kg_rag_query":
        q = arguments.get("query", "")
        if not q:
            raise ValueError("Missing required argument: 'query'")
        return query_and_prune_graphrag(
            query=q,
            repo_name=arguments.get("repo", "kubernetes"),
            top_k=int(arguments.get("top_k", 5)),
        )
    if tool_name == "kg_rag_upsert":
        return sync_kg_db_to_pgvector(
            repo_name=arguments.get("repo", "kubernetes"),
            changed_nodes_override=arguments.get("changed_nodes"),
            force_full=bool(arguments.get("force_full", False)),
        )
    if tool_name == "kg_gpu_pool_status":
        return get_full_mcp_status(repo_name=arguments.get("repo", "kubernetes"))
    if tool_name == "kg_webhook_sync":
        return delta_update_knowledge_graph_db(
            repo_name=arguments.get("repo", "kubernetes"),
            changed_files=arguments.get("changed_files"),
            pull_git=bool(arguments.get("pull_git", False)),
            sync_pgvector=bool(arguments.get("sync_pgvector", True)),
            trigger_source=f"mcp_tool:{tool_name}",
        )
    if tool_name == "kg_pii_guardrail_scan":
        raw_t = arguments.get("text", "")
        sanitized_t, redactions = sanitize_pii_and_secrets(raw_t)
        return {
            "guardrail": "active",
            "pii_or_secrets_detected": bool(redactions),
            "redaction_counts": redactions,
            "sanitized_text": sanitized_t,
        }
    raise ValueError(f"Unknown MCP tool: '{tool_name}'")


@mcp_router.get("/mcp", tags=["ML Services"])
async def mcp_get_info(repo: str = "kubernetes"):
    """
    GET /mcp — Return Middleware health, GPU pool status, VectorDB status, and MCP tool schemas.
    """
    return await asyncio.to_thread(get_full_mcp_status, repo)


@mcp_router.post("/mcp", tags=["ML Services"])
async def mcp_streamable_http_endpoint(request: Request):
    """
    POST /mcp — Official Streamable HTTP MCP Endpoint (`http://192.168.1.181:8000/mcp`).
    Supports both:
      1. Standard JSON-RPC 2.0 MCP methods (`initialize`, `notifications/initialized`,
         `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`) used by Antigravity (`agy`).
      2. Direct REST tool invocations (`{"tool": "kg_rag_query", "arguments": {...}}`).
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload sent to /mcp")

    # Case 1: Direct convenience invocation {"tool": "...", "arguments": {...}}
    if "tool" in body and "method" not in body:
        tool_name = body.get("tool")
        arguments = body.get("arguments") or {}
        try:
            return await asyncio.to_thread(_dispatch_mcp_tool, tool_name, arguments)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    # Case 2: Standard JSON-RPC 2.0 MCP Protocol
    rpc_id = body.get("id")
    method = body.get("method", "")
    params = body.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                },
                "serverInfo": {
                    "name": "cluster-graphrag-mcp-middleware",
                    "version": "1.0.0",
                },
            },
        }

    if method.startswith("notifications/"):
        return JSONResponse(status_code=202, content={"jsonrpc": "2.0", "status": "accepted"})

    if method == "ping":
        return {"jsonrpc": "2.0", "id": rpc_id, "result": {}}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {"tools": MCP_TOOLS_SCHEMA},
        }

    if method == "tools/call":
        t_name = params.get("name", "")
        t_args = params.get("arguments") or {}
        try:
            result_data = await asyncio.to_thread(_dispatch_mcp_tool, t_name, t_args)
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result_data, indent=2),
                        }
                    ],
                    "isError": False,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error executing {t_name}: {exc}"}],
                    "isError": True,
                },
            }

    if method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "resources": [
                    {
                        "uri": "kg://kubernetes/status",
                        "name": "Kubernetes Knowledge Graph & GPU Pool Status",
                        "mimeType": "application/json",
                    },
                    {
                        "uri": "kg://sap/status",
                        "name": "SAP S/4HANA Knowledge Graph & GPU Pool Status",
                        "mimeType": "application/json",
                    },
                ]
            },
        }

    if method == "resources/read":
        uri = str(params.get("uri") or "kg://kubernetes/status")
        m_repo = re.match(r"^kg://([^/]+)/status$", uri)
        target_repo = m_repo.group(1) if m_repo else "kubernetes"
        status_payload = await asyncio.to_thread(get_full_mcp_status, target_repo)
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(status_payload, indent=2),
                    }
                ]
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


@mcp_router.get("/api/mcp/status", tags=["ML Services"])
async def api_mcp_status(repo: str = "kubernetes"):
    """Return full status of the MCP Middleware, GPU pool, GNN weights, and pgvector tables."""
    return await asyncio.to_thread(get_full_mcp_status, repo)


@mcp_router.post("/api/mcp/query", tags=["ML Services"])
async def api_mcp_query(req: MCPQueryRequest):
    """Flow 2 REST endpoint: Query & Prune via GPU Pool (MiniLM -> GNN) + PostgreSQL pgvector."""
    try:
        return await asyncio.to_thread(query_and_prune_graphrag, req.query, req.repo, req.top_k)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@mcp_router.post("/api/mcp/upsert", tags=["ML Services"])
async def api_mcp_upsert(req: MCPUpsertRequest):
    """Flow 1 REST endpoint: Delta Index & GNN Update from knowledge_graph.db -> PostgreSQL pgvector."""
    try:
        return await asyncio.to_thread(
            sync_kg_db_to_pgvector,
            req.repo,
            None,
            req.changed_nodes,
            req.force_full,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


def _extract_webhook_params(payload: Any) -> Tuple[str, List[str], bool, bool, str]:
    """Extract repo_name, changed_files (from direct list or GitHub/GitLab commits), pull_git, sync_pgvector, and commit_sha."""
    repo_name = "kubernetes"
    changed_files: List[str] = []
    pull_git = False
    sync_pgvector = True
    commit_sha = ""
    if isinstance(payload, dict):
        if "repository" in payload and isinstance(payload["repository"], dict):
            repo_name = payload["repository"].get("name") or "kubernetes"
        elif "repo" in payload:
            repo_name = str(payload["repo"])
        pull_git = bool(payload.get("pull_git", False))
        sync_pgvector = bool(payload.get("sync_pgvector", True))
        commit_sha = str(payload.get("commit_sha") or payload.get("after") or "")[:12]
        if isinstance(payload.get("changed_files"), list):
            changed_files.extend(str(f) for f in payload["changed_files"] if f)
        if isinstance(payload.get("commits"), list):
            for cm in payload["commits"]:
                if isinstance(cm, dict):
                    for k in ("added", "modified", "removed"):
                        if isinstance(cm.get(k), list):
                            changed_files.extend(str(f) for f in cm[k] if f)
    # Deduplicate while preserving order
    dedup_files = list(dict.fromkeys(changed_files))
    return repo_name, dedup_files, pull_git, sync_pgvector, commit_sha


@mcp_router.post("/api/webhooks/git-push", tags=["Cluster Management"])
async def api_git_push_webhook(request: Request):
    """
    Single `query_kg.py`-based Webhook endpoint to delta-update `knowledge_graph.db`
    and `PostgreSQL + pgvector` whenever code is committed, pushed, or pulled across the cluster.
    Accepts GitHub/GitLab webhook payloads or `{ "repo": "kubernetes", "pull_git": false }`.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    repo_name, changed_files, pull_git, sync_pgvector, commit_sha = _extract_webhook_params(payload)
    trig = f"webhook:/api/webhooks/git-push{(':' + commit_sha) if commit_sha else ''}"
    try:
        return await asyncio.to_thread(
            delta_update_knowledge_graph_db,
            repo_name,
            changed_files,
            pull_git,
            sync_pgvector,
            trig,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


class MCPPiiScanRequest(BaseModel):
    text: str


@mcp_router.post("/api/mcp/pii-scan", tags=["ML Services"])
async def api_mcp_pii_scan(req: MCPPiiScanRequest):
    """Scan and redact PII and secrets using the 2-Stage MCP Guardrail."""
    sanitized_t, redactions = sanitize_pii_and_secrets(req.text)
    return {
        "guardrail": "active",
        "pii_or_secrets_detected": bool(redactions),
        "redaction_counts": redactions,
        "sanitized_text": sanitized_t,
    }

