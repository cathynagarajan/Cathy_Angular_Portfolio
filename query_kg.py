#!/usr/bin/env python3
"""Root-level entrypoint that forwards all CLI parameters and switches (including /s, /I, /install) to knowledge_graph/query_kg.py."""

import sys
from pathlib import Path

KG_DIR = Path(__file__).resolve().parent / "knowledge_graph"
sys.path.insert(0, str(KG_DIR))

from query_kg import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
