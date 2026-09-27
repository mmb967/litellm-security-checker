"""Persistence for ontology objects.

Only the action layer imports this module. Agents have no path to it: there
is no "run_sql" or "get_table" tool, and nothing here is exposed as a tool.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Callable, Iterable, TypeVar

import yaml

from warden.ontology.objects import OBJECT_TYPES, OntologyObject

T = TypeVar("T", bound=OntologyObject)


class ObjectStore:
    def __init__(self, path: str | Path = ":memory:"):
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS objects ("
                " type TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,"
                " PRIMARY KEY (type, id))"
            )
            self._conn.commit()

    def put(self, obj: OntologyObject) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO objects (type, id, data) VALUES (?, ?, ?)",
                (obj.TYPE, obj.id, obj.model_dump_json()),
            )
            self._conn.commit()

    def get(self, cls: type[T], obj_id: str) -> T | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM objects WHERE type = ? AND id = ?", (cls.TYPE, obj_id)
            ).fetchone()
        return cls.model_validate_json(row[0]) if row else None

    def list(self, cls: type[T], where: Callable[[T], bool] | None = None) -> list[T]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM objects WHERE type = ? ORDER BY id", (cls.TYPE,)
            ).fetchall()
        objs = [cls.model_validate_json(r[0]) for r in rows]
        return [o for o in objs if where is None or where(o)]

    def next_id(self, cls: type[OntologyObject], prefix: str) -> str:
        with self._lock:
            (n,) = self._conn.execute(
                "SELECT COUNT(*) FROM objects WHERE type = ?", (cls.TYPE,)
            ).fetchone()
        return f"{prefix}-{n + 1:04d}"

    def load_seed(self, path: str | Path) -> None:
        data = yaml.safe_load(Path(path).read_text())
        self.load_records(data)

    def load_records(self, data: dict[str, Iterable[dict]]) -> None:
        for type_name, records in data.items():
            cls = OBJECT_TYPES[type_name]
            for rec in records:
                self.put(cls.model_validate(rec))

    def dump(self) -> dict[str, list[dict]]:
        with self._lock:
            rows = self._conn.execute("SELECT type, data FROM objects ORDER BY type, id").fetchall()
        out: dict[str, list[dict]] = {}
        for t, d in rows:
            out.setdefault(t, []).append(json.loads(d))
        return out
