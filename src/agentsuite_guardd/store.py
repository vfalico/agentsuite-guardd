from __future__ import annotations
import json, sqlite3, threading, time


class Conflict(Exception):
    pass


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.lock = threading.RLock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS operations ("
            "id TEXT PRIMARY KEY, "
            "request_digest TEXT NOT NULL, "
            "state TEXT NOT NULL, "
            "value TEXT NOT NULL, "
            "updated REAL NOT NULL)"
        )

    def reserve(self, operation_id: str, request_digest: str, value: dict) -> dict:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        now = time.time()
        with self.lock:
            row = self.db.execute(
                "SELECT request_digest,value FROM operations WHERE id=?",
                (operation_id,),
            ).fetchone()
            if row:
                if row[0] != request_digest:
                    raise Conflict("idempotency identity conflict")
                return json.loads(row[1])
            self.db.execute(
                "INSERT INTO operations VALUES (?,?,?,?,?)",
                (operation_id, request_digest, "reserved", encoded, now),
            )
            return value

    def transition(
        self,
        operation_id: str,
        request_digest: str,
        expected: str,
        new: str,
        value: dict,
    ) -> dict:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        now = time.time()
        with self.lock:
            row = self.db.execute(
                "SELECT request_digest,state,value FROM operations WHERE id=?",
                (operation_id,),
            ).fetchone()
            if not row:
                raise Conflict("operation not reserved")
            if row[0] != request_digest:
                raise Conflict("request digest conflict")
            if row[1] == new:
                return json.loads(row[2])
            if row[1] != expected:
                raise Conflict(f"state conflict: {row[1]}")
            cur = self.db.execute(
                "UPDATE operations SET state=?,value=?,updated=? WHERE id=? AND state=?",
                (new, encoded, now, operation_id, expected),
            )
            if cur.rowcount != 1:
                raise Conflict("concurrent state conflict")
            return value

    def get(self, operation_id: str) -> tuple[str, dict]:
        row = self.db.execute(
            "SELECT state,value FROM operations WHERE id=?", (operation_id,)
        ).fetchone()
        if not row:
            raise KeyError(operation_id)
        return row[0], json.loads(row[1])

    def list_ids(self, prefix: str = "") -> tuple[str, ...]:
        rows = self.db.execute(
            "SELECT id FROM operations WHERE id LIKE ? ORDER BY id", (prefix + "%",)
        ).fetchall()
        return tuple(r[0] for r in rows)

    def close(self):
        self.db.close()
