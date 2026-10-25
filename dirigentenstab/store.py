import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet


class Store:
    def __init__(self, database: str, key_file: str):
        self.path = Path(database)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.cipher = Fernet(Path(key_file).read_bytes().strip())
        with self.connect() as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            version = conn.execute('PRAGMA user_version').fetchone()[0]
            for migration in sorted((Path(__file__).parent / 'migrations').glob('*.sql')):
                number = int(migration.stem)
                if number > version:
                    conn.executescript('BEGIN IMMEDIATE;\n' + migration.read_text()
                                       + f'\nPRAGMA user_version={number};\nCOMMIT;')
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def all(self, sql, args=()):
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(sql, args)]

    def one(self, sql, args=()):
        rows = self.all(sql, args)
        return rows[0] if rows else None

    def execute(self, sql, args=()):
        with self.connect() as conn:
            return conn.execute(sql, args).rowcount

    def seal(self, value):
        return self.cipher.encrypt(json.dumps(value).encode())

    def open(self, value):
        return json.loads(self.cipher.decrypt(value))

    def audit(self, actor, operation, target='', status='ok'):
        self.execute('INSERT INTO audit(created,actor,operation,target,status) VALUES(?,?,?,?,?)',
                     (time.time(), actor, operation, target, status))
