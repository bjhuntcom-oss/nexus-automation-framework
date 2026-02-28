"""
Nexus Automation Framework - Database Manager

High-performance SQLite database manager with:
- Connection pooling (thread-safe)
- WAL journal mode for concurrent reads/writes
- Auto-VACUUM and checkpoint management
- Query builder with parameterized queries
- Schema migration system
- Performance monitoring
- Corruption detection and recovery
"""

import sqlite3
import threading
import time
import logging
import hashlib
import json
import os
from queue import Queue, Empty
from typing import Optional, Dict, Any, List, Tuple, Union
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from nexus_framework.config import database_config, LOGS_DIR
from nexus_framework.exceptions import (
    DatabaseConnectionError, DatabaseCorruptedError, QueryError
)

logger = logging.getLogger("nexus_db")


# ══════════════════════════════════════════════════════════════════════════════
# SCHEMA MIGRATIONS
# ══════════════════════════════════════════════════════════════════════════════

SCHEMA_VERSION = 3

MIGRATIONS: Dict[int, List[str]] = {
    1: [
        # Core knowledge tables
        """CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now')),
            description TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id TEXT PRIMARY KEY,
            description TEXT NOT NULL DEFAULT '',
            severity REAL NOT NULL DEFAULT 0.0,
            cvss_score REAL NOT NULL DEFAULT 0.0,
            cvss_vector TEXT NOT NULL DEFAULT '',
            published_date TEXT NOT NULL DEFAULT '',
            modified_date TEXT NOT NULL DEFAULT '',
            affected_products TEXT NOT NULL DEFAULT '[]',
            references_json TEXT NOT NULL DEFAULT '[]',
            required_privileges TEXT NOT NULL DEFAULT '',
            user_interaction INTEGER NOT NULL DEFAULT 0,
            scope_changed INTEGER NOT NULL DEFAULT 0,
            confidentiality_impact TEXT NOT NULL DEFAULT '',
            integrity_impact TEXT NOT NULL DEFAULT '',
            availability_impact TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""",
        """CREATE TABLE IF NOT EXISTS attack_techniques (
            technique_id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            phase TEXT NOT NULL DEFAULT '',
            platforms TEXT NOT NULL DEFAULT '[]',
            required_permissions TEXT NOT NULL DEFAULT '[]',
            data_sources TEXT NOT NULL DEFAULT '[]',
            mitigations TEXT NOT NULL DEFAULT '[]',
            effectiveness_score REAL NOT NULL DEFAULT 0.5,
            detection_difficulty TEXT NOT NULL DEFAULT '',
            tool_requirements TEXT NOT NULL DEFAULT '[]',
            sub_techniques TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""",
        """CREATE TABLE IF NOT EXISTS service_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT NOT NULL DEFAULT '',
            service_version TEXT NOT NULL DEFAULT '',
            port INTEGER,
            protocol TEXT NOT NULL DEFAULT 'tcp',
            cve_ids TEXT NOT NULL DEFAULT '[]',
            default_credentials TEXT NOT NULL DEFAULT '[]',
            common_misconfigurations TEXT NOT NULL DEFAULT '[]',
            exploitation_methods TEXT NOT NULL DEFAULT '[]',
            detection_signatures TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(service_name, service_version, port)
        )""",
        """CREATE TABLE IF NOT EXISTS exploit_patterns (
            pattern_id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            vulnerability_type TEXT NOT NULL DEFAULT '',
            exploitation_method TEXT NOT NULL DEFAULT '',
            required_conditions TEXT NOT NULL DEFAULT '[]',
            success_indicators TEXT NOT NULL DEFAULT '[]',
            side_effects TEXT NOT NULL DEFAULT '[]',
            detection_signatures TEXT NOT NULL DEFAULT '[]',
            mitigation_techniques TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""",
        """CREATE TABLE IF NOT EXISTS evasion_patterns (
            pattern_id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            evasion_technique TEXT NOT NULL DEFAULT '',
            target_defenses TEXT NOT NULL DEFAULT '[]',
            implementation_methods TEXT NOT NULL DEFAULT '[]',
            detection_bypasses TEXT NOT NULL DEFAULT '[]',
            effectiveness_score REAL NOT NULL DEFAULT 0.5,
            countermeasures TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""",
        """CREATE TABLE IF NOT EXISTS workflow_rules (
            rule_id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            trigger_conditions TEXT NOT NULL DEFAULT '{}',
            actions TEXT NOT NULL DEFAULT '[]',
            priority INTEGER NOT NULL DEFAULT 50,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""",
    ],
    2: [
        # Indexes for performance
        "CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity)",
        "CREATE INDEX IF NOT EXISTS idx_cve_score ON cve_entries(cvss_score)",
        "CREATE INDEX IF NOT EXISTS idx_cve_published ON cve_entries(published_date)",
        "CREATE INDEX IF NOT EXISTS idx_cve_products ON cve_entries(affected_products)",
        "CREATE INDEX IF NOT EXISTS idx_attack_phase ON attack_techniques(phase)",
        "CREATE INDEX IF NOT EXISTS idx_attack_effectiveness ON attack_techniques(effectiveness_score)",
        "CREATE INDEX IF NOT EXISTS idx_service_name ON service_vulnerabilities(service_name)",
        "CREATE INDEX IF NOT EXISTS idx_service_port ON service_vulnerabilities(port)",
        "CREATE INDEX IF NOT EXISTS idx_exploit_type ON exploit_patterns(vulnerability_type)",
        "CREATE INDEX IF NOT EXISTS idx_evasion_effectiveness ON evasion_patterns(effectiveness_score)",
        "CREATE INDEX IF NOT EXISTS idx_workflow_priority ON workflow_rules(priority)",
        "CREATE INDEX IF NOT EXISTS idx_workflow_enabled ON workflow_rules(enabled)",
        # Full text search
        """CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(
            cve_id, description, affected_products,
            content='cve_entries',
            content_rowid='rowid'
        )""",
        """CREATE VIRTUAL TABLE IF NOT EXISTS technique_fts USING fts5(
            technique_id, name, description,
            content='attack_techniques',
            content_rowid='rowid'
        )""",
    ],
    3: [
        # Payloads table
        """CREATE TABLE IF NOT EXISTS payloads (
            payload_id TEXT PRIMARY KEY,
            category TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL DEFAULT '',
            content TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            target_tech TEXT NOT NULL DEFAULT 'generic',
            tags TEXT NOT NULL DEFAULT '[]',
            waf_bypass INTEGER NOT NULL DEFAULT 0,
            encoding TEXT NOT NULL DEFAULT 'none',
            severity TEXT NOT NULL DEFAULT 'medium',
            source TEXT NOT NULL DEFAULT '',
            success_indicator TEXT NOT NULL DEFAULT '',
            context TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )""",
        "CREATE INDEX IF NOT EXISTS idx_payload_category ON payloads(category)",
        "CREATE INDEX IF NOT EXISTS idx_payload_tech ON payloads(target_tech)",
        "CREATE INDEX IF NOT EXISTS idx_payload_severity ON payloads(severity)",
        # Security audit log
        """CREATE TABLE IF NOT EXISTS security_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            event_type TEXT NOT NULL DEFAULT '',
            threat_level TEXT NOT NULL DEFAULT 'info',
            source TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            action_taken TEXT NOT NULL DEFAULT '',
            details_json TEXT NOT NULL DEFAULT '{}',
            event_hash TEXT NOT NULL DEFAULT '',
            prev_hash TEXT NOT NULL DEFAULT ''
        )""",
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON security_audit_log(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_audit_type ON security_audit_log(event_type)",
        "CREATE INDEX IF NOT EXISTS idx_audit_threat ON security_audit_log(threat_level)",
        # Operations table
        """CREATE TABLE IF NOT EXISTS operations (
            operation_id TEXT PRIMARY KEY,
            target_scope TEXT NOT NULL DEFAULT '[]',
            objectives TEXT NOT NULL DEFAULT '[]',
            current_state TEXT NOT NULL DEFAULT 'reconnaissance',
            stealth_requirement REAL NOT NULL DEFAULT 0.5,
            risk_tolerance REAL NOT NULL DEFAULT 0.5,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            completed_at TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        )""",
        # Findings table
        """CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_id TEXT,
            finding_type TEXT NOT NULL DEFAULT '',
            severity REAL NOT NULL DEFAULT 0.0,
            confidence REAL NOT NULL DEFAULT 0.5,
            target TEXT NOT NULL DEFAULT '',
            tool_name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            raw_output TEXT NOT NULL DEFAULT '',
            evidence TEXT NOT NULL DEFAULT '',
            remediation TEXT NOT NULL DEFAULT '',
            cve_ids TEXT NOT NULL DEFAULT '[]',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (operation_id) REFERENCES operations(operation_id)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_findings_op ON findings(operation_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
        "CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type)",
        "CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)",
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
# CONNECTION POOL
# ══════════════════════════════════════════════════════════════════════════════

class ConnectionPool:
    """Thread-safe SQLite connection pool."""

    def __init__(self, db_path: str, pool_size: int = 5, max_overflow: int = 10):
        self.db_path = db_path
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self._pool: Queue = Queue(maxsize=pool_size + max_overflow)
        self._created = 0
        self._lock = threading.Lock()
        self._stats = {"acquired": 0, "released": 0, "created": 0, "errors": 0}

        # Pre-create connections
        for _ in range(pool_size):
            conn = self._create_connection()
            self._pool.put(conn)

    def _create_connection(self) -> sqlite3.Connection:
        """Create a new optimized SQLite connection."""
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=database_config.timeout,
                check_same_thread=False,
                isolation_level=None,  # autocommit mode for WAL
            )
            conn.row_factory = sqlite3.Row

            # Performance pragmas
            conn.execute(f"PRAGMA journal_mode={database_config.journal_mode}")
            conn.execute(f"PRAGMA synchronous={database_config.synchronous}")
            conn.execute(f"PRAGMA cache_size={database_config.cache_size}")
            conn.execute(f"PRAGMA mmap_size={database_config.mmap_size}")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")

            with self._lock:
                self._created += 1
                self._stats["created"] += 1

            return conn
        except sqlite3.Error as e:
            self._stats["errors"] += 1
            raise DatabaseConnectionError(self.db_path, cause=e)

    def acquire(self, timeout: float = 10.0) -> sqlite3.Connection:
        """Acquire a connection from the pool."""
        try:
            conn = self._pool.get(timeout=timeout)
            self._stats["acquired"] += 1
            # Validate connection
            try:
                conn.execute("SELECT 1")
            except sqlite3.Error:
                conn = self._create_connection()
            return conn
        except Empty:
            # Pool exhausted, try to create overflow
            with self._lock:
                if self._created < self.pool_size + self.max_overflow:
                    conn = self._create_connection()
                    self._stats["acquired"] += 1
                    return conn
            raise DatabaseConnectionError(
                self.db_path,
                cause=Exception("Connection pool exhausted")
            )

    def release(self, conn: sqlite3.Connection):
        """Release a connection back to the pool."""
        try:
            self._pool.put_nowait(conn)
            self._stats["released"] += 1
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            with self._lock:
                self._created -= 1

    def close_all(self):
        """Close all connections in the pool."""
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except Exception:
                pass
        with self._lock:
            self._created = 0

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "pool_size": self._pool.qsize(), "total_created": self._created}


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class DatabaseManager:
    """
    High-performance database manager with connection pooling,
    migration support, and query helpers.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or database_config.db_path
        self.pool = ConnectionPool(
            self.db_path,
            pool_size=database_config.pool_size,
            max_overflow=database_config.max_overflow,
        )
        self.logger = logging.getLogger("nexus_db")
        self._query_stats: Dict[str, Dict[str, Any]] = {}
        self._initialized = False

    def initialize(self):
        """Initialize database with schema migrations."""
        if self._initialized:
            return
        self._run_migrations()
        self._initialized = True
        self.logger.info(f"Database initialized at {self.db_path}")

    @contextmanager
    def connection(self):
        """Context manager for database connections."""
        conn = self.pool.acquire()
        try:
            yield conn
        except sqlite3.Error as e:
            self.logger.error(f"Database error: {e}")
            raise QueryError(error=str(e))
        finally:
            self.pool.release(conn)

    @contextmanager
    def transaction(self):
        """Context manager for database transactions."""
        conn = self.pool.acquire()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception as e:
            conn.execute("ROLLBACK")
            raise
        finally:
            self.pool.release(conn)

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a single query."""
        start = time.monotonic()
        with self.connection() as conn:
            try:
                cursor = conn.execute(query, params)
                elapsed = (time.monotonic() - start) * 1000
                self._track_query(query, elapsed, True)
                return cursor
            except sqlite3.Error as e:
                elapsed = (time.monotonic() - start) * 1000
                self._track_query(query, elapsed, False)
                raise QueryError(query=query[:200], error=str(e))

    def execute_many(self, query: str, params_list: List[tuple]) -> int:
        """Execute a query with multiple parameter sets."""
        with self.transaction() as conn:
            try:
                conn.executemany(query, params_list)
                return len(params_list)
            except sqlite3.Error as e:
                raise QueryError(query=query[:200], error=str(e))

    def fetch_one(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        """Fetch a single row."""
        with self.connection() as conn:
            row = conn.execute(query, params).fetchone()
            return dict(row) if row else None

    def fetch_all(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Fetch all rows."""
        with self.connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def fetch_count(self, table: str, where: str = "", params: tuple = ()) -> int:
        """Count rows in a table."""
        query = f"SELECT COUNT(*) as cnt FROM {table}"
        if where:
            query += f" WHERE {where}"
        result = self.fetch_one(query, params)
        return result["cnt"] if result else 0

    def insert(self, table: str, data: Dict[str, Any]) -> int:
        """Insert a row and return rowid."""
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        query = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
        with self.transaction() as conn:
            cursor = conn.execute(query, tuple(data.values()))
            return cursor.lastrowid

    def upsert(self, table: str, data: Dict[str, Any], conflict_columns: List[str]) -> int:
        """Insert or update on conflict."""
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        conflict = ", ".join(conflict_columns)
        update_cols = ", ".join(
            f"{k}=excluded.{k}" for k in data.keys() if k not in conflict_columns
        )
        query = (
            f"INSERT INTO {table} ({columns}) VALUES ({placeholders}) "
            f"ON CONFLICT({conflict}) DO UPDATE SET {update_cols}"
        )
        with self.transaction() as conn:
            cursor = conn.execute(query, tuple(data.values()))
            return cursor.lastrowid

    def search_fts(self, table: str, query: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Full-text search on an FTS5 table."""
        try:
            sql = f"SELECT * FROM {table} WHERE {table} MATCH ? LIMIT ?"
            return self.fetch_all(sql, (query, limit))
        except sqlite3.Error:
            # FTS table may not exist; fall back
            return []

    def vacuum(self):
        """Run VACUUM to reclaim space."""
        with self.connection() as conn:
            conn.execute("VACUUM")
        self.logger.info("Database VACUUM completed")

    def checkpoint(self):
        """Run WAL checkpoint."""
        with self.connection() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.logger.info("WAL checkpoint completed")

    def integrity_check(self) -> bool:
        """Run integrity check on the database."""
        result = self.fetch_one("PRAGMA integrity_check")
        ok = result and result.get("integrity_check") == "ok"
        if not ok:
            self.logger.error(f"Database integrity check FAILED: {result}")
        return ok

    def get_db_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        try:
            page_count = self.fetch_one("PRAGMA page_count")
            page_size = self.fetch_one("PRAGMA page_size")
            freelist = self.fetch_one("PRAGMA freelist_count")
            journal = self.fetch_one("PRAGMA journal_mode")

            tables = self.fetch_all(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            table_counts = {}
            for t in tables:
                name = t["name"]
                if not name.startswith("sqlite_") and not name.endswith("_fts"):
                    count = self.fetch_count(name)
                    table_counts[name] = count

            db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0

            return {
                "db_path": self.db_path,
                "db_size_mb": round(db_size / (1024 * 1024), 2),
                "page_count": page_count.get("page_count", 0) if page_count else 0,
                "page_size": page_size.get("page_size", 0) if page_size else 0,
                "freelist_pages": freelist.get("freelist_count", 0) if freelist else 0,
                "journal_mode": journal.get("journal_mode", "") if journal else "",
                "tables": table_counts,
                "total_rows": sum(table_counts.values()),
                "pool_stats": self.pool.get_stats(),
                "query_stats": dict(self._query_stats),
            }
        except Exception as e:
            return {"error": str(e)}

    def _run_migrations(self):
        """Run pending database migrations."""
        with self.transaction() as conn:
            # Ensure schema_version table exists
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL DEFAULT (datetime('now')),
                    description TEXT
                )
            """)

            # Get current version
            row = conn.execute("SELECT MAX(version) as v FROM schema_version").fetchone()
            current_version = row["v"] if row and row["v"] else 0

            # Apply pending migrations
            for version in sorted(MIGRATIONS.keys()):
                if version > current_version:
                    self.logger.info(f"Applying migration v{version}...")
                    for sql in MIGRATIONS[version]:
                        try:
                            conn.execute(sql)
                        except sqlite3.OperationalError as e:
                            if "already exists" not in str(e):
                                self.logger.warning(f"Migration v{version} warning: {e}")
                    conn.execute(
                        "INSERT OR REPLACE INTO schema_version (version, description) VALUES (?, ?)",
                        (version, f"Migration v{version}")
                    )
                    self.logger.info(f"Migration v{version} applied successfully")

    def _track_query(self, query: str, elapsed_ms: float, success: bool):
        """Track query performance statistics."""
        # Normalize query for stats
        key = query.split()[0].upper() if query.strip() else "UNKNOWN"
        if key not in self._query_stats:
            self._query_stats[key] = {
                "count": 0, "errors": 0,
                "total_ms": 0.0, "max_ms": 0.0, "min_ms": float("inf"),
            }
        stats = self._query_stats[key]
        stats["count"] += 1
        stats["total_ms"] += elapsed_ms
        stats["max_ms"] = max(stats["max_ms"], elapsed_ms)
        stats["min_ms"] = min(stats["min_ms"], elapsed_ms)
        if not success:
            stats["errors"] += 1

    def close(self):
        """Close the database manager."""
        self.pool.close_all()
        self.logger.info("Database manager closed")


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL INSTANCE
# ══════════════════════════════════════════════════════════════════════════════

db_manager = DatabaseManager()
