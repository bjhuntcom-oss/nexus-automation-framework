"""
CVE Advisor - Vulnerability Intelligence Engine
===============================================

Provides structured CVE queries against the local knowledge.db SQLite database.
Designed to operate with or without the database present: every public method
returns a safe, typed result even when the DB is unavailable.

Environment variables:
    KNOWLEDGE_DB_PATH   Path to knowledge.db (default: "knowledge.db")

Schema expected (created by nexus_framework.strategic.knowledge.KnowledgeDatabase):
    cve_entries          -- main CVE table
    service_vulnerabilities -- service-to-CVE mapping table

Thread safety:
    Uses threading.local() to maintain a per-thread SQLite connection,
    combined with check_same_thread=False for explicit multi-thread usage.
"""

import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data Transfer Objects
# ---------------------------------------------------------------------------

@dataclass
class CVEResult:
    """Flattened CVE record returned by all advisor methods."""

    cve_id: str
    description: str
    cvss_score: float
    severity: str                          # CRITICAL / HIGH / MEDIUM / LOW / NONE
    exploit_available: bool
    exploit_complexity: str
    published_date: str
    affected_products: List[str] = field(default_factory=list)
    confidentiality_impact: str = ""
    integrity_impact: str = ""
    availability_impact: str = ""
    required_privileges: str = ""
    cvss_vector: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to plain dict for JSON responses."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "exploit_available": self.exploit_available,
            "exploit_complexity": self.exploit_complexity,
            "published_date": self.published_date,
            "affected_products": self.affected_products,
            "confidentiality_impact": self.confidentiality_impact,
            "integrity_impact": self.integrity_impact,
            "availability_impact": self.availability_impact,
            "required_privileges": self.required_privileges,
            "cvss_vector": self.cvss_vector,
        }


@dataclass
class AttackSurfaceReport:
    """Result of score_attack_surface()."""

    overall_score: float                   # 0.0 – 10.0
    risk_label: str                        # Critical / High / Medium / Low
    total_cves: int
    exploitable_cves: int
    per_service: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    top_cves: List[CVEResult] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_score": round(self.overall_score, 2),
            "risk_label": self.risk_label,
            "total_cves": self.total_cves,
            "exploitable_cves": self.exploitable_cves,
            "per_service": self.per_service,
            "top_cves": [c.to_dict() for c in self.top_cves],
            "recommendations": self.recommendations,
        }


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: float) -> str:
    """Convert a CVSS v3 numeric score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class CVEAdvisor:
    """
    SQLite-backed CVE advisory engine.

    Parameters
    ----------
    db_path : str, optional
        Explicit path to knowledge.db.  Falls back to the ``KNOWLEDGE_DB_PATH``
        environment variable, then to the hardcoded default ``"knowledge.db"``.

    Examples
    --------
    >>> advisor = CVEAdvisor()
    >>> cves = advisor.get_cves_for_service("apache", version="2.4.48")
    >>> report = advisor.score_attack_surface({"apache": "2.4.48", "openssh": "7.4"})
    """

    _DEFAULT_DB = "knowledge.db"

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path: str = (
            db_path
            or os.environ.get("KNOWLEDGE_DB_PATH", self._DEFAULT_DB)
        )
        self._local = threading.local()   # per-thread connection pool
        self._db_available: bool = self._probe_db()

        if not self._db_available:
            logger.warning(
                "CVEAdvisor: database not found at '%s'. "
                "All queries will return empty results.",
                self._db_path,
            )
        else:
            logger.info(
                "CVEAdvisor: connected to knowledge database at '%s'.",
                self._db_path,
            )

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _probe_db(self) -> bool:
        """Return True if the database file exists and is readable."""
        return os.path.isfile(self._db_path)

    def _get_conn(self) -> Optional[sqlite3.Connection]:
        """
        Return a per-thread SQLite connection, creating it on first use.

        Returns None if the database is unavailable.
        """
        if not self._db_available:
            return None
        if not hasattr(self._local, "conn") or self._local.conn is None:
            try:
                self._local.conn = sqlite3.connect(
                    self._db_path,
                    check_same_thread=False,
                    timeout=10,
                )
                self._local.conn.row_factory = sqlite3.Row
                # Optimisations for read-heavy workload
                self._local.conn.execute("PRAGMA journal_mode=WAL;")
                self._local.conn.execute("PRAGMA synchronous=NORMAL;")
                self._local.conn.execute("PRAGMA cache_size=4000;")
            except sqlite3.Error as exc:
                logger.error("CVEAdvisor: failed to open connection: %s", exc)
                self._local.conn = None
        return self._local.conn

    def _execute(
        self,
        sql: str,
        params: Tuple = (),
    ) -> List[sqlite3.Row]:
        """
        Execute a SELECT statement and return all rows.

        Returns an empty list on any error or if the DB is unavailable.
        """
        conn = self._get_conn()
        if conn is None:
            return []
        try:
            cursor = conn.execute(sql, params)
            return cursor.fetchall()
        except sqlite3.Error as exc:
            logger.error("CVEAdvisor query error: %s | SQL: %s", exc, sql)
            return []

    # ------------------------------------------------------------------
    # Row -> CVEResult conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_cve(row: sqlite3.Row) -> CVEResult:
        """Convert a raw ``cve_entries`` row into a ``CVEResult``."""
        raw_products = row["affected_products"] or "[]"
        try:
            products: List[str] = json.loads(raw_products)
        except (json.JSONDecodeError, TypeError):
            products = []

        raw_score = row["cvss_score"] or 0.0
        return CVEResult(
            cve_id=row["cve_id"],
            description=row["description"] or "",
            cvss_score=float(raw_score),
            severity=_cvss_to_severity(float(raw_score)),
            exploit_available=bool(row["exploit_available"]),
            exploit_complexity=row["exploit_complexity"] or "",
            published_date=row["published_date"] or "",
            affected_products=products,
            confidentiality_impact=row["confidentiality_impact"] or "",
            integrity_impact=row["integrity_impact"] or "",
            availability_impact=row["availability_impact"] or "",
            required_privileges=row["required_privileges"] or "",
            cvss_vector=row["cvss_vector"] or "",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_cves_for_service(
        self,
        service_name: str,
        version: Optional[str] = None,
        limit: int = 20,
    ) -> List[CVEResult]:
        """
        Return CVEs affecting *service_name* (optionally filtered by *version*),
        ordered by CVSS score descending.

        The query searches both the ``cve_entries.affected_products`` JSON column
        and the ``service_vulnerabilities`` join table so that CVEs stored via
        either pathway are found.

        Parameters
        ----------
        service_name : str
            Partial or full service name (e.g. "apache", "openssh", "mysql").
        version : str, optional
            Specific version string for tighter matching.
        limit : int
            Maximum number of CVEs to return (default 20).

        Returns
        -------
        List[CVEResult]
            Sorted by CVSS score descending.  Empty list if no results or DB
            is unavailable.
        """
        if not service_name:
            return []

        service_pattern = f"%{service_name.lower()}%"

        # --- Strategy 1: search cve_entries.affected_products directly ---
        rows_direct = self._execute(
            """
            SELECT DISTINCT c.*
            FROM   cve_entries c
            WHERE  LOWER(c.affected_products) LIKE ?
            ORDER  BY c.cvss_score DESC
            LIMIT  ?
            """,
            (service_pattern, limit),
        )

        # --- Strategy 2: join through service_vulnerabilities ---
        if version:
            rows_svc = self._execute(
                """
                SELECT DISTINCT c.*
                FROM   cve_entries c
                JOIN   service_vulnerabilities sv
                       ON LOWER(sv.cve_refs) LIKE '%' || c.cve_id || '%'
                WHERE  LOWER(sv.service_name) LIKE ?
                  AND  LOWER(sv.version_pattern) LIKE '%' || LOWER(?) || '%'
                ORDER  BY c.cvss_score DESC
                LIMIT  ?
                """,
                (service_pattern, version, limit),
            )
        else:
            rows_svc = self._execute(
                """
                SELECT DISTINCT c.*
                FROM   cve_entries c
                JOIN   service_vulnerabilities sv
                       ON LOWER(sv.cve_refs) LIKE '%' || c.cve_id || '%'
                WHERE  LOWER(sv.service_name) LIKE ?
                ORDER  BY c.cvss_score DESC
                LIMIT  ?
                """,
                (service_pattern, limit),
            )

        # Merge, deduplicate by cve_id, re-sort
        seen: set = set()
        merged: List[CVEResult] = []
        for row in list(rows_direct) + list(rows_svc):
            cve_id = row["cve_id"]
            if cve_id not in seen:
                seen.add(cve_id)
                merged.append(self._row_to_cve(row))

        merged.sort(key=lambda c: c.cvss_score, reverse=True)
        result = merged[:limit]

        logger.debug(
            "get_cves_for_service('%s', version=%s) -> %d results",
            service_name,
            version,
            len(result),
        )
        return result

    def get_exploitable_cves(
        self,
        min_cvss: float = 7.0,
        days_back: int = 365,
        limit: int = 50,
    ) -> List[CVEResult]:
        """
        Return CVEs that have a known public exploit, meet the minimum CVSS
        threshold, and were published within the last *days_back* days.

        Parameters
        ----------
        min_cvss : float
            Minimum CVSS score (default 7.0 = HIGH).
        days_back : int
            Look-back window in days from today (default 365).
        limit : int
            Maximum results (default 50).

        Returns
        -------
        List[CVEResult]
            Sorted by CVSS score descending.
        """
        cutoff_date = (datetime.utcnow() - timedelta(days=days_back)).strftime(
            "%Y-%m-%d"
        )

        rows = self._execute(
            """
            SELECT *
            FROM   cve_entries
            WHERE  exploit_available = 1
              AND  cvss_score       >= ?
              AND  published_date   >= ?
            ORDER  BY cvss_score DESC
            LIMIT  ?
            """,
            (min_cvss, cutoff_date, limit),
        )

        results = [self._row_to_cve(r) for r in rows]
        logger.debug(
            "get_exploitable_cves(min_cvss=%.1f, days_back=%d) -> %d results",
            min_cvss,
            days_back,
            len(results),
        )
        return results

    def find_cve_chains(self, cve_ids: List[str]) -> Dict[str, Any]:
        """
        Identify CVEs that share affected products with the supplied *cve_ids*,
        enabling the construction of multi-stage exploit chains.

        The algorithm:
        1. Fetch the full product list for each supplied CVE.
        2. Search for other CVEs affecting the same products.
        3. Group them by shared product to surface chaining opportunities.

        Parameters
        ----------
        cve_ids : List[str]
            Seed CVE identifiers (e.g. ["CVE-2021-44228", "CVE-2021-34527"]).

        Returns
        -------
        dict with keys:
            seed_cves        -- list[CVEResult] for the input IDs
            chain_candidates -- list[CVEResult] sharing at least one product
            product_pivot    -- dict {product: [cve_id, ...]} showing the links
            chain_score      -- float 0-10, estimated chaining risk
        """
        if not cve_ids:
            return {
                "seed_cves": [],
                "chain_candidates": [],
                "product_pivot": {},
                "chain_score": 0.0,
            }

        placeholders = ",".join("?" * len(cve_ids))
        seed_rows = self._execute(
            f"SELECT * FROM cve_entries WHERE cve_id IN ({placeholders})",
            tuple(cve_ids),
        )

        seed_results = [self._row_to_cve(r) for r in seed_rows]

        # Collect all product strings from seeds
        all_products: List[str] = []
        for cve in seed_results:
            all_products.extend(cve.affected_products)

        # Deduplicate and normalise
        unique_products = list({p.lower().strip() for p in all_products if p.strip()})

        product_pivot: Dict[str, List[str]] = {}
        chain_cve_ids: set = set()

        for product in unique_products:
            pattern = f"%{product}%"
            rows = self._execute(
                """
                SELECT cve_id, affected_products
                FROM   cve_entries
                WHERE  LOWER(affected_products) LIKE ?
                  AND  cve_id NOT IN ({placeholders})
                LIMIT  20
                """.format(placeholders=placeholders),
                (pattern, *cve_ids),
            )
            if rows:
                linked_ids = [r["cve_id"] for r in rows]
                product_pivot[product] = linked_ids
                chain_cve_ids.update(linked_ids)

        # Fetch full records for chain candidates
        chain_results: List[CVEResult] = []
        if chain_cve_ids:
            ph2 = ",".join("?" * len(chain_cve_ids))
            chain_rows = self._execute(
                f"""
                SELECT * FROM cve_entries
                WHERE  cve_id IN ({ph2})
                ORDER  BY cvss_score DESC
                LIMIT  30
                """,
                tuple(chain_cve_ids),
            )
            chain_results = [self._row_to_cve(r) for r in chain_rows]

        # Compute chain risk score: average of seed CVSS, weighted by exploitability
        if seed_results:
            avg_seed_cvss = sum(c.cvss_score for c in seed_results) / len(seed_results)
            exploit_bonus = 0.5 * sum(1 for c in seed_results if c.exploit_available)
            chain_score = min(10.0, avg_seed_cvss + exploit_bonus)
        else:
            chain_score = 0.0

        logger.debug(
            "find_cve_chains(%s) -> %d seed, %d chain candidates, score=%.1f",
            cve_ids,
            len(seed_results),
            len(chain_results),
            chain_score,
        )
        return {
            "seed_cves": [c.to_dict() for c in seed_results],
            "chain_candidates": [c.to_dict() for c in chain_results],
            "product_pivot": product_pivot,
            "chain_score": round(chain_score, 2),
        }

    def get_attack_path_cves(self, target_type: str) -> List[CVEResult]:
        """
        Return the most relevant CVEs for a given target category.

        Target types and their keyword filters:

        ============  =================================================
        web           Apache, Nginx, PHP, IIS, Tomcat, WordPress, HTTP
        windows       Windows, NTLM, SMB, Print Spooler, Active Directory
        linux         Linux, kernel, sudo, glibc, systemd, bash
        network       Cisco, Juniper, SNMP, BGP, VPN, firewall, router
        database      MySQL, PostgreSQL, Oracle, MSSQL, MongoDB, Redis
        cloud         AWS, Azure, GCP, Kubernetes, Docker, container
        ============  =================================================

        Parameters
        ----------
        target_type : str
            One of: web, windows, linux, network, database, cloud.

        Returns
        -------
        List[CVEResult]
            Up to 30 CVEs sorted by CVSS score descending.
        """
        keyword_map: Dict[str, List[str]] = {
            "web": [
                "apache", "nginx", "php", "iis", "tomcat",
                "wordpress", "http", "web", "joomla", "drupal",
            ],
            "windows": [
                "windows", "ntlm", "smb", "print spooler",
                "active directory", "kerberos", "wmi", "rdp",
            ],
            "linux": [
                "linux", "kernel", "sudo", "glibc",
                "systemd", "bash", "polkit", "unix",
            ],
            "network": [
                "cisco", "juniper", "snmp", "bgp", "vpn",
                "firewall", "router", "switch", "fortinet",
            ],
            "database": [
                "mysql", "postgresql", "oracle", "mssql",
                "mongodb", "redis", "sqlite", "mariadb",
            ],
            "cloud": [
                "aws", "azure", "gcp", "kubernetes", "docker",
                "container", "helm", "terraform", "s3",
            ],
        }

        keywords = keyword_map.get(target_type.lower(), [target_type.lower()])

        all_rows: List[sqlite3.Row] = []
        for kw in keywords:
            pattern = f"%{kw}%"
            rows = self._execute(
                """
                SELECT DISTINCT *
                FROM   cve_entries
                WHERE  LOWER(description)        LIKE ?
                    OR LOWER(affected_products)  LIKE ?
                ORDER  BY cvss_score DESC
                LIMIT  10
                """,
                (pattern, pattern),
            )
            all_rows.extend(rows)

        # Deduplicate and sort
        seen: set = set()
        results: List[CVEResult] = []
        for row in all_rows:
            if row["cve_id"] not in seen:
                seen.add(row["cve_id"])
                results.append(self._row_to_cve(row))

        results.sort(key=lambda c: c.cvss_score, reverse=True)
        results = results[:30]

        logger.debug(
            "get_attack_path_cves('%s') -> %d results", target_type, len(results)
        )
        return results

    def score_attack_surface(
        self,
        services: Dict[str, Optional[str]],
    ) -> AttackSurfaceReport:
        """
        Compute an aggregated attack-surface risk score for a host given its
        exposed services.

        Algorithm
        ---------
        1. For each service, query CVEs (with version if provided).
        2. Compute per-service sub-score:
               sub_score = max(CVSS) * (1 + 0.1 * exploitable_count)
        3. Overall score = geometric mean of sub-scores, capped at 10.0.
        4. Risk label derived from overall score via CVSS thresholds.

        Parameters
        ----------
        services : dict
            Mapping of service name -> version string (version may be None).
            Example: ``{"apache": "2.4.48", "openssh": "7.4", "mysql": None}``

        Returns
        -------
        AttackSurfaceReport
        """
        per_service: Dict[str, Dict[str, Any]] = {}
        all_cves: List[CVEResult] = []
        sub_scores: List[float] = []

        for svc_name, svc_version in services.items():
            cves = self.get_cves_for_service(svc_name, version=svc_version, limit=15)
            exploitable = [c for c in cves if c.exploit_available]

            max_cvss = max((c.cvss_score for c in cves), default=0.0)
            sub_score = min(
                10.0,
                max_cvss * (1.0 + 0.1 * len(exploitable)) if cves else 0.0,
            )
            sub_scores.append(sub_score)
            all_cves.extend(cves)

            per_service[svc_name] = {
                "version": svc_version,
                "cve_count": len(cves),
                "exploitable_count": len(exploitable),
                "max_cvss": round(max_cvss, 1),
                "sub_score": round(sub_score, 2),
                "severity": _cvss_to_severity(max_cvss),
            }

        # Geometric mean of sub-scores (avoids single outlier domination)
        if sub_scores:
            import math
            nonzero = [s for s in sub_scores if s > 0]
            if nonzero:
                log_sum = sum(math.log(s) for s in nonzero)
                overall = math.exp(log_sum / len(nonzero))
            else:
                overall = 0.0
        else:
            overall = 0.0

        overall = round(min(10.0, overall), 2)

        # Deduplicate all_cves and sort, take top 10
        seen: set = set()
        unique_cves: List[CVEResult] = []
        for c in all_cves:
            if c.cve_id not in seen:
                seen.add(c.cve_id)
                unique_cves.append(c)
        unique_cves.sort(key=lambda c: c.cvss_score, reverse=True)
        top_cves = unique_cves[:10]

        exploitable_total = sum(
            1 for c in unique_cves if c.exploit_available
        )

        # Generate recommendations
        recommendations: List[str] = []
        for svc, data in per_service.items():
            if data["exploitable_count"] > 0:
                recommendations.append(
                    f"Patch {svc} immediately — {data['exploitable_count']} "
                    f"exploitable CVE(s) with max CVSS {data['max_cvss']}."
                )
            elif data["cve_count"] > 0:
                recommendations.append(
                    f"Review {svc} ({data['cve_count']} CVE(s) found, "
                    f"none with public exploit yet)."
                )
        if overall >= 9.0:
            recommendations.insert(
                0, "CRITICAL attack surface — immediate remediation required."
            )
        elif overall >= 7.0:
            recommendations.insert(
                0, "HIGH attack surface — schedule urgent patching cycle."
            )

        report = AttackSurfaceReport(
            overall_score=overall,
            risk_label=_cvss_to_severity(overall),
            total_cves=len(unique_cves),
            exploitable_cves=exploitable_total,
            per_service=per_service,
            top_cves=top_cves,
            recommendations=recommendations,
        )

        logger.info(
            "score_attack_surface(%s services) -> score=%.2f (%s)",
            len(services),
            overall,
            report.risk_label,
        )
        return report

    # ------------------------------------------------------------------
    # Utility / diagnostics
    # ------------------------------------------------------------------

    def ping(self) -> Dict[str, Any]:
        """Return health information about the database connection."""
        rows = self._execute("SELECT COUNT(*) AS cnt FROM cve_entries")
        cve_count = rows[0]["cnt"] if rows else 0
        return {
            "db_path": self._db_path,
            "db_available": self._db_available,
            "cve_count": cve_count,
        }
