#!/usr/bin/env python3
"""
Nexus Automation Framework - Database Analysis Script
Analyzes and displays the structure and content of knowledge.db
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime

def analyze_database(db_path="knowledge.db"):
    """Complete database analysis"""
    
    if not Path(db_path).exists():
        print(f"❌ Database {db_path} not found")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("📊 STRUCTURE DE LA BASE DE DONNÉES knowledge.db")
    print("=" * 60)
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    for table in sorted(tables):
        print(f"\n🗂️ TABLE: {table.upper()}")
        
        # Table structure
        cursor.execute(f"PRAGMA table_info({table})")
        columns = cursor.fetchall()
        print("   Colonnes:")
        for col in columns:
            if len(col) == 5:
                col_name, col_type, not_null, default, pk = col
            else:
                col_name, col_type, not_null, default, pk, _ = col
            pk_str = " (PK)" if pk else ""
            null_str = " NOT NULL" if not_null else ""
            default_str = f" DEFAULT {default}" if default else ""
            print(f"     - {col_name}: {col_type}{pk_str}{null_str}{default_str}")
        
        # Row count
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"   Entrées: {count}")
        
        # Sample data
        if count > 0:
            cursor.execute(f"SELECT * FROM {table} LIMIT 3")
            rows = cursor.fetchall()
            col_names = [description[0] for description in cursor.description]
            
            print("   Exemples:")
            for i, row in enumerate(rows, 1):
                print(f"     {i}. ", end="")
                for j, (col_name, value) in enumerate(zip(col_names, row)):
                    if isinstance(value, str) and len(value) > 50:
                        value = value[:47] + "..."
                    print(f"{col_name}={value}", end="")
                    if j < len(row) - 1:
                        print(", ", end="")
                print()
    
    # Global statistics
    print(f"\n📈 STATISTIQUES GLOBALES")
    print("=" * 60)
    
    # Database size
    size_mb = Path(db_path).stat().st_size / (1024 * 1024)
    print(f"Taille: {size_mb:.2f} MB")
    
    # Table distribution
    total_entries = 0
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        total_entries += count
        print(f"{table}: {count} entrées")
    
    print(f"Total: {total_entries} entrées")
    
    # CVE-specific statistics
    if "cve_entries" in tables:
        print(f"\n🔍 STATISTIQUES CVE")
        print("=" * 30)
        
        # By severity
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN severity >= 0.9 THEN 'CRITICAL'
                    WHEN severity >= 0.7 THEN 'HIGH' 
                    WHEN severity >= 0.5 THEN 'MEDIUM'
                    ELSE 'LOW'
                END as severity_level,
                COUNT(*) as count
            FROM cve_entries 
            GROUP BY severity_level
        """)
        severity_stats = dict(cursor.fetchall())
        print("Par sévérité:")
        for level, count in severity_stats.items():
            print(f"  {level}: {count}")
        
        # By CVSS score ranges
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN cvss_score >= 9.0 THEN '9.0-10.0'
                    WHEN cvss_score >= 7.0 THEN '7.0-8.9'
                    WHEN cvss_score >= 4.0 THEN '4.0-6.9'
                    ELSE '0.0-3.9'
                END as score_range,
                COUNT(*) as count
            FROM cve_entries 
            GROUP BY score_range
        """)
        score_stats = dict(cursor.fetchall())
        print("Par score CVSS:")
        for range_val, count in score_stats.items():
            print(f"  {range_val}: {count}")
        
        # Exploit availability
        cursor.execute("""
            SELECT exploit_available, COUNT(*) 
            FROM cve_entries 
            GROUP BY exploit_available
        """)
        exploit_stats = dict(cursor.fetchall())
        print("Exploits disponibles:")
        for available, count in exploit_stats.items():
            status = "Oui" if available else "Non"
            print(f"  {status}: {count}")
        
        # Recent CVEs
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
        cursor.execute("""
            SELECT COUNT(*) FROM cve_entries 
            WHERE published_date >= ?
        """, (thirty_days_ago,))
        recent_count = cursor.fetchone()[0]
        print(f"Récents (30 jours): {recent_count}")
    
    # Attack techniques statistics
    if "attack_techniques" in tables:
        print(f"\n⚔️ STATISTIQUES TECHNIQUES D'ATTAQUE")
        print("=" * 40)
        
        # By phase
        cursor.execute("""
            SELECT phase, COUNT(*) 
            FROM attack_techniques 
            GROUP BY phase
        """)
        phase_stats = dict(cursor.fetchall())
        print("Par phase:")
        for phase, count in phase_stats.items():
            print(f"  {phase}: {count}")
        
        # Effectiveness distribution
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN effectiveness_score >= 0.8 THEN 'Très élevée'
                    WHEN effectiveness_score >= 0.6 THEN 'Élevée'
                    WHEN effectiveness_score >= 0.4 THEN 'Moyenne'
                    ELSE 'Faible'
                END as effectiveness,
                COUNT(*) as count
            FROM attack_techniques 
            GROUP BY effectiveness
        """)
        eff_stats = dict(cursor.fetchall())
        print("Par efficacité:")
        for eff, count in eff_stats.items():
            print(f"  {eff}: {count}")
    
    # Service vulnerabilities
    if "service_vulnerabilities" in tables:
        print(f"\n🖥️ STATISTIQUES VULNÉRABILITÉS DE SERVICES")
        print("=" * 45)
        
        # Top services
        cursor.execute("""
            SELECT service_name, COUNT(*) 
            FROM service_vulnerabilities 
            GROUP BY service_name 
            ORDER BY COUNT(*) DESC 
            LIMIT 10
        """)
        service_stats = cursor.fetchall()
        print("Services les plus vulnérables:")
        for service, count in service_stats:
            print(f"  {service}: {count}")
        
        # By protocol
        cursor.execute("""
            SELECT protocol, COUNT(*) 
            FROM service_vulnerabilities 
            GROUP BY protocol
        """)
        protocol_stats = dict(cursor.fetchall())
        print("Par protocole:")
        for protocol, count in protocol_stats.items():
            print(f"  {protocol}: {count}")
    
    # Knowledge versions
    if "knowledge_versions" in tables:
        print(f"\n📚 VERSIONS DES CONNAISSANCES")
        print("=" * 30)
        
        cursor.execute("""
            SELECT version, created_at, description 
            FROM knowledge_versions 
            ORDER BY version DESC
        """)
        versions = cursor.fetchall()
        for version, created_at, description in versions:
            created = datetime.fromisoformat(created_at).strftime("%Y-%m-%d %H:%M")
            print(f"  v{version}: {created} - {description[:50]}...")
    
    conn.close()

if __name__ == "__main__":
    from datetime import timedelta
    analyze_database()
