#!/usr/bin/env python3
"""
Nexus Automation Framework - Knowledge DB Schema Redesign

Migrate from basic schema to a proper relational model with:
- Foreign key constraints
- Proper indexes for performance
- New tables: payloads, checklists, wordlists, tool_profiles
- Normalized structure
- Data migration from existing tables
"""

import os
import sqlite3
import logging
import json
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("NEXUS_DB_PATH", "knowledge.db")
BACKUP_PATH = f"{DB_PATH}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

def backup_database():
    """Create a backup of the current database."""
    logger.info(f"Creating backup: {BACKUP_PATH}")
    conn = sqlite3.connect(DB_PATH)
    backup = sqlite3.connect(BACKUP_PATH)
    conn.backup(backup)
    conn.close()
    backup.close()
    logger.info("Backup completed")

def create_new_schema(conn):
    """Create the new schema with proper relationships and indexes."""
    
    # Enable foreign key constraints
    conn.execute("PRAGMA foreign_keys = ON")
    
    # ── Core Tables ────────────────────────────────────────────────────────
    
    # CVE Entries (enhanced)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_entries_new (
            cve_id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            severity REAL,
            cvss_score REAL,
            cvss_vector TEXT,
            published_date TEXT,
            modified_date TEXT,
            affected_products TEXT,  -- JSON array
            cve_references TEXT,    -- JSON array
            exploit_available BOOLEAN DEFAULT FALSE,
            exploit_complexity TEXT,
            required_privileges TEXT,
            user_interaction BOOLEAN,
            scope_changed BOOLEAN,
            confidentiality_impact TEXT,
            integrity_impact TEXT,
            availability_impact TEXT,
            knowledge_version INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Attack Techniques (MITRE ATT&CK)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS attack_techniques_new (
            technique_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            tactic TEXT,
            platforms TEXT,  -- JSON array
            data_sources TEXT,  -- JSON array
            detection TEXT,
            mitigation TEXT,
            ref_links TEXT,  -- JSON array (renamed from 'references')
            knowledge_version INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Service Vulnerabilities
    conn.execute("""
        CREATE TABLE IF NOT EXISTS service_vulnerabilities_new (
            vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT NOT NULL,
            version_pattern TEXT,
            vulnerability_type TEXT,
            description TEXT,
            severity TEXT,
            cve_refs TEXT,  -- JSON array of CVE IDs
            exploit_refs TEXT,  -- JSON array of exploit references
            detection_methods TEXT,  -- JSON array
            mitigation TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Exploit Patterns
    conn.execute("""
        CREATE TABLE IF NOT EXISTS exploit_patterns_new (
            pattern_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            technique_refs TEXT,  -- JSON array of technique IDs
            service_refs TEXT,   -- JSON array of service names
            payload_examples TEXT,  -- JSON array
            detection_indicators TEXT,  -- JSON array
            success_indicators TEXT,  -- JSON array
            complexity TEXT,
            reliability TEXT,
            side_effects TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Evasion Patterns
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evasion_patterns_new (
            pattern_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            target_systems TEXT,  -- JSON array
            technique_refs TEXT,  -- JSON array
            implementation TEXT,
            detection_bypass TEXT,
            effectiveness TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Workflow Rules
    conn.execute("""
        CREATE TABLE IF NOT EXISTS workflow_rules_new (
            rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phase TEXT,
            category TEXT,
            description TEXT,
            conditions TEXT,  -- JSON array
            actions TEXT,     -- JSON array
            priority INTEGER DEFAULT 5,
            enabled BOOLEAN DEFAULT TRUE,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # ── New Tables ────────────────────────────────────────────────────────
    
    # Payloads (from payload_manager.py)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS payloads (
            payload_id TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            name TEXT NOT NULL,
            content TEXT NOT NULL,
            description TEXT DEFAULT '',
            target_tech TEXT DEFAULT 'generic',
            tags TEXT DEFAULT '[]',  -- JSON array
            waf_bypass BOOLEAN DEFAULT FALSE,
            encoding TEXT DEFAULT 'none',
            severity TEXT DEFAULT 'medium',
            source TEXT DEFAULT '',
            success_indicator TEXT DEFAULT '',
            context TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Checklists (pentest methodology checklists)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS checklists (
            checklist_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            phase TEXT,
            items TEXT,  -- JSON array of checklist items
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Wordlists (pentest wordlists and dictionaries)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS wordlists (
            wordlist_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            language TEXT DEFAULT 'en',
            word_count INTEGER DEFAULT 0,
            file_path TEXT,
            source TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Tool Profiles (configuration and capabilities for security tools)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tool_profiles (
            tool_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            command_template TEXT,
            parameters TEXT,  -- JSON array
            output_formats TEXT,  -- JSON array
            capabilities TEXT,  -- JSON array
            dependencies TEXT,  -- JSON array
            install_commands TEXT,  -- JSON array
            version TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # ── Relationship Tables ────────────────────────────────────────────────
    
    # CVE-Technique relationships
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cve_technique_mapping (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            confidence REAL DEFAULT 1.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (cve_id) REFERENCES cve_entries_new(cve_id) ON DELETE CASCADE,
            FOREIGN KEY (technique_id) REFERENCES attack_techniques_new(technique_id) ON DELETE CASCADE,
            UNIQUE(cve_id, technique_id)
        )
    """)
    
    # Service-Exploit relationships
    conn.execute("""
        CREATE TABLE IF NOT EXISTS service_exploit_mapping (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id INTEGER NOT NULL,
            pattern_id INTEGER NOT NULL,
            confidence REAL DEFAULT 1.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vuln_id) REFERENCES service_vulnerabilities_new(vuln_id) ON DELETE CASCADE,
            FOREIGN KEY (pattern_id) REFERENCES exploit_patterns_new(pattern_id) ON DELETE CASCADE,
            UNIQUE(vuln_id, pattern_id)
        )
    """)
    
    # Technique-Payload relationships
    conn.execute("""
        CREATE TABLE IF NOT EXISTS technique_payload_mapping (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technique_id TEXT NOT NULL,
            payload_id TEXT NOT NULL,
            relevance_score REAL DEFAULT 1.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (technique_id) REFERENCES attack_techniques_new(technique_id) ON DELETE CASCADE,
            FOREIGN KEY (payload_id) REFERENCES payloads(payload_id) ON DELETE CASCADE,
            UNIQUE(technique_id, payload_id)
        )
    """)
    
    # ── Indexes for Performance ─────────────────────────────────────────────
    
    # CVE indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries_new(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_cvss_score ON cve_entries_new(cvss_score)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_published ON cve_entries_new(published_date)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_exploit_available ON cve_entries_new(exploit_available)")
    
    # Technique indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_technique_tactic ON attack_techniques_new(tactic)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_technique_platforms ON attack_techniques_new(platforms)")
    
    # Service vulnerability indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_service_name ON service_vulnerabilities_new(service_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_service_type ON service_vulnerabilities_new(vulnerability_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_service_severity ON service_vulnerabilities_new(severity)")
    
    # Exploit pattern indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_exploit_category ON exploit_patterns_new(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_exploit_complexity ON exploit_patterns_new(complexity)")
    
    # Evasion pattern indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_evasion_category ON evasion_patterns_new(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_evasion_target ON evasion_patterns_new(target_systems)")
    
    # Workflow indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_workflow_phase ON workflow_rules_new(phase)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_workflow_category ON workflow_rules_new(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_workflow_priority ON workflow_rules_new(priority)")
    
    # Payload indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payload_category ON payloads(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payload_tech ON payloads(target_tech)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payload_severity ON payloads(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_payload_waf_bypass ON payloads(waf_bypass)")
    
    # Checklist indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_checklist_phase ON checklists(phase)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_checklist_category ON checklists(category)")
    
    # Wordlist indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wordlist_category ON wordlists(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_wordlist_language ON wordlists(language)")
    
    # Tool profile indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tool_category ON tool_profiles(category)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tool_name ON tool_profiles(name)")
    
    logger.info("New schema created successfully")

def migrate_data(conn):
    """Migrate data from old tables to new schema."""
    logger.info("Starting data migration...")
    
    # Migrate CVE entries
    logger.info("Migrating CVE entries...")
    conn.execute("""
        INSERT INTO cve_entries_new (
            cve_id, description, severity, cvss_score, cvss_vector,
            published_date, modified_date, affected_products, cve_references,
            exploit_available, exploit_complexity, required_privileges,
            user_interaction, scope_changed, confidentiality_impact,
            integrity_impact, availability_impact, knowledge_version
        )
        SELECT cve_id, description, severity, cvss_score, cvss_vector,
               published_date, modified_date, affected_products, cve_references,
               exploit_available, exploit_complexity, required_privileges,
               user_interaction, scope_changed, confidentiality_impact,
               integrity_impact, availability_impact, knowledge_version
        FROM cve_entries
    """)
    
    # Migrate attack techniques
    logger.info("Migrating attack techniques...")
    conn.execute("""
        INSERT INTO attack_techniques_new (
            technique_id, name, description, tactic, platforms, data_sources,
            detection, mitigation, ref_links, knowledge_version
        )
        SELECT technique_id, name, description, phase, platforms, data_sources,
               detection_methods, mitigation, '[]' as ref_links, knowledge_version
        FROM attack_techniques
    """)
    
    # Migrate service vulnerabilities
    logger.info("Migrating service vulnerabilities...")
    conn.execute("""
        INSERT INTO service_vulnerabilities_new (
            service_name, version_pattern, vulnerability_type, description,
            severity, cve_refs, exploit_refs, detection_methods, mitigation
        )
        SELECT service_name, service_version, 'unknown' as vulnerability_type, 
               'Service vulnerability' as description, 'medium' as severity,
               cve_ids, '[]' as exploit_refs, detection_signatures, common_misconfigurations
        FROM service_vulnerabilities
    """)
    
    # Migrate exploit patterns
    logger.info("Migrating exploit patterns...")
    conn.execute("""
        INSERT INTO exploit_patterns_new (
            name, description, category, technique_refs, service_refs,
            payload_examples, detection_indicators, success_indicators,
            complexity, reliability, side_effects
        )
        SELECT name, exploitation_method as description, vulnerability_type as category,
               '[]' as technique_refs, '[]' as service_refs, '[]' as payload_examples,
               detection_signatures as detection_indicators, success_indicators,
               'medium' as complexity, 'medium' as reliability, side_effects
        FROM exploit_patterns
    """)
    
    # Migrate evasion patterns
    logger.info("Migrating evasion patterns...")
    conn.execute("""
        INSERT INTO evasion_patterns_new (
            name, description, category, target_systems, technique_refs,
            implementation, detection_bypass, effectiveness
        )
        SELECT name, evasion_technique as description, 'evasion' as category,
               '[]' as target_systems, '[]' as technique_refs, implementation_methods,
               detection_bypasses, effectiveness_score as effectiveness
        FROM evasion_patterns
    """)
    
    # Migrate workflow rules
    logger.info("Migrating workflow rules...")
    conn.execute("""
        INSERT INTO workflow_rules_new (
            name, phase, category, description, conditions, actions, priority, enabled
        )
        SELECT name, phase, category, description, trigger_condition as conditions,
               actions, priority, enabled
        FROM workflow_rules
    """)
    
    logger.info("Data migration completed")

def create_relationships(conn):
    """Create relationships between entities based on data analysis."""
    logger.info("Creating entity relationships...")
    
    # Create CVE-Technique mappings based on pattern matching
    logger.info("Creating CVE-Technique mappings...")
    conn.execute("""
        INSERT OR IGNORE INTO cve_technique_mapping (cve_id, technique_id, confidence)
        SELECT DISTINCT 
            c.cve_id,
            t.technique_id,
            CASE 
                WHEN c.description LIKE '%' || t.name || '%' THEN 0.9
                WHEN c.description LIKE '%' || LOWER(t.name) || '%' THEN 0.8
                WHEN c.description LIKE '%' || UPPER(t.name) || '%' THEN 0.8
                ELSE 0.5
            END as confidence
        FROM cve_entries_new c
        CROSS JOIN attack_techniques_new t
        WHERE (c.description LIKE '%' || t.name || '%' OR 
               c.description LIKE '%' || LOWER(t.name) || '%' OR
               c.description LIKE '%' || UPPER(t.name) || '%')
        AND confidence > 0.5
        LIMIT 10000
    """)
    
    # Create Service-Exploit mappings
    logger.info("Creating Service-Exploit mappings...")
    conn.execute("""
        INSERT OR IGNORE INTO service_exploit_mapping (vuln_id, pattern_id, confidence)
        SELECT DISTINCT 
            s.vuln_id,
            e.pattern_id,
            CASE 
                WHEN s.service_name LIKE '%' || e.name || '%' THEN 0.9
                WHEN s.vulnerability_type LIKE '%' || e.category || '%' THEN 0.8
                WHEN s.description LIKE '%' || e.description || '%' THEN 0.7
                ELSE 0.5
            END as confidence
        FROM service_vulnerabilities_new s
        CROSS JOIN exploit_patterns_new e
        WHERE (s.service_name LIKE '%' || e.name || '%' OR 
               s.vulnerability_type LIKE '%' || e.category || '%' OR
               s.description LIKE '%' || e.description || '%')
        AND confidence > 0.5
        LIMIT 5000
    """)
    
    # Create Technique-Payload mappings
    logger.info("Creating Technique-Payload mappings...")
    conn.execute("""
        INSERT OR IGNORE INTO technique_payload_mapping (technique_id, payload_id, relevance_score)
        SELECT DISTINCT 
            t.technique_id,
            p.payload_id,
            CASE 
                WHEN t.name LIKE '%' || p.name || '%' THEN 0.9
                WHEN t.tactic LIKE '%' || p.category || '%' THEN 0.8
                WHEN p.category LIKE '%' || t.tactic || '%' THEN 0.8
                ELSE 0.6
            END as relevance_score
        FROM attack_techniques_new t
        CROSS JOIN payloads p
        WHERE (t.name LIKE '%' || p.name || '%' OR 
               t.tactic LIKE '%' || p.category || '%' OR
               p.category LIKE '%' || t.tactic || '%')
        AND relevance_score > 0.5
        LIMIT 8000
    """)
    
    logger.info("Entity relationships created")

def finalize_schema(conn):
    """Finalize the schema by dropping old tables and renaming new ones."""
    logger.info("Finalizing schema...")
    
    # Drop old tables
    old_tables = [
        'cve_entries', 'attack_techniques', 'service_vulnerabilities',
        'exploit_patterns', 'evasion_patterns', 'workflow_rules'
    ]
    
    for table in old_tables:
        try:
            conn.execute(f"DROP TABLE IF EXISTS {table}")
            logger.info(f"Dropped old table: {table}")
        except Exception as e:
            logger.warning(f"Could not drop table {table}: {e}")
    
    # Rename new tables to final names
    renames = {
        'cve_entries_new': 'cve_entries',
        'attack_techniques_new': 'attack_techniques',
        'service_vulnerabilities_new': 'service_vulnerabilities',
        'exploit_patterns_new': 'exploit_patterns',
        'evasion_patterns_new': 'evasion_patterns',
        'workflow_rules_new': 'workflow_rules'
    }
    
    for old_name, new_name in renames.items():
        try:
            conn.execute(f"ALTER TABLE {old_name} RENAME TO {new_name}")
            logger.info(f"Renamed {old_name} to {new_name}")
        except Exception as e:
            logger.warning(f"Could not rename table {old_name}: {e}")
    
    # Create view for statistics
    conn.execute("""
        CREATE VIEW IF NOT EXISTS knowledge_stats AS
        SELECT 
            'cve_entries' as table_name,
            COUNT(*) as total_count,
            COUNT(CASE WHEN exploit_available = 1 THEN 1 END) as exploit_count,
            AVG(cvss_score) as avg_cvss
        FROM cve_entries
        UNION ALL
        SELECT 
            'attack_techniques' as table_name,
            COUNT(*) as total_count,
            0 as exploit_count,
            0 as avg_cvss
        FROM attack_techniques
        UNION ALL
        SELECT 
            'payloads' as table_name,
            COUNT(*) as total_count,
            COUNT(CASE WHEN waf_bypass = 1 THEN 1 END) as exploit_count,
            0 as avg_cvss
        FROM payloads
        UNION ALL
        SELECT 
            'service_vulnerabilities' as table_name,
            COUNT(*) as total_count,
            0 as exploit_count,
            0 as avg_cvss
        FROM service_vulnerabilities
    """)
    
    conn.commit()
    logger.info("Schema finalization completed")

def main():
    """Main migration process."""
    logger.info("Starting knowledge database schema redesign...")
    
    # Check if database exists
    if not os.path.exists(DB_PATH):
        logger.error(f"Database not found: {DB_PATH}")
        return False
    
    try:
        # Create backup
        backup_database()
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        
        # Create new schema
        create_new_schema(conn)
        
        # Migrate existing data
        migrate_data(conn)
        
        # Create relationships
        create_relationships(conn)
        
        # Finalize schema
        finalize_schema(conn)
        
        conn.close()
        
        logger.info("Schema redesign completed successfully!")
        logger.info(f"Backup saved to: {BACKUP_PATH}")
        
        return True
        
    except Exception as e:
        logger.error(f"Schema redesign failed: {e}")
        logger.info(f"You can restore from backup: {BACKUP_PATH}")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
