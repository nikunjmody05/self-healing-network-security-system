-- Threat memory schema (SQLite).
-- Generated from threat_memory.py: ThreatMemory creates threat_events, threat_patterns and
-- recovery_audit on open; endpoint_healing_audit and apt_* are created lazily on first use.
-- Each pipeline/demo run creates its own fresh database (runs/<RUN_ID>/threat_memory_run.db).

CREATE TABLE threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                prediction INTEGER,
                confidence REAL,
                threat_score REAL,
                severity TEXT,
                rl_state TEXT,
                rl_action TEXT,
                response TEXT,
                containment INTEGER,
                containment_verified INTEGER,
                pattern_id TEXT,
                pattern_status TEXT,
                fingerprint TEXT,
                metadata TEXT
            );

CREATE TABLE threat_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_id TEXT UNIQUE,
                fingerprint TEXT UNIQUE,
                first_seen TEXT,
                last_seen TEXT,
                occurrence_count INTEGER DEFAULT 1,
                prediction INTEGER,
                average_confidence REAL,
                average_threat_score REAL,
                severity TEXT,
                last_action TEXT,
                last_response TEXT,
                successful_containments INTEGER DEFAULT 0,
                failed_containments INTEGER DEFAULT 0
            );

CREATE TABLE recovery_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                run_id TEXT NOT NULL,
                flow_step INTEGER NOT NULL,
                original_prediction INTEGER NOT NULL,
                true_label INTEGER NOT NULL,
                initial_action TEXT NOT NULL,
                initial_verification_status TEXT,
                healing_action TEXT,
                recovery_action TEXT,
                recovery_status TEXT,
                recovery_verified INTEGER NOT NULL DEFAULT 0,
                evaluation_mode TEXT NOT NULL,
                metadata TEXT
            );

CREATE TABLE endpoint_healing_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                run_id TEXT,
                trigger_event_id TEXT,
                host_id TEXT NOT NULL,
                scenario TEXT,
                recovery_status TEXT NOT NULL,
                verified INTEGER NOT NULL,
                files_checked INTEGER,
                files_failed INTEGER,
                quarantined INTEGER,
                restored INTEGER,
                persistence_removed INTEGER,
                final_healing_action TEXT,
                failure_reasons TEXT,
                report_path TEXT,
                evaluation_mode TEXT NOT NULL
            );

CREATE TABLE apt_campaigns (
                campaign_id TEXT PRIMARY KEY,
                run_id TEXT,
                first_seen TEXT NOT NULL,
                trigger_event_id TEXT,
                hosts TEXT,
                stage_count INTEGER DEFAULT 0,
                verdict TEXT,
                evaluation_mode TEXT NOT NULL
            );

CREATE TABLE apt_campaign_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                tactic_id TEXT,
                tactic TEXT,
                host_id TEXT NOT NULL,
                artifact TEXT,
                artifact_sha256 TEXT,
                description TEXT
            );

CREATE TABLE apt_iocs (
                campaign_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                first_host TEXT NOT NULL,
                hosts_seen TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                PRIMARY KEY (campaign_id, sha256)
            );
