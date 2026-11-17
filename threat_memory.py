import sqlite3
import json
from datetime import datetime


# ============================================================
# THREAT MEMORY
# ============================================================

class ThreatMemory:

    def __init__(
        self,
        db_path="threat_memory.db"
    ):

        self.db_path = db_path

        self.connection = sqlite3.connect(
            self.db_path
        )

        self.connection.row_factory = sqlite3.Row

        self.cursor = self.connection.cursor()

        self._create_tables()

        print(
            f"Threat Memory Ready: {self.db_path}"
        )


    # ========================================================
    # CREATE DATABASE TABLES
    # ========================================================

    def _create_tables(self):

        # ----------------------------------------------------
        # THREAT EVENTS
        # ----------------------------------------------------

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_events (

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

            )
            """
        )


        # ----------------------------------------------------
        # THREAT PATTERNS
        # ----------------------------------------------------

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_patterns (

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

            )
            """
        )


        # ----------------------------------------------------
        # RECOVERY AUDIT
        # ----------------------------------------------------
        #
        # This table stores incidents that required recovery
        # during offline oracle-assisted evaluation.
        #
        # IMPORTANT:
        #
        # A record in this table does NOT mean that the RF
        # model originally detected the attack.
        #
        # Example:
        #
        # Actual Attack
        #      ↓
        # RF predicts BENIGN
        #      ↓
        # RL chooses ALLOW
        #      ↓
        # Ground truth reveals failure AFTER response
        #      ↓
        # Self-Healing recommends BLOCK
        #      ↓
        # Recovery is evaluated
        #
        # Such an incident belongs here rather than being
        # falsely inserted into threat_patterns.
        # ----------------------------------------------------

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS recovery_audit (

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

            )
            """
        )


        self.connection.commit()


    # ========================================================
    # GENERATE TIMESTAMP
    # ========================================================

    def _timestamp(self):

        return datetime.now().isoformat(
            timespec="seconds"
        )


    # ========================================================
    # STORE SECURITY EVENT
    # ========================================================

    def store_event(
        self,
        event_id,
        prediction,
        confidence,
        threat_score,
        severity,
        rl_state,
        rl_action,
        response,
        containment,
        fingerprint,
        pattern_id=None,
        pattern_status="NEW",
        source_ip=None,
        destination_ip=None,
        protocol=None,
        containment_verified=False,
        metadata=None
    ):

        timestamp = self._timestamp()

        if metadata is None:
            metadata = {}

        metadata_json = json.dumps(
            metadata
        )

        self.cursor.execute(
            """
            INSERT INTO threat_events (

                event_id,
                timestamp,
                source_ip,
                destination_ip,
                protocol,
                prediction,
                confidence,
                threat_score,
                severity,
                rl_state,
                rl_action,
                response,
                containment,
                containment_verified,
                pattern_id,
                pattern_status,
                fingerprint,
                metadata

            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,

            (
                event_id,
                timestamp,
                source_ip,
                destination_ip,
                protocol,
                int(prediction),
                float(confidence),
                float(threat_score),
                severity,
                str(rl_state),
                rl_action,
                response,
                int(bool(containment)),
                int(bool(containment_verified)),
                pattern_id,
                pattern_status,
                fingerprint,
                metadata_json
            )
        )

        self.connection.commit()

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "stored": True
        }


    # ========================================================
    # STORE RECOVERY AUDIT EVENT
    # ========================================================

    def store_recovery_audit(
        self,
        event_id,
        run_id,
        flow_step,
        original_prediction,
        true_label,
        initial_action,
        initial_verification_status,
        healing_action,
        recovery_action,
        recovery_status,
        recovery_verified,
        metadata=None
    ):

        if metadata is None:
            metadata = {}

        metadata_json = json.dumps(
            metadata
        )

        timestamp = self._timestamp()

        self.cursor.execute(
            """
            INSERT INTO recovery_audit (

                event_id,
                timestamp,
                run_id,
                flow_step,
                original_prediction,
                true_label,
                initial_action,
                initial_verification_status,
                healing_action,
                recovery_action,
                recovery_status,
                recovery_verified,
                evaluation_mode,
                metadata

            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,

            (
                event_id,
                timestamp,
                run_id,
                int(flow_step),
                int(original_prediction),
                int(true_label),
                initial_action,
                initial_verification_status,
                healing_action,
                recovery_action,
                recovery_status,
                int(bool(recovery_verified)),
                "OFFLINE_ORACLE_ASSISTED",
                metadata_json
            )
        )

        self.connection.commit()

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "stored": True
        }


    # ========================================================
    # GET EVENT
    # ========================================================

    def get_event(
        self,
        event_id
    ):

        self.cursor.execute(
            """
            SELECT *
            FROM threat_events
            WHERE event_id = ?
            """,

            (
                event_id,
            )
        )

        row = self.cursor.fetchone()

        if row is None:
            return None

        return dict(
            row
        )


    # ========================================================
    # GET RECOVERY AUDIT EVENT
    # ========================================================

    def get_recovery_audit(
        self,
        event_id
    ):

        self.cursor.execute(
            """
            SELECT *
            FROM recovery_audit
            WHERE event_id = ?
            """,

            (
                event_id,
            )
        )

        row = self.cursor.fetchone()

        if row is None:
            return None

        return dict(
            row
        )


    # ========================================================
    # GET ALL RECOVERY AUDIT EVENTS
    # ========================================================

    def get_all_recovery_audits(
        self
    ):

        self.cursor.execute(
            """
            SELECT *
            FROM recovery_audit
            ORDER BY id ASC
            """
        )

        rows = self.cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]


    # ========================================================
    # GET PATTERN BY FINGERPRINT
    # ========================================================

    def get_pattern_by_fingerprint(
        self,
        fingerprint
    ):

        self.cursor.execute(
            """
            SELECT *
            FROM threat_patterns
            WHERE fingerprint = ?
            """,

            (
                fingerprint,
            )
        )

        row = self.cursor.fetchone()

        if row is None:
            return None

        return dict(
            row
        )


    # ========================================================
    # GET PATTERN BY ID
    # ========================================================

    def get_pattern(
        self,
        pattern_id
    ):

        self.cursor.execute(
            """
            SELECT *
            FROM threat_patterns
            WHERE pattern_id = ?
            """,

            (
                pattern_id,
            )
        )

        row = self.cursor.fetchone()

        if row is None:
            return None

        return dict(
            row
        )


    # ========================================================
    # CREATE NEW THREAT PATTERN
    # ========================================================

    def create_pattern(
        self,
        pattern_id,
        fingerprint,
        prediction,
        confidence,
        threat_score,
        severity,
        action,
        response,
        containment_success=False
    ):

        timestamp = self._timestamp()

        successful_containments = (
            1
            if containment_success
            else 0
        )

        self.cursor.execute(
            """
            INSERT INTO threat_patterns (

                pattern_id,
                fingerprint,
                first_seen,
                last_seen,
                occurrence_count,
                prediction,
                average_confidence,
                average_threat_score,
                severity,
                last_action,
                last_response,
                successful_containments,
                failed_containments

            )

            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,

            (
                pattern_id,
                fingerprint,
                timestamp,
                timestamp,
                1,
                int(prediction),
                float(confidence),
                float(threat_score),
                severity,
                action,
                response,
                successful_containments,
                0
            )
        )

        self.connection.commit()

        return self.get_pattern(
            pattern_id
        )


    # ========================================================
    # UPDATE EXISTING THREAT PATTERN
    # ========================================================

    def update_pattern(
        self,
        pattern_id,
        confidence,
        threat_score,
        severity,
        action,
        response,
        containment_success=False
    ):

        pattern = self.get_pattern(
            pattern_id
        )

        if pattern is None:
            return None

        old_count = pattern[
            "occurrence_count"
        ]

        new_count = (
            old_count + 1
        )


        # ----------------------------------------------------
        # RUNNING AVERAGES
        # ----------------------------------------------------

        new_average_confidence = (

            (
                pattern["average_confidence"]
                * old_count
            )

            + float(confidence)

        ) / new_count


        new_average_threat_score = (

            (
                pattern["average_threat_score"]
                * old_count
            )

            + float(threat_score)

        ) / new_count


        successful_containments = pattern[
            "successful_containments"
        ]

        if containment_success:

            successful_containments += 1


        self.cursor.execute(
            """
            UPDATE threat_patterns

            SET

                last_seen = ?,

                occurrence_count = ?,

                average_confidence = ?,

                average_threat_score = ?,

                severity = ?,

                last_action = ?,

                last_response = ?,

                successful_containments = ?

            WHERE pattern_id = ?
            """,

            (
                self._timestamp(),
                new_count,
                new_average_confidence,
                new_average_threat_score,
                severity,
                action,
                response,
                successful_containments,
                pattern_id
            )
        )

        self.connection.commit()

        return self.get_pattern(
            pattern_id
        )


    # ========================================================
    # UPDATE EVENT VERIFICATION
    # ========================================================

    def update_containment_verification(
        self,
        event_id,
        verified
    ):

        self.cursor.execute(
            """
            UPDATE threat_events

            SET containment_verified = ?

            WHERE event_id = ?
            """,

            (
                int(bool(verified)),
                event_id
            )
        )

        self.connection.commit()


    # ========================================================
    # RECORD PATTERN VERIFICATION RESULT
    # ========================================================

    def record_verification_result(
        self,
        pattern_id,
        success
    ):

        pattern = self.get_pattern(
            pattern_id
        )

        if pattern is None:

            return None


        successful_containments = pattern[
            "successful_containments"
        ]

        failed_containments = pattern[
            "failed_containments"
        ]


        if success:

            successful_containments += 1

        else:

            failed_containments += 1


        self.cursor.execute(
            """
            UPDATE threat_patterns

            SET
                successful_containments = ?,
                failed_containments = ?

            WHERE pattern_id = ?
            """,

            (
                successful_containments,
                failed_containments,
                pattern_id
            )
        )

        self.connection.commit()


        return self.get_pattern(
            pattern_id
        )


    # ========================================================
    # RECORD COMPLETE VERIFICATION
    # ========================================================

    def record_containment_verification(
        self,
        event_id,
        pattern_id,
        success
    ):

        # ----------------------------------------------------
        # UPDATE INDIVIDUAL EVENT
        # ----------------------------------------------------

        self.update_containment_verification(
            event_id=event_id,
            verified=success
        )


        # ----------------------------------------------------
        # UPDATE PERSISTENT PATTERN HISTORY
        # ----------------------------------------------------

        updated_pattern = (
            self.record_verification_result(
                pattern_id=pattern_id,
                success=success
            )
        )


        return {

            "event_id":
                event_id,

            "pattern_id":
                pattern_id,

            "verified":
                bool(success),

            "pattern":
                updated_pattern
        }


    # ========================================================
    # GET RECENT EVENTS
    # ========================================================

    def get_recent_events(
        self,
        limit=10
    ):

        self.cursor.execute(
            """
            SELECT *
            FROM threat_events

            ORDER BY id DESC

            LIMIT ?
            """,

            (
                int(limit),
            )
        )

        rows = self.cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]


    # ========================================================
    # GET ALL PATTERNS
    # ========================================================

    def get_all_patterns(
        self
    ):

        self.cursor.execute(
            """
            SELECT *
            FROM threat_patterns

            ORDER BY occurrence_count DESC
            """
        )

        rows = self.cursor.fetchall()

        return [
            dict(row)
            for row in rows
        ]


    # ========================================================
    # MEMORY STATISTICS
    # ========================================================

    def get_statistics(
        self
    ):

        # ----------------------------------------------------
        # TOTAL EVENTS
        # ----------------------------------------------------

        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM threat_events
            """
        )

        total_events = self.cursor.fetchone()[0]


        # ----------------------------------------------------
        # TOTAL PATTERNS
        # ----------------------------------------------------

        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM threat_patterns
            """
        )

        total_patterns = self.cursor.fetchone()[0]


        # ----------------------------------------------------
        # REPEATED PATTERNS
        # ----------------------------------------------------

        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM threat_patterns
            WHERE occurrence_count > 1
            """
        )

        repeated_patterns = self.cursor.fetchone()[0]


        # ----------------------------------------------------
        # SUCCESSFUL CONTAINMENTS
        # ----------------------------------------------------

        self.cursor.execute(
            """
            SELECT
                COALESCE(
                    SUM(successful_containments),
                    0
                )
            FROM threat_patterns
            """
        )

        successful_containments = (
            self.cursor.fetchone()[0]
        )


        # ----------------------------------------------------
        # FAILED CONTAINMENTS
        # ----------------------------------------------------

        self.cursor.execute(
            """
            SELECT
                COALESCE(
                    SUM(failed_containments),
                    0
                )
            FROM threat_patterns
            """
        )

        failed_containments = (
            self.cursor.fetchone()[0]
        )


        # ----------------------------------------------------
        # VERIFIED EVENT CONTAINMENTS
        # ----------------------------------------------------

        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM threat_events
            WHERE containment_verified = 1
            """
        )

        verified_events = (
            self.cursor.fetchone()[0]
        )


        # ----------------------------------------------------
        # RECOVERY AUDIT EVENTS
        # ----------------------------------------------------

        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM recovery_audit
            """
        )

        recovery_audit_events = (
            self.cursor.fetchone()[0]
        )


        # ----------------------------------------------------
        # VERIFIED RECOVERIES
        # ----------------------------------------------------

        self.cursor.execute(
            """
            SELECT COUNT(*)
            FROM recovery_audit
            WHERE recovery_verified = 1
            """
        )

        verified_recoveries = (
            self.cursor.fetchone()[0]
        )


        return {

            "total_events":
                total_events,

            "total_patterns":
                total_patterns,

            "repeated_patterns":
                repeated_patterns,

            "successful_containments":
                successful_containments,

            "failed_containments":
                failed_containments,

            "verified_events":
                verified_events,

            "recovery_audit_events":
                recovery_audit_events,

            "verified_recoveries":
                verified_recoveries
        }


    # ========================================================
    # ENDPOINT HEALING AUDIT
    # ========================================================
    #
    # Created lazily so that opening an existing (historical)
    # database never alters its schema unless endpoint healing
    # results are actually stored in it.
    #
    # ========================================================

    def _ensure_endpoint_table(self):

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS endpoint_healing_audit (

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

            )
            """
        )

        self.connection.commit()


    def store_endpoint_healing(
        self,
        run_id,
        trigger_event_id,
        report,
        final_healing_action
    ):

        self._ensure_endpoint_table()

        summary = report.get("integrity_summary", {})

        self.cursor.execute(
            """
            INSERT INTO endpoint_healing_audit (
                incident_id, timestamp, run_id, trigger_event_id,
                host_id, scenario, recovery_status, verified,
                files_checked, files_failed, quarantined, restored,
                persistence_removed, final_healing_action,
                failure_reasons, report_path, evaluation_mode
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                report["incident_id"],
                self._timestamp(),
                run_id,
                trigger_event_id,
                report["host_id"],
                report.get("scenario"),
                report["recovery_status"],
                int(bool(report["verified"])),
                summary.get("files_checked", 0),
                summary.get("files_failed", 0),
                len(report.get("quarantine_actions", [])),
                sum(
                    1 for a in report.get("restoration_actions", [])
                    if a.get("restored")
                ),
                len(report.get("persistence_removed", [])),
                final_healing_action,
                json.dumps(report.get("failure_reasons", [])),
                report.get("report_path"),
                "CONTROLLED_ENDPOINT_SIMULATION"
            )
        )

        self.connection.commit()


    def get_endpoint_healing_audits(self):

        self._ensure_endpoint_table()

        self.cursor.execute(
            "SELECT * FROM endpoint_healing_audit ORDER BY id ASC"
        )

        return [dict(row) for row in self.cursor.fetchall()]


    # ========================================================
    # MULTI-STAGE APT CAMPAIGN MEMORY (simulation)
    # ========================================================
    #
    # Links the stages of one simulated campaign across hosts and
    # remembers indicators of compromise (IOC hashes), so a second
    # host's artefact can be recognised as already known.
    # Created lazily, like endpoint_healing_audit.
    #
    # ========================================================

    def _ensure_apt_tables(self):

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS apt_campaigns (
                campaign_id TEXT PRIMARY KEY,
                run_id TEXT,
                first_seen TEXT NOT NULL,
                trigger_event_id TEXT,
                hosts TEXT,
                stage_count INTEGER DEFAULT 0,
                verdict TEXT,
                evaluation_mode TEXT NOT NULL
            )
            """
        )

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS apt_campaign_events (
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
            )
            """
        )

        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS apt_iocs (
                campaign_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                first_host TEXT NOT NULL,
                hosts_seen TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                PRIMARY KEY (campaign_id, sha256)
            )
            """
        )

        self.connection.commit()


    def create_campaign(self, campaign_id, run_id, trigger_event_id):

        self._ensure_apt_tables()

        self.cursor.execute(
            "INSERT INTO apt_campaigns (campaign_id, run_id, first_seen, "
            "trigger_event_id, hosts, stage_count, verdict, evaluation_mode) "
            "VALUES (?, ?, ?, ?, '', 0, 'ACTIVE', ?)",
            (campaign_id, run_id, self._timestamp(), trigger_event_id,
             "CONTROLLED_APT_SIMULATION")
        )

        self.connection.commit()


    def store_campaign_event(self, campaign_id, seq, tactic_id, tactic,
                             host_id, artifact, artifact_sha256,
                             description):

        self._ensure_apt_tables()

        self.cursor.execute(
            "INSERT INTO apt_campaign_events (campaign_id, seq, timestamp, "
            "tactic_id, tactic, host_id, artifact, artifact_sha256, "
            "description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (campaign_id, seq, self._timestamp(), tactic_id, tactic,
             host_id, artifact, artifact_sha256, description)
        )

        row = self.cursor.execute(
            "SELECT hosts FROM apt_campaigns WHERE campaign_id = ?",
            (campaign_id,)
        ).fetchone()

        hosts = [h for h in (row["hosts"] or "").split(",") if h]
        if host_id not in hosts:
            hosts.append(host_id)

        self.cursor.execute(
            "UPDATE apt_campaigns SET hosts = ?, stage_count = stage_count + 1 "
            "WHERE campaign_id = ?",
            (",".join(hosts), campaign_id)
        )

        self.connection.commit()


    def record_ioc(self, campaign_id, sha256, host_id):
        """
        Remember an IOC hash. Returns the hosts on which it had already
        been seen BEFORE this observation (empty list = new IOC).
        """

        self._ensure_apt_tables()

        row = self.cursor.execute(
            "SELECT hosts_seen FROM apt_iocs WHERE campaign_id = ? AND sha256 = ?",
            (campaign_id, sha256)
        ).fetchone()

        if row is None:
            self.cursor.execute(
                "INSERT INTO apt_iocs (campaign_id, sha256, first_host, "
                "hosts_seen, first_seen) VALUES (?, ?, ?, ?, ?)",
                (campaign_id, sha256, host_id, host_id, self._timestamp())
            )
            self.connection.commit()
            return []

        previous = [h for h in row["hosts_seen"].split(",") if h]

        if host_id not in previous:
            self.cursor.execute(
                "UPDATE apt_iocs SET hosts_seen = ? "
                "WHERE campaign_id = ? AND sha256 = ?",
                (",".join(previous + [host_id]), campaign_id, sha256)
            )
            self.connection.commit()

        return [h for h in previous if h != host_id]


    def set_campaign_verdict(self, campaign_id, verdict):

        self._ensure_apt_tables()

        self.cursor.execute(
            "UPDATE apt_campaigns SET verdict = ? WHERE campaign_id = ?",
            (verdict, campaign_id)
        )

        self.connection.commit()


    def get_campaign(self, campaign_id):

        self._ensure_apt_tables()

        campaign = self.cursor.execute(
            "SELECT * FROM apt_campaigns WHERE campaign_id = ?",
            (campaign_id,)
        ).fetchone()

        if campaign is None:
            return None

        events = self.cursor.execute(
            "SELECT * FROM apt_campaign_events WHERE campaign_id = ? "
            "ORDER BY seq",
            (campaign_id,)
        ).fetchall()

        iocs = self.cursor.execute(
            "SELECT * FROM apt_iocs WHERE campaign_id = ?",
            (campaign_id,)
        ).fetchall()

        return {
            "campaign": dict(campaign),
            "events": [dict(e) for e in events],
            "iocs": [dict(i) for i in iocs],
        }


    # ========================================================
    # CLOSE DATABASE
    # ========================================================

    def close(
        self
    ):

        self.connection.close()