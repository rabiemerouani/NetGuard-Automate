import sqlite3
import json
from datetime import datetime

DB_NAME = "netguard.db"

def get_connection():
    """Helper function to establish a connection to SQLite and return rows as dicts."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Enables accessing columns by name instead of tuple index
    return conn

def init_db():
    """Initializes the database schema by creating the necessary tables if they do not exist."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Create audits tracking table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT NOT NULL,
            device_ip TEXT NOT NULL,
            execution_date TEXT NOT NULL,
            total_vulnerabilities INTEGER NOT NULL
        )
    """)
    
    # 2. Create detailed vulnerabilities table with foreign key constraint
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            issue TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            level INTEGER NOT NULL,
            details TEXT NOT NULL,
            fix TEXT NOT NULL,
            locations TEXT,
            FOREIGN KEY (audit_id) REFERENCES audits(id) ON DELETE CASCADE
        )
    """)
    
    conn.commit()
    conn.close()
    print(" Database initialized successfully.")

def save_audit_result(device_name: str, device_ip: str, vulnerabilities: list) -> int:
    """
    Persists an audit execution record along with all its structural findings into SQLite.
    Returns the auto-generated unique ID of the newly created audit.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_vulns = len(vulnerabilities)
    
    try:
        # 1. Insert the primary audit execution record
        cursor.execute(
            """
            INSERT INTO audits (device_name, device_ip, execution_date, total_vulnerabilities)
            VALUES (?, ?, ?, ?)
            """,
            (device_name, device_ip, current_time, total_vulns)
        )
        
        # Retrieve the auto-incremented ID generated for this audit row
        audit_id = cursor.lastrowid
        
        # 2. Bulk insert all parsed CIS vulnerability findings
        for vuln in vulnerabilities:
            # Safely handle 'locations' field if it exists as a list (transforming it to JSON text string)
            locations_data = json.dumps(vuln.get("locations", [])) if "locations" in vuln else None
            
            cursor.execute(
                """
                INSERT INTO vulnerabilities (
                    audit_id, rule_id, issue, severity, category, level, details, fix, locations
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    vuln.get("id", "UNKNOWN"),  # Maps 'id' field returned from analyzer
                    vuln.get("issue", ""),
                    vuln.get("severity", "MEDIUM"),
                    vuln.get("category", "General"),
                    vuln.get("level", 1),
                    vuln.get("details", ""),
                    vuln.get("fix", ""),
                    locations_data
                )
            )
            
        conn.commit()
        return audit_id
        
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def get_all_audits() -> list:
    """Retrieves high-level summary overview of all scans sorted from newest to oldest."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM audits ORDER BY execution_date DESC")
    rows = cursor.fetchall()
    conn.close()
    
    # Convert sqlite3.Row items into native Python dict lists
    return [dict(row) for row in rows]

def get_audit_with_vulnerabilities(audit_id: int) -> dict:
    """
    Fetches a specific audit tracking record coupled with its list of findings.
    Returns None if the requested audit ID does not exist.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Fetch the audit execution header
    cursor.execute("SELECT * FROM audits WHERE id = ?", (audit_id,))
    audit_row = cursor.fetchone()
    
    if not audit_row:
        conn.close()
        return None
        
    audit_data = dict(audit_row)
    
    # 2. Fetch all matching sub-records from vulnerabilities table
    cursor.execute("SELECT * FROM vulnerabilities WHERE audit_id = ?", (audit_id,))
    vuln_rows = cursor.fetchall()
    conn.close()
    
    vulnerabilities = []
    for row in vuln_rows:
        vuln_dict = dict(row)
        # Parse 'locations' column back into native list format if populated
        if vuln_dict.get("locations"):
            try:
                vuln_dict["locations"] = json.loads(vuln_dict["locations"])
            except json.JSONDecodeError:
                pass
        vulnerabilities.append(vuln_dict)
        
    audit_data["findings"] = vulnerabilities
    return audit_data