import sqlite3
import json
from datetime import datetime

DB_NAME = "netguard.db"
def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema by creating the necessary tables if they do not exist."""
    conn = get_connection()
    cursor = conn.cursor()



cursor.execute("""
               
CREATE TABLE IF NOT EXISTS audits (
               id INTEGER PRIMERY KEY AUTOINCREMENT,
               device_name TEXT NOT NULL,
               device_ip TEXT NOT NULL,
               execution_dater TEXT NOT NULL,
               total_vulnerabilities INTEGER NOT NULL
               )
                """)


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

print("Database initialized successfully.")

conn = get_connection()
cursor = conn.cursor()

current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
total_vulns = len(vulnerabilities)

# 1. Insert the primary audit execution record
cursor.execute(
            """
            INSERT INTO audits (device_name, device_ip, execution_date, total_vulnerabilities)
            VALUES (?, ?, ?, ?)
            """,
            (device_name, device_ip, current_time, total_vulns)
        )
