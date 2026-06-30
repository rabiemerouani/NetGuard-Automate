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
    



