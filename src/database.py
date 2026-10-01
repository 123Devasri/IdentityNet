import os
import sqlite3
import hashlib
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../database/identitynet.db"))

def hash_password(password: str) -> str:
    """Hash password using PBKDF2 with SHA-256."""
    salt = b"identitynet_salt_2026"
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000).hex()

class DatabaseManager:
    """
    SQLite Database Manager for IdentityNet.
    Manages participants, sessions, network events, contest questions, and submissions.
    """
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = os.path.abspath(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Initialize database schema and seed default data if empty."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Participants table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS participants (
                    participant_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    participant_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    logout_time TIMESTAMP,
                    status TEXT DEFAULT 'ONLINE',
                    FOREIGN KEY (participant_id) REFERENCES participants(participant_id)
                );
            """)

            # Network events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    client_ip TEXT NOT NULL,
                    participant_id TEXT,
                    destination TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT
                );
            """)

            # Questions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS questions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    sample_input TEXT,
                    sample_output TEXT,
                    points INTEGER DEFAULT 100
                );
            """)

            # Submissions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    participant_id TEXT NOT NULL,
                    question_id INTEGER NOT NULL,
                    code TEXT NOT NULL,
                    status TEXT DEFAULT 'ACCEPTED',
                    FOREIGN KEY (participant_id) REFERENCES participants(participant_id),
                    FOREIGN KEY (question_id) REFERENCES questions(id)
                );
            """)

            conn.commit()
            self._seed_default_data(cursor)
            conn.commit()

    def _seed_default_data(self, cursor: sqlite3.Cursor):
        """Seed sample participants and contest questions if none exist."""
        cursor.execute("SELECT COUNT(*) FROM participants;")
        if cursor.fetchone()[0] == 0:
            sample_users = [
                ("P001", "Alice Johnson", hash_password("pass123")),
                ("P002", "Bob Smith", hash_password("pass123")),
                ("P003", "Charlie Brown", hash_password("pass123")),
                ("P004", "Diana Prince", hash_password("pass123")),
            ]
            cursor.executemany("INSERT INTO participants (participant_id, name, password_hash) VALUES (?, ?, ?);", sample_users)

        cursor.execute("SELECT COUNT(*) FROM questions;")
        if cursor.fetchone()[0] == 0:
            sample_questions = [
                ("Problem A: Sum of Evens", "Write a program that takes an integer N and returns the sum of all even numbers from 1 to N.", "10", "30", 100),
                ("Problem B: Palindrome Checker", "Given a string S, return 'YES' if S is a palindrome (ignoring spaces), otherwise return 'NO'.", "race car", "YES", 150),
                ("Problem C: Fibonacci Sequence", "Given N, return the N-th number in the Fibonacci sequence starting with F(0)=0, F(1)=1.", "7", "13", 200)
            ]
            cursor.executemany("INSERT INTO questions (title, description, sample_input, sample_output, points) VALUES (?, ?, ?, ?, ?);", sample_questions)

    def authenticate_participant(self, participant_id: str, password: str) -> Optional[Dict[str, Any]]:
        """Verify participant ID and password."""
        hashed = hash_password(password)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT participant_id, name FROM participants WHERE participant_id = ? AND password_hash = ?;", (participant_id, hashed))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def create_session(self, participant_id: str, ip_address: str, mac_address: Optional[str] = None) -> str:
        """Create a new participant login session and return session_id."""
        session_id = str(uuid.uuid4())
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Set any existing online session for this IP to OFFLINE
            cursor.execute("UPDATE sessions SET status = 'OFFLINE', logout_time = CURRENT_TIMESTAMP WHERE ip_address = ? AND status = 'ONLINE';", (ip_address,))
            # Insert new active session
            cursor.execute(
                "INSERT INTO sessions (session_id, participant_id, ip_address, mac_address, status) VALUES (?, ?, ?, ?, 'ONLINE');",
                (session_id, participant_id, ip_address, mac_address or "00:00:00:00:00:00")
            )
            conn.commit()
        return session_id

    def get_session_by_id(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Fetch session data by session ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.session_id, s.participant_id, s.ip_address, s.mac_address, s.login_time, s.status, p.name
                FROM sessions s
                JOIN participants p ON s.participant_id = p.participant_id
                WHERE s.session_id = ? AND s.status = 'ONLINE';
            """, (session_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def get_participant_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Lookup active participant by IP address."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.participant_id, p.name, s.ip_address, s.mac_address
                FROM sessions s
                JOIN participants p ON s.participant_id = p.participant_id
                WHERE s.ip_address = ? AND s.status = 'ONLINE'
                ORDER BY s.login_time DESC LIMIT 1;
            """, (ip_address,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Fetch list of all currently active/online participants."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT s.participant_id, p.name, s.ip_address, s.mac_address, s.login_time, s.status
                FROM sessions s
                JOIN participants p ON s.participant_id = p.participant_id
                WHERE s.status = 'ONLINE'
                ORDER BY s.login_time DESC;
            """)
            return [dict(row) for row in cursor.fetchall()]

    def log_network_event(self, client_ip: str, destination: str, action: str, reason: str = ""):
        """Log a network access event (ALLOW/BLOCK)."""
        participant = self.get_participant_by_ip(client_ip)
        participant_id = participant["participant_id"] if participant else "Unauthenticated"
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO network_events (client_ip, participant_id, destination, action, reason)
                VALUES (?, ?, ?, ?, ?);
            """, (client_ip, participant_id, destination, action, reason))
            conn.commit()

    def get_recent_network_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recent network events for Admin Dashboard."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, client_ip, participant_id, destination, action, reason
                FROM network_events
                ORDER BY id DESC LIMIT ?;
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_questions(self) -> List[Dict[str, Any]]:
        """Fetch all contest questions."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, description, sample_input, sample_output, points FROM questions ORDER BY id ASC;")
            return [dict(row) for row in cursor.fetchall()]

    def record_submission(self, participant_id: str, question_id: int, code: str) -> Dict[str, Any]:
        """Record code submission for a question."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO submissions (participant_id, question_id, code, status)
                VALUES (?, ?, ?, 'ACCEPTED');
            """, (participant_id, question_id, code))
            conn.commit()
            sub_id = cursor.lastrowid
            cursor.execute("SELECT * FROM submissions WHERE id = ?;", (sub_id,))
            return dict(cursor.fetchone())
