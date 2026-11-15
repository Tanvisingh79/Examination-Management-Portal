import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "emp-secret-key"
DATABASE = os.path.join(app.root_path, "emp.sqlite3")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'examiner', 'student')),
        department TEXT DEFAULT '',
        course TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'active'
    );
    CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS exams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER NOT NULL REFERENCES courses(id),
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        duration INTEGER NOT NULL DEFAULT 30,
        max_marks REAL NOT NULL DEFAULT 100,
        slot_start TEXT DEFAULT '',
        slot_end TEXT DEFAULT '',
        booking_start TEXT DEFAULT '',
        booking_end TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'draft'
    );
    CREATE TABLE IF NOT EXISTS rubrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
        criterion TEXT NOT NULL,
        max_marks REAL NOT NULL,
        weightage REAL NOT NULL DEFAULT 1,
        description TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS slots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        exam_id INTEGER NOT NULL REFERENCES exams(id),
        examiner_id INTEGER NOT NULL REFERENCES users(id),
        date TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT NOT NULL,
        capacity INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'available'
    );
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL REFERENCES users(id),
        slot_id INTEGER NOT NULL REFERENCES slots(id),
        status TEXT NOT NULL DEFAULT 'booked',
        UNIQUE(student_id, slot_id)
    );
    CREATE TABLE IF NOT EXISTS evaluations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_id INTEGER NOT NULL UNIQUE REFERENCES bookings(id),
        marks REAL NOT NULL,
        remarks TEXT DEFAULT '',
        evaluated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS evaluation_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        evaluation_id INTEGER NOT NULL REFERENCES evaluations(id) ON DELETE CASCADE,
        rubric_id INTEGER NOT NULL REFERENCES rubrics(id),
        marks REAL NOT NULL
    );
    """)
    # default admin account
    admin = conn.execute("SELECT id FROM users WHERE role = 'admin'").fetchone()
    if admin is None:
        conn.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
                     ("Admin", "admin@emp.local", generate_password_hash("admin123", method="pbkdf2:sha256"), "admin"))
    conn.commit()
    conn.close()


init_db()

