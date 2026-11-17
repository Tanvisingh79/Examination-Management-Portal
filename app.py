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


def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
            if user is None or user["status"] != "active":
                session.clear()
                flash("Your account is not active.", "error")
                return redirect(url_for("login"))
            if role and user["role"] != role:
                flash("You can't open that page.", "error")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.context_processor
def add_user():
    user = None
    if "user_id" in session:
        user = get_db().execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return {"current_user": user}


def get_rubrics():
    # rubric rows grouped by exam id
    rubrics = {}
    for r in get_db().execute("SELECT * FROM rubrics ORDER BY id").fetchall():
        rubrics.setdefault(r["exam_id"], []).append(r)
    return rubrics


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user is None or not check_password_hash(user["password"], password):
            flash("Wrong email or password.", "error")
        elif user["status"] != "active":
            flash("Your account is not approved yet.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        role = request.form["role"]
        if name == "" or email == "" or len(password) < 6 or role not in ("student", "examiner"):
            flash("Please fill everything in. Password needs at least 6 characters.", "error")
            return render_template("register.html")

        # examiners need to be approved by the admin
        status = "active"
        if role == "examiner":
            status = "pending"
        try:
            db = get_db()
            db.execute("INSERT INTO users (name, email, password, role, department, course, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (name, email, generate_password_hash(password, method="pbkdf2:sha256"), role,
                        request.form["department"], request.form["course"], status))
            db.commit()
            flash("Account created.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email is already registered.", "error")
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required()
def dashboard():
    role = get_db().execute("SELECT role FROM users WHERE id = ?", (session["user_id"],)).fetchone()["role"]
    return redirect(url_for(role + "_dashboard"))


# ---------------- admin ----------------

@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    db = get_db()
    q = request.args.get("q", "").strip()
    like = "%" + q + "%"

    courses = db.execute("SELECT c.*, count(e.id) AS exam_count FROM courses c "
                         "LEFT JOIN exams e ON e.course_id = c.id GROUP BY c.id ORDER BY c.code").fetchall()
    exams = db.execute("SELECT e.*, c.code AS course_code FROM exams e "
                       "JOIN courses c ON c.id = e.course_id ORDER BY e.id DESC").fetchall()
    people = db.execute("SELECT * FROM users WHERE role != 'admin' AND "
                        "(name LIKE ? OR email LIKE ? OR CAST(id AS TEXT) LIKE ?) ORDER BY role, name",
                        (like, like, like)).fetchall()
    slots = db.execute("SELECT s.*, e.name AS exam_name, c.code, u.name AS examiner_name, "
                       "(SELECT count(*) FROM bookings WHERE slot_id = s.id AND status = 'booked') AS booked "
                       "FROM slots s JOIN exams e ON e.id = s.exam_id JOIN courses c ON c.id = e.course_id "
                       "JOIN users u ON u.id = s.examiner_id ORDER BY s.date, s.start_time").fetchall()
    bookings = db.execute("SELECT b.*, s.date, s.start_time, s.end_time, e.name AS exam_name, c.code, "
                          "u.name AS student_name, x.name AS examiner_name FROM bookings b "
                          "JOIN slots s ON s.id = b.slot_id JOIN exams e ON e.id = s.exam_id "
                          "JOIN courses c ON c.id = e.course_id JOIN users u ON u.id = b.student_id "
                          "JOIN users x ON x.id = s.examiner_id ORDER BY s.date, s.start_time").fetchall()

    return render_template("admin_dashboard.html", courses=courses, exams=exams, rubrics=get_rubrics(),
                           people=people, slots=slots, bookings=bookings, q=q)


@app.route("/admin/course", methods=["POST"])
@login_required("admin")
def create_course():
    code = request.form["code"].strip().upper()
    name = request.form["name"].strip()
    try:
        db = get_db()
        db.execute("INSERT INTO courses (code, name, description) VALUES (?, ?, ?)",
                   (code, name, request.form["description"].strip()))
        db.commit()
        flash("Course added.", "success")
    except sqlite3.IntegrityError:
        flash("That course code already exists.", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/course/<int:course_id>/edit", methods=["POST"])
@login_required("admin")
def edit_course(course_id):
    try:
        db = get_db()
        db.execute("UPDATE courses SET code = ?, name = ?, description = ? WHERE id = ?",
                   (request.form["code"].strip().upper(), request.form["name"].strip(),
                    request.form["description"].strip(), course_id))
        db.commit()
        flash("Course updated.", "success")
    except sqlite3.IntegrityError:
        flash("That course code already exists.", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/course/<int:course_id>/delete", methods=["POST"])
@login_required("admin")
def delete_course(course_id):
    db = get_db()
    exam = db.execute("SELECT id FROM exams WHERE course_id = ?", (course_id,)).fetchone()
    if exam:
        flash("Delete the exams of this course first.", "error")
    else:
        db.execute("DELETE FROM courses WHERE id = ?", (course_id,))
        db.commit()
        flash("Course deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/exam", methods=["POST"])
@login_required("admin")
def create_exam():
    f = request.form
    try:
        db = get_db()
        db.execute("INSERT INTO exams (course_id, name, type, duration, max_marks, slot_start, slot_end, "
                   "booking_start, booking_end) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (int(f["course_id"]), f["name"].strip(), f["type"], int(f["duration"]), float(f["max_marks"]),
                    f["slot_start"], f["slot_end"], f["booking_start"], f["booking_end"]))
        db.commit()
        flash("Exam created.", "success")
    except (ValueError, KeyError):
        flash("Please check the exam details.", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/exam/<int:exam_id>/edit", methods=["POST"])
@login_required("admin")
def edit_exam(exam_id):
    f = request.form
    try:
        db = get_db()
        db.execute("UPDATE exams SET name = ?, type = ?, duration = ?, max_marks = ?, slot_start = ?, "
                   "slot_end = ?, booking_start = ?, booking_end = ? WHERE id = ?",
                   (f["name"].strip(), f["type"], int(f["duration"]), float(f["max_marks"]),
                    f["slot_start"], f["slot_end"], f["booking_start"], f["booking_end"], exam_id))
        db.commit()
        flash("Exam updated.", "success")
    except (ValueError, KeyError):
        flash("Please check the exam details.", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/exam/<int:exam_id>/status", methods=["POST"])
@login_required("admin")
def exam_status(exam_id):
    status = request.form["status"]
    if status in ("draft", "slot_creation", "booking_open", "closed", "completed"):
        db = get_db()
        db.execute("UPDATE exams SET status = ? WHERE id = ?", (status, exam_id))
        db.commit()
        flash("Status updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/exam/<int:exam_id>/delete", methods=["POST"])
@login_required("admin")
def delete_exam(exam_id):
    db = get_db()
    booking = db.execute("SELECT b.id FROM bookings b JOIN slots s ON s.id = b.slot_id WHERE s.exam_id = ?",
                         (exam_id,)).fetchone()
    if booking:
        flash("This exam already has bookings, so it can't be deleted.", "error")
    else:
        db.execute("DELETE FROM slots WHERE exam_id = ?", (exam_id,))
        db.execute("DELETE FROM rubrics WHERE exam_id = ?", (exam_id,))
        db.execute("DELETE FROM exams WHERE id = ?", (exam_id,))
        db.commit()
        flash("Exam deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/exam/<int:exam_id>/rubric", methods=["POST"])
@login_required("admin")
def add_rubric(exam_id):
    f = request.form
    try:
        db = get_db()
        db.execute("INSERT INTO rubrics (exam_id, criterion, max_marks, weightage, description) VALUES (?, ?, ?, ?, ?)",
                   (exam_id, f["criterion"].strip(), float(f["max_marks"]), float(f["weightage"]), f["description"].strip()))
        db.commit()
        flash("Criterion added.", "success")
    except (ValueError, KeyError):
        flash("Please enter a criterion and a valid max mark.", "error")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/rubric/<int:rubric_id>/delete", methods=["POST"])
@login_required("admin")
def delete_rubric(rubric_id):
    db = get_db()
    used = db.execute("SELECT id FROM evaluation_scores WHERE rubric_id = ?", (rubric_id,)).fetchone()
    if used:
        flash("This criterion was already used in an evaluation.", "error")
    else:
        db.execute("DELETE FROM rubrics WHERE id = ?", (rubric_id,))
        db.commit()
        flash("Criterion deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/<int:user_id>/status", methods=["POST"])
@login_required("admin")
def user_status(user_id):
    status = request.form["status"]
    if status in ("active", "pending", "inactive"):
        db = get_db()
        db.execute("UPDATE users SET status = ? WHERE id = ? AND role != 'admin'", (status, user_id))
        db.commit()
        flash("User updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/booking/<int:booking_id>/reschedule", methods=["POST"])
@login_required("admin")
def reschedule_booking(booking_id):
    db = get_db()
    try:
        new_slot_id = int(request.form["slot_id"])
    except ValueError:
        flash("Enter a slot ID.", "error")
        return redirect(url_for("admin_dashboard"))

    slot = db.execute("SELECT s.*, e.status AS exam_status, u.status AS examiner_status, "
                      "(SELECT count(*) FROM bookings WHERE slot_id = s.id AND status = 'booked') AS booked "
                      "FROM slots s JOIN exams e ON e.id = s.exam_id JOIN users u ON u.id = s.examiner_id "
                      "WHERE s.id = ?", (new_slot_id,)).fetchone()
    booking = db.execute("SELECT b.status, s.exam_id FROM bookings b JOIN slots s ON s.id = b.slot_id "
                         "WHERE b.id = ?", (booking_id,)).fetchone()

    if slot is None or booking is None or booking["status"] != "booked":
        flash("That slot is not available.", "error")
    elif slot["exam_id"] != booking["exam_id"]:
        flash("The new slot must be for the same exam.", "error")
    elif slot["booked"] >= slot["capacity"] or slot["examiner_status"] != "active":
        flash("That slot is not available.", "error")
    elif slot["exam_status"] not in ("booking_open", "closed"):
        flash("That slot is not available.", "error")
    else:
        db.execute("UPDATE bookings SET slot_id = ? WHERE id = ?", (new_slot_id, booking_id))
        db.commit()
        flash("Booking moved.", "success")
    return redirect(url_for("admin_dashboard"))


# ---------------- examiner ----------------

@app.route("/examiner")
@login_required("examiner")
def examiner_dashboard():
    db = get_db()
    me = session["user_id"]

    available = db.execute("SELECT e.*, c.code FROM exams e JOIN courses c ON c.id = e.course_id "
                           "WHERE e.status = 'slot_creation' ORDER BY e.id DESC").fetchall()
    slots = db.execute("SELECT s.*, e.name AS exam_name, e.status AS exam_status, c.code, "
                       "(SELECT count(*) FROM bookings WHERE slot_id = s.id AND status = 'booked') AS booked "
                       "FROM slots s JOIN exams e ON e.id = s.exam_id JOIN courses c ON c.id = e.course_id "
                       "WHERE s.examiner_id = ? ORDER BY s.date, s.start_time", (me,)).fetchall()
    roster = db.execute("SELECT b.id AS booking_id, s.date, s.start_time, e.id AS exam_id, e.name AS exam_name, "
                        "c.code, u.id AS student_id, u.name AS student_name, v.marks, v.remarks FROM bookings b "
                        "JOIN slots s ON s.id = b.slot_id JOIN exams e ON e.id = s.exam_id "
                        "JOIN courses c ON c.id = e.course_id JOIN users u ON u.id = b.student_id "
                        "LEFT JOIN evaluations v ON v.booking_id = b.id "
                        "WHERE s.examiner_id = ? AND b.status IN ('booked', 'completed') "
                        "ORDER BY s.date, s.start_time", (me,)).fetchall()

    return render_template("examiner_dashboard.html", available=available, slots=slots,
                           roster=roster, criteria_by_exam=get_rubrics())


@app.route("/examiner/slot", methods=["POST"])
@login_required("examiner")
def create_slot():
    f = request.form
    try:
        exam_id = int(f["exam_id"])
        capacity = int(f["capacity"])
    except ValueError:
        flash("Please check the slot details.", "error")
        return redirect(url_for("examiner_dashboard"))

    db = get_db()
    exam = db.execute("SELECT id FROM exams WHERE id = ? AND status = 'slot_creation'", (exam_id,)).fetchone()
    if exam is None or capacity < 1 or f["start_time"] >= f["end_time"]:
        flash("Please check the slot details.", "error")
    else:
        db.execute("INSERT INTO slots (exam_id, examiner_id, date, start_time, end_time, capacity) VALUES (?, ?, ?, ?, ?, ?)",
                   (exam_id, session["user_id"], f["date"], f["start_time"], f["end_time"], capacity))
        db.commit()
        flash("Slot created.", "success")
    return redirect(url_for("examiner_dashboard"))


def slot_can_change(slot_id):
    # a slot can only be changed while slots are being created and nobody has booked it
    slot = get_db().execute("SELECT s.id, e.status AS exam_status, "
                            "(SELECT count(*) FROM bookings WHERE slot_id = s.id AND status = 'booked') AS booked "
                            "FROM slots s JOIN exams e ON e.id = s.exam_id "
                            "WHERE s.id = ? AND s.examiner_id = ?", (slot_id, session["user_id"])).fetchone()
    return slot is not None and slot["exam_status"] == "slot_creation" and slot["booked"] == 0


@app.route("/examiner/slot/<int:slot_id>/edit", methods=["POST"])
@login_required("examiner")
def edit_slot(slot_id):
    f = request.form
    try:
        capacity = int(f["capacity"])
    except ValueError:
        capacity = 0

    if not slot_can_change(slot_id) or capacity < 1 or f["start_time"] >= f["end_time"]:
        flash("Can't update this slot.", "error")
    else:
        db = get_db()
        db.execute("UPDATE slots SET date = ?, start_time = ?, end_time = ?, capacity = ? WHERE id = ?",
                   (f["date"], f["start_time"], f["end_time"], capacity, slot_id))
        db.commit()
        flash("Slot updated.", "success")
    return redirect(url_for("examiner_dashboard"))


@app.route("/examiner/slot/<int:slot_id>/delete", methods=["POST"])
@login_required("examiner")
def delete_slot(slot_id):
    if slot_can_change(slot_id):
        db = get_db()
        db.execute("DELETE FROM slots WHERE id = ?", (slot_id,))
        db.commit()
        flash("Slot deleted.", "success")
    else:
        flash("Can't delete this slot.", "error")
    return redirect(url_for("examiner_dashboard"))


@app.route("/examiner/evaluate/<int:booking_id>", methods=["POST"])
@login_required("examiner")
def evaluate(booking_id):
    db = get_db()
    booking = db.execute("SELECT s.examiner_id, s.exam_id, e.max_marks FROM bookings b "
                         "JOIN slots s ON s.id = b.slot_id JOIN exams e ON e.id = s.exam_id "
                         "WHERE b.id = ?", (booking_id,)).fetchone()
    if booking is None or booking["examiner_id"] != session["user_id"]:
        flash("You can't evaluate this booking.", "error")
        return redirect(url_for("examiner_dashboard"))

    rubrics = db.execute("SELECT * FROM rubrics WHERE exam_id = ?", (booking["exam_id"],)).fetchall()
    scores = {}
    total = 0
    try:
        if rubrics:
            # add up the marks of each criterion
            for r in rubrics:
                mark = float(request.form["rubric_" + str(r["id"])])
                if mark < 0 or mark > r["max_marks"]:
                    raise ValueError
                scores[r["id"]] = mark
                total += mark
        else:
            total = float(request.form["marks"])
        if total < 0 or total > booking["max_marks"]:
            raise ValueError
    except (ValueError, KeyError):
        flash("Invalid marks.", "error")
        return redirect(url_for("examiner_dashboard"))

    db.execute("INSERT INTO evaluations (booking_id, marks, remarks) VALUES (?, ?, ?) "
               "ON CONFLICT(booking_id) DO UPDATE SET marks = excluded.marks, remarks = excluded.remarks",
               (booking_id, total, request.form["remarks"].strip()))
    evaluation_id = db.execute("SELECT id FROM evaluations WHERE booking_id = ?", (booking_id,)).fetchone()["id"]
    db.execute("DELETE FROM evaluation_scores WHERE evaluation_id = ?", (evaluation_id,))
    for rubric_id in scores:
        db.execute("INSERT INTO evaluation_scores (evaluation_id, rubric_id, marks) VALUES (?, ?, ?)",
                   (evaluation_id, rubric_id, scores[rubric_id]))
    db.execute("UPDATE bookings SET status = 'completed' WHERE id = ?", (booking_id,))
    db.commit()
    flash("Marks saved.", "success")
    return redirect(url_for("examiner_dashboard"))


# ---------------- student ----------------

@app.route("/student")
@login_required("student")
def student_dashboard():
    db = get_db()
    me = session["user_id"]
    q = request.args.get("q", "").strip()
    like = "%" + q + "%"

    exams = db.execute("SELECT e.*, c.code, c.name AS course_name FROM exams e JOIN courses c ON c.id = e.course_id "
                       "WHERE e.status IN ('booking_open', 'closed', 'completed') "
                       "AND (e.name LIKE ? OR c.name LIKE ? OR c.code LIKE ?) ORDER BY e.id DESC",
                       (like, like, like)).fetchall()

    # slots that are open and still have seats
    slots = db.execute("SELECT s.*, e.name AS exam_name, c.code, c.name AS course_name, u.name AS examiner_name, "
                       "(SELECT count(*) FROM bookings WHERE slot_id = s.id AND status = 'booked') AS booked, "
                       "(SELECT count(*) FROM bookings WHERE student_id = ? AND slot_id = s.id AND status = 'booked') AS mine "
                       "FROM slots s JOIN exams e ON e.id = s.exam_id JOIN courses c ON c.id = e.course_id "
                       "JOIN users u ON u.id = s.examiner_id "
                       "WHERE e.status = 'booking_open' AND s.status = 'available' AND u.status = 'active' "
                       "AND (SELECT count(*) FROM bookings WHERE slot_id = s.id AND status = 'booked') < s.capacity "
                       "ORDER BY s.date, s.start_time", (me,)).fetchall()

    history = db.execute("SELECT b.*, s.date, s.start_time, s.end_time, e.name AS exam_name, e.max_marks, c.code, "
                         "u.name AS examiner_name, v.marks, v.remarks FROM bookings b "
                         "JOIN slots s ON s.id = b.slot_id JOIN exams e ON e.id = s.exam_id "
                         "JOIN courses c ON c.id = e.course_id JOIN users u ON u.id = s.examiner_id "
                         "LEFT JOIN evaluations v ON v.booking_id = b.id WHERE b.student_id = ? "
                         "ORDER BY s.date DESC, s.start_time DESC", (me,)).fetchall()

    return render_template("student_dashboard.html", exams=exams, slots=slots, history=history, q=q)


@app.route("/student/book/<int:slot_id>", methods=["POST"])
@login_required("student")
def book_slot(slot_id):
    db = get_db()
    slot = db.execute("SELECT s.*, e.status AS exam_status, "
                      "(SELECT count(*) FROM bookings WHERE slot_id = s.id AND status = 'booked') AS booked "
                      "FROM slots s JOIN exams e ON e.id = s.exam_id "
                      "WHERE s.id = ? AND s.status = 'available'", (slot_id,)).fetchone()
    if slot is None or slot["exam_status"] != "booking_open":
        flash("This slot is not open for booking.", "error")
        return redirect(url_for("student_dashboard"))
    if slot["booked"] >= slot["capacity"]:
        flash("This slot is full.", "error")
        return redirect(url_for("student_dashboard"))

    # one booking per exam
    already = db.execute("SELECT b.id FROM bookings b JOIN slots s ON s.id = b.slot_id "
                         "WHERE b.student_id = ? AND s.exam_id = ? AND b.status = 'booked'",
                         (session["user_id"], slot["exam_id"])).fetchone()
    if already:
        flash("You already booked this exam.", "error")
        return redirect(url_for("student_dashboard"))

    try:
        db.execute("INSERT INTO bookings (student_id, slot_id) VALUES (?, ?)", (session["user_id"], slot_id))
        db.commit()
        flash("Slot booked.", "success")
    except sqlite3.IntegrityError:
        flash("You already booked this slot.", "error")
    return redirect(url_for("student_dashboard"))


@app.route("/student/cancel/<int:booking_id>", methods=["POST"])
@login_required("student")
def cancel_booking(booking_id):
    db = get_db()
    booking = db.execute("SELECT b.status, e.status AS exam_status FROM bookings b "
                         "JOIN slots s ON s.id = b.slot_id JOIN exams e ON e.id = s.exam_id "
                         "WHERE b.id = ? AND b.student_id = ?", (booking_id, session["user_id"])).fetchone()
    if booking and booking["status"] == "booked" and booking["exam_status"] == "booking_open":
        db.execute("UPDATE bookings SET status = 'cancelled' WHERE id = ?", (booking_id,))
        db.commit()
        flash("Booking cancelled.", "success")
    else:
        flash("You can't cancel this booking.", "error")
    return redirect(url_for("student_dashboard"))


if __name__ == "__main__":
    app.run(debug=True)
