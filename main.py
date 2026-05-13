from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import sqlite3
from datetime import datetime, timedelta
import qrcode
import os

USERNAME = os.getenv("ADMIN_USERNAME", "admin")
PASSWORD = os.getenv("ADMIN_PASSWORD", "1234")
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")
DB_PATH = os.getenv("DB_PATH", "database.db")

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def add_column_if_missing(cursor, table, column, definition):
    cursor.execute(f"PRAGMA table_info({table})")
    existing = [row[1] for row in cursor.fetchall()]
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        item TEXT,
        amount REAL,
        datetime TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS memberships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        phone TEXT,
        expiry TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        member_id INTEGER,
        name TEXT,
        datetime TEXT,
        muscle_group TEXT,
        note TEXT,
        result TEXT
    )
    """)

    # Safe migration for old database.db files already deployed.
    add_column_if_missing(c, "logs", "member_id", "INTEGER")
    add_column_if_missing(c, "logs", "muscle_group", "TEXT")
    add_column_if_missing(c, "logs", "note", "TEXT")
    add_column_if_missing(c, "logs", "result", "TEXT")

    conn.commit()
    conn.close()


init_db()


def check_auth(request: Request):
    return request.cookies.get("user") == "loggedin"


def nav_auth(request: Request):
    if not check_auth(request):
        return RedirectResponse(url="/login", status_code=303)
    return None


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT 10")
    rows = c.fetchall()
    conn.close()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"transactions": rows}
    )


@app.post("/payment", response_class=HTMLResponse)
def payment(request: Request, name: str = Form(...), phone: str = Form(...), item: str = Form(...)):
    amount = {"Monthly": 1500, "Day Pass": 200, "Drink": 50}[item]
    payment_qr = generate_promptpay_qr(amount)
    return templates.TemplateResponse(
        request=request,
        name="payment.html",
        context={"name": name, "phone": phone, "item": item, "amount": amount, "payment_qr": payment_qr}
    )


@app.post("/pay", response_class=HTMLResponse)
def pay(request: Request, name: str = Form(...), phone: str = Form(...), item: str = Form(...)):
    amount = {"Monthly": 1500, "Day Pass": 200, "Drink": 50}[item]
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        INSERT INTO transactions (name, item, amount, datetime)
        VALUES (?, ?, ?, ?)
    """, (name, item, amount, datetime.now().strftime("%Y-%m-%d %H:%M")))

    qr_path = None

    if item == "Monthly":
        c.execute("SELECT id, expiry FROM memberships WHERE phone=?", (phone,))
        existing = c.fetchone()

        if existing:
            member_id, old_expiry = existing["id"], existing["expiry"]
            old_expiry_date = datetime.strptime(old_expiry, "%Y-%m-%d")
            today = datetime.now()
            if old_expiry_date < today:
                new_expiry = today + timedelta(days=30)
            else:
                new_expiry = old_expiry_date + timedelta(days=30)
            c.execute("UPDATE memberships SET name=?, expiry=? WHERE id=?", (name, new_expiry.strftime("%Y-%m-%d"), member_id))
        else:
            expiry = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
            c.execute("INSERT INTO memberships (name, phone, expiry) VALUES (?, ?, ?)", (name, phone, expiry))
            member_id = c.lastrowid

        qr_path = create_member_qr(member_id)

    conn.commit()
    c.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT 10")
    rows = c.fetchall()
    conn.close()

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"transactions": rows, "message": f"{name} paid for {item}", "qr": qr_path}
    )


def create_member_qr(member_id: int):
    url = f"{BASE_URL}/check/{member_id}"
    img = qrcode.make(url)
    path = f"static/{member_id}.png"
    img.save(path)
    return f"/static/{member_id}.png"


@app.get("/check/{member_id}", response_class=HTMLResponse)
def check_user_form(request: Request, member_id: int):
    """After scanning a member QR, staff lands here and chooses today's workout."""
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, name, phone, expiry FROM memberships WHERE id=?", (member_id,))
    member = c.fetchone()
    conn.close()

    if not member:
        return templates.TemplateResponse(request=request, name="check.html", context={"status": "❌ Not Found", "member": None})

    today = datetime.now().strftime("%Y-%m-%d")
    valid = member["expiry"] >= today
    status = "✅ Valid Membership" if valid else "❌ Expired"

    return templates.TemplateResponse(
        request=request,
        name="check.html",
        context={"status": status, "member": member, "valid": valid, "saved": False}
    )


@app.post("/check/{member_id}", response_class=HTMLResponse)
def save_checkin(request: Request, member_id: int, muscle_group: str = Form(""), note: str = Form("")):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, name, phone, expiry FROM memberships WHERE id=?", (member_id,))
    member = c.fetchone()

    if not member:
        conn.close()
        return templates.TemplateResponse(request=request, name="check.html", context={"status": "❌ Not Found", "member": None})

    today = datetime.now().strftime("%Y-%m-%d")
    valid = member["expiry"] >= today

    if valid:
        c.execute("""
            INSERT INTO logs (member_id, name, datetime, muscle_group, note, result)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            member_id,
            member["name"],
            datetime.now().strftime("%Y-%m-%d %H:%M"),
            muscle_group,
            note,
            "valid"
        ))
        conn.commit()
        status = "✅ ACCESS GRANTED"
        saved = True
    else:
        c.execute("""
            INSERT INTO logs (member_id, name, datetime, muscle_group, note, result)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (member_id, member["name"], datetime.now().strftime("%Y-%m-%d %H:%M"), muscle_group, note, "expired"))
        conn.commit()
        status = "❌ EXPIRED"
        saved = False

    conn.close()
    return templates.TemplateResponse(
        request=request,
        name="check.html",
        context={"status": status, "member": member, "valid": valid, "saved": saved}
    )


@app.get("/members", response_class=HTMLResponse)
def members(request: Request):
    auth = nav_auth(request)
    if auth: return auth

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, name, phone, expiry FROM memberships ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()

    today = datetime.now()
    soon = today + timedelta(days=3)
    members_list = []
    for m in rows:
        expiry = datetime.strptime(m["expiry"], "%Y-%m-%d")
        if expiry < today:
            status = "expired"
        elif expiry <= soon:
            status = "soon"
        else:
            status = "valid"
        members_list.append({"id": m["id"], "name": m["name"], "phone": m["phone"], "expiry": m["expiry"], "status": status})

    return templates.TemplateResponse(request=request, name="members.html", context={"members": members_list})


@app.get("/member/{member_id}", response_class=HTMLResponse)
def member_detail(request: Request, member_id: int):
    auth = nav_auth(request)
    if auth: return auth

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, name, phone, expiry FROM memberships WHERE id=?", (member_id,))
    member = c.fetchone()

    if not member:
        conn.close()
        return RedirectResponse(url="/members", status_code=303)

    c.execute("""
        SELECT datetime, muscle_group, note, result
        FROM logs
        WHERE member_id=?
        ORDER BY id DESC
    """, (member_id,))
    workout_logs = c.fetchall()

    # Backward compatibility: if old logs have no member_id, also match by name.
    if not workout_logs:
        c.execute("""
            SELECT datetime, muscle_group, note, result
            FROM logs
            WHERE name=?
            ORDER BY id DESC
        """, (member["name"],))
        workout_logs = c.fetchall()

    total_visits = len([x for x in workout_logs if (x["result"] or "valid") == "valid"])
    last_visit = workout_logs[0]["datetime"] if workout_logs else None
    conn.close()

    return templates.TemplateResponse(
        request=request,
        name="member_detail.html",
        context={"member": member, "logs": workout_logs, "total_visits": total_visits, "last_visit": last_visit}
    )


@app.get("/regenerate/{member_id}", response_class=HTMLResponse)
def regenerate(request: Request, member_id: int):
    auth = nav_auth(request)
    if auth: return auth
    qr_path = create_member_qr(member_id)
    return templates.TemplateResponse(request=request, name="entry.html", context={"qr": qr_path})


@app.post("/renew/{member_id}")
def renew(request: Request, member_id: int):
    auth = nav_auth(request)
    if auth: return auth

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT expiry FROM memberships WHERE id=?", (member_id,))
    row = c.fetchone()
    today = datetime.now()
    if row:
        expiry = datetime.strptime(row["expiry"], "%Y-%m-%d")
        new_expiry = today + timedelta(days=30) if expiry < today else expiry + timedelta(days=30)
        c.execute("UPDATE memberships SET expiry=? WHERE id=?", (new_expiry.strftime("%Y-%m-%d"), member_id))
        conn.commit()
    conn.close()
    return RedirectResponse(url="/members", status_code=303)


@app.get("/scan", response_class=HTMLResponse)
def scan(request: Request):
    auth = nav_auth(request)
    if auth: return auth
    return templates.TemplateResponse(request=request, name="scan.html", context={})


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={})


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    if username == USERNAME and password == PASSWORD:
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(key="user", value="loggedin", httponly=True, samesite="lax")
        return response
    return RedirectResponse(url="/login", status_code=303)


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("user")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    auth = nav_auth(request)
    if auth: return auth

    conn = get_conn()
    c = conn.cursor()
    today = datetime.now().strftime("%Y-%m-%d")
    c.execute("SELECT SUM(amount) FROM transactions WHERE datetime LIKE ?", (f"{today}%",))
    revenue = c.fetchone()[0] or 0
    c.execute("SELECT COUNT(*) FROM transactions")
    total_tx = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM memberships WHERE expiry >= ?", (today,))
    active_members = c.fetchone()[0]
    conn.close()
    return templates.TemplateResponse(request=request, name="dashboard.html", context={"revenue": revenue, "total_tx": total_tx, "active_members": active_members})


@app.get("/logs", response_class=HTMLResponse)
def logs(request: Request):
    auth = nav_auth(request)
    if auth: return auth
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT name, datetime, muscle_group, note, result FROM logs ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return templates.TemplateResponse(request=request, name="logs.html", context={"logs": rows})


@app.get("/analytics", response_class=HTMLResponse)
def analytics(request: Request):
    auth = nav_auth(request)
    if auth: return auth
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT substr(datetime, 1, 10) as date, COUNT(*)
        FROM logs
        WHERE result='valid' OR result IS NULL
        GROUP BY date
        ORDER BY date DESC
        LIMIT 7
    """)
    rows = c.fetchall()
    conn.close()
    rows.reverse()
    dates = [r[0] for r in rows]
    counts = [r[1] for r in rows]
    return templates.TemplateResponse(request=request, name="analytics.html", context={"dates": dates, "counts": counts})


def generate_promptpay_qr(amount):
    promptpay_id = os.getenv("PROMPTPAY_ID", "091")
    data = f"PAY:{promptpay_id}:{amount}"
    img = qrcode.make(data)
    path = "static/payment.png"
    img.save(path)
    return "/static/payment.png"


@app.get("/phone-check", response_class=HTMLResponse)
def phone_check_page(request: Request):
    return templates.TemplateResponse(request=request, name="phone_check.html", context={})


@app.post("/phone-check", response_class=HTMLResponse)
def phone_check(request: Request, phone: str = Form(...)):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT name, expiry FROM memberships WHERE phone=?", (phone,))
    row = c.fetchone()
    conn.close()
    if not row:
        return templates.TemplateResponse(request=request, name="phone_check.html", context={"result": "❌ Not Found"})
    name, expiry = row["name"], row["expiry"]
    today = datetime.now().strftime("%Y-%m-%d")
    status = "✅ Valid Membership" if expiry >= today else "❌ Expired"
    return templates.TemplateResponse(request=request, name="phone_check.html", context={"result": status, "name": name})


@app.get("/api/check-phone")
def api_check_phone(phone: str):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT name, expiry FROM memberships WHERE phone=?", (phone,))
    row = c.fetchone()
    conn.close()
    if not row:
        return JSONResponse({"status": "not_found"})
    today = datetime.now().strftime("%Y-%m-%d")
    if row["expiry"] >= today:
        return JSONResponse({"status": "valid", "name": row["name"]})
    return JSONResponse({"status": "expired", "name": row["name"]})


@app.get("/test")
def test():
    return "ok"
