from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from email.message import EmailMessage
import smtplib
import secrets
import random
import datetime
import re
import os
import threading


SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SECRET_KEY = os.environ.get("SECRET_KEY")

BASE_URL = "https://satshe.com"

app = Flask(__name__)
app.secret_key = SECRET_KEY or "dev-fallback-secret-key-change-me"


def get_conn():
    return sqlite3.connect("users.db")


def init_db():
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email_verified INTEGER NOT NULL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


def send_email(to_email, subject, content):
    if not SMTP_USER or not SMTP_PASS:
        raise RuntimeError("SMTP 环境变量未配置完整")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content(content)

    # 加 timeout，避免 SMTP 长时间卡死 worker
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)


def send_email_async(to_email, subject, content):
    def worker():
        try:
            send_email(to_email, subject, content)
            print(f"[MAIL OK] to={to_email} subject={subject}")
        except Exception as e:
            # 异步发送失败只打日志，不让用户请求卡死
            print(f"[MAIL ERROR] to={to_email} subject={subject} error={repr(e)}")

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()


def now_iso():
    return datetime.datetime.now().isoformat()


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_valid_email(email):
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return re.match(pattern, email) is not None


def validate_table_name(table_name):
    allowed = {"email_codes", "password_resets"}
    if table_name not in allowed:
        raise ValueError("非法表名")
    return table_name


def get_latest_row(cursor, table_name, email):
    table_name = validate_table_name(table_name)
    cursor.execute(f"""
        SELECT id, created_at
        FROM {table_name}
        WHERE email = ?
        ORDER BY id DESC
        LIMIT 1
    """, (email,))
    return cursor.fetchone()


def count_recent_by_email(cursor, table_name, email, after_time):
    table_name = validate_table_name(table_name)
    cursor.execute(f"""
        SELECT COUNT(*)
        FROM {table_name}
        WHERE email = ? AND created_at >= ?
    """, (email, after_time))
    return cursor.fetchone()[0]


def count_recent_by_ip(cursor, table_name, ip_address, after_time):
    table_name = validate_table_name(table_name)
    cursor.execute(f"""
        SELECT COUNT(*)
        FROM {table_name}
        WHERE ip_address = ? AND created_at >= ?
    """, (ip_address, after_time))
    return cursor.fetchone()[0]


@app.route("/")
def index():
    if "username" in session:
        return render_template("home.html", username=session["username"])
    return redirect("/login")


@app.route("/send-email-code", methods=["POST"])
def send_email_code():
    email = request.form.get("email", "").strip().lower()
    ip_address = get_client_ip()
    now = datetime.datetime.now()

    # 保留注册页里已填的用户名/邮箱，别让用户刷新后全丢
    session["temp_username"] = request.form.get("username", "").strip()
    session["temp_email"] = email

    if not email:
        flash("请先输入电子邮箱地址", "error")
        return redirect("/register")

    if not is_valid_email(email):
        flash("邮箱格式不正确", "error")
        return redirect("/register")

    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    exists = cursor.fetchone()
    if exists:
        conn.close()
        flash("该邮箱已被注册", "error")
        return redirect("/register")

    latest = get_latest_row(cursor, "email_codes", email)
    if latest:
        _, latest_created_at = latest
        latest_dt = datetime.datetime.fromisoformat(latest_created_at)
        if (now - latest_dt).total_seconds() < 60:
            conn.close()
            flash("该邮箱请求过于频繁，请60秒后再试", "error")
            return redirect("/register")

    day_ago = (now - datetime.timedelta(days=1)).isoformat()
    email_daily_count = count_recent_by_email(cursor, "email_codes", email, day_ago)
    if email_daily_count >= 8:
        conn.close()
        flash("该邮箱今日验证码发送次数已达上限", "error")
        return redirect("/register")

    minute_ago = (now - datetime.timedelta(minutes=1)).isoformat()
    ip_1min_count = count_recent_by_ip(cursor, "email_codes", ip_address, minute_ago)
    if ip_1min_count >= 3:
        conn.close()
        flash("当前网络请求过于频繁，请稍后再试", "error")
        return redirect("/register")

    hour_ago = (now - datetime.timedelta(hours=1)).isoformat()
    ip_1hour_count = count_recent_by_ip(cursor, "email_codes", ip_address, hour_ago)
    if ip_1hour_count >= 20:
        conn.close()
        flash("当前网络发送次数过多，请1小时后再试", "error")
        return redirect("/register")

    cursor.execute("""
        UPDATE email_codes
        SET used = 1
        WHERE email = ? AND used = 0
    """, (email,))

    code = str(random.randint(100000, 999999))
    created_at = now.isoformat()
    expires_at = (now + datetime.timedelta(minutes=5)).isoformat()

    cursor.execute("""
        INSERT INTO email_codes (email, code, expires_at, created_at, ip_address, used)
        VALUES (?, ?, ?, ?, ?, 0)
    """, (email, code, expires_at, created_at, ip_address))

    conn.commit()
    conn.close()

    # 改为异步发邮件，用户立刻返回，不阻塞页面
    send_email_async(
        email,
        "satshe 注册验证码",
        f"你的注册验证码是：{code}\n\n五分钟内有效，请勿泄露给他人。"
    )

    flash("验证码已发送，请检查邮箱", "success")
    return redirect("/register")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        code = request.form.get("code", "").strip()
        agree_terms = request.form.get("agree_terms")

        # 仅保留非敏感字段
        session["temp_username"] = username
        session["temp_email"] = email

        if not username or not email or not password or not confirm_password or not code:
            flash("所有字段都不能为空", "error")
            return redirect("/register")

        if not is_valid_email(email):
            flash("邮箱格式不正确", "error")
            return redirect("/register")

        if len(password) < 6:
            flash("密码长度至少为6个字符", "error")
            return redirect("/register")

        if password != confirm_password:
            flash("两次输入的密码不一致", "error")
            return redirect("/register")

        if not agree_terms:
            flash("请先勾选并同意网站准则", "error")
            return redirect("/register")

        conn = get_conn()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, code, expires_at
            FROM email_codes
            WHERE email = ? AND used = 0
            ORDER BY id DESC
            LIMIT 1
        """, (email,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            flash("请先获取邮箱验证码", "error")
            return redirect("/register")

        code_id, db_code, expires_at = row

        if datetime.datetime.now() > datetime.datetime.fromisoformat(expires_at):
            conn.close()
            flash("验证码已过期，请重新获取", "error")
            return redirect("/register")

        if code != db_code:
            conn.close()
            flash("验证码错误", "error")
            return redirect("/register")

        try:
            cursor.execute("""
                INSERT INTO users (username, email, password, email_verified)
                VALUES (?, ?, ?, 1)
            """, (username, email, generate_password_hash(password)))

            cursor.execute("""
                UPDATE email_codes
                SET used = 1
                WHERE id = ?
            """, (code_id,))

            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("用户名或邮箱已存在", "error")
            return redirect("/register")

        conn.close()
        flash("注册成功，请登录", "success")
        session.pop("temp_username", None)
        session.pop("temp_email", None)
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("邮箱和密码不能为空", "error")
            return redirect("/login")

        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, password
            FROM users
            WHERE email = ?
        """, (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session["username"] = user[0]

            if user[0].lower() == "saturn_shine":
                flash("欢迎回来，Saturn_shine!", "success")
                return redirect("/saturn-shine")

            flash("你已经成功登录。", "success")
            return redirect("/")

        flash("邮箱或密码错误", "error")
        return redirect("/login")

    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        ip_address = get_client_ip()
        now = datetime.datetime.now()

        if not email:
            flash("邮箱不能为空", "error")
            return redirect("/forgot-password")

        if not is_valid_email(email):
            flash("邮箱格式不正确", "error")
            return redirect("/forgot-password")

        conn = get_conn()
        cursor = conn.cursor()

        latest = get_latest_row(cursor, "password_resets", email)
        if latest:
            _, latest_created_at = latest
            latest_dt = datetime.datetime.fromisoformat(latest_created_at)
            if (now - latest_dt).total_seconds() < 120:
                conn.close()
                flash("请求过于频繁，请稍后再试", "error")
                return redirect("/forgot-password")

        day_ago = (now - datetime.timedelta(days=1)).isoformat()
        email_daily_count = count_recent_by_email(cursor, "password_resets", email, day_ago)
        if email_daily_count >= 5:
            conn.close()
            flash("该邮箱今日重置次数已达上限", "error")
            return redirect("/forgot-password")

        hour_ago = (now - datetime.timedelta(hours=1)).isoformat()
        ip_1hour_count = count_recent_by_ip(cursor, "password_resets", ip_address, hour_ago)
        if ip_1hour_count >= 10:
            conn.close()
            flash("当前网络请求过于频繁，请稍后再试", "error")
            return redirect("/forgot-password")

        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            cursor.execute("""
                UPDATE password_resets
                SET used = 1
                WHERE email = ? AND used = 0
            """, (email,))

            token = secrets.token_urlsafe(32)
            created_at = now.isoformat()
            expires_at = (now + datetime.timedelta(minutes=30)).isoformat()

            cursor.execute("""
                INSERT INTO password_resets (email, token, expires_at, created_at, ip_address, used)
                VALUES (?, ?, ?, ?, ?, 0)
            """, (email, token, expires_at, created_at, ip_address))

            conn.commit()
            conn.close()

            reset_link = f"{BASE_URL}/reset-password/{token}"

            # 同样改为异步，不阻塞用户
            send_email_async(
                email,
                "Saturn_shine 重置密码",
                f"请点击下面链接重置密码：\n{reset_link}\n\n该链接30分钟内有效。"
            )
        else:
            conn.close()

        flash("如果该邮箱已注册，我们已发送重置邮件", "success")
        return redirect("/login")

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_conn()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, email, expires_at, used
        FROM password_resets
        WHERE token = ?
        ORDER BY id DESC
        LIMIT 1
    """, (token,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        flash("重置链接无效", "error")
        return redirect("/login")

    reset_id, email, expires_at, used = row

    if used == 1:
        conn.close()
        flash("该重置链接已使用", "error")
        return redirect("/login")

    if datetime.datetime.now() > datetime.datetime.fromisoformat(expires_at):
        conn.close()
        flash("重置链接已过期", "error")
        return redirect("/login")

    if request.method == "POST":
        password = request.form.get("password", "").strip()

        if not password:
            conn.close()
            flash("新密码不能为空", "error")
            return redirect(f"/reset-password/{token}")

        if len(password) < 6:
            conn.close()
            flash("密码长度至少为6个字符", "error")
            return redirect(f"/reset-password/{token}")

        cursor.execute("""
            UPDATE users
            SET password = ?
            WHERE email = ?
        """, (generate_password_hash(password), email))

        cursor.execute("""
            UPDATE password_resets
            SET used = 1
            WHERE id = ?
        """, (reset_id,))

        conn.commit()
        conn.close()

        flash("密码重置成功，请重新登录", "success")
        return redirect("/login")

    conn.close()
    return render_template("reset_password.html")


@app.route("/saturn-shine")
def saturn_shine():
    if session.get("username", "").lower() != "saturn_shine":
        flash("无权访问该页面", "error")
        return redirect("/login")
    return render_template("saturn_shine.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("你已退出登录", "success")
    return redirect("/login")


# 确保无论本地还是 Gunicorn / Render，数据库都存在
init_db()

if __name__ == "__main__":
    app.run(debug=False)