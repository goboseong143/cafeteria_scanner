"""Password recovery using a code the signed-in user chooses."""
import secrets
import time

from flask import make_response, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


MIN_RECOVERY_CODE_LENGTH = 6


def install_recovery(app, limiter, get_db, password_matches):
    dummy_digest = generate_password_hash(secrets.token_urlsafe(32))

    def screen(mode, message="", status=200):
        if "recovery_csrf" not in session:
            session["recovery_csrf"] = secrets.token_urlsafe(32)
        response = make_response(render_template("recovery.html", mode=mode, message=message,
                                                 csrf=session["recovery_csrf"],
                                                 code_minimum=MIN_RECOVERY_CODE_LENGTH), status)
        response.headers["Cache-Control"] = "no-store"
        return response

    def valid_form():
        expected = session.get("recovery_csrf")
        return expected and secrets.compare_digest(expected.encode(), request.form.get("csrf", "").encode())

    @app.route("/account/recovery-code", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def recovery_settings():
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        if request.method == "GET":
            return screen("setup")
        if not valid_form():
            return screen("setup", "페이지를 새로 열어 다시 시도해 주세요.", 403)
        password = request.form.get("password", "")
        code = request.form.get("code", "")
        if not MIN_RECOVERY_CODE_LENGTH <= len(code) <= 128 or not code.strip() or code in (password, session["username"]):
            return screen("setup", f"아이디·비밀번호와 다른 {MIN_RECOVERY_CODE_LENGTH}~128자의 복구 코드를 입력해 주세요.", 400)
        if code != request.form.get("confirm", ""):
            return screen("setup", "두 복구 코드가 일치하지 않습니다.", 400)
        with get_db() as conn:
            row = conn.execute("SELECT password FROM users WHERE id=?", (session["user_id"],)).fetchone()
            if not row or not password_matches(row[0], password):
                return screen("setup", "현재 비밀번호를 확인해 주세요.", 400)
            # A concurrent password reset must also invalidate pending setup requests.
            changed = conn.execute("""
                INSERT INTO recovery_codes (user_id, digest, revision)
                SELECT id, ?, ? FROM users WHERE id=? AND password=?
                ON CONFLICT(user_id) DO UPDATE SET digest=excluded.digest, revision=excluded.revision
            """, (generate_password_hash(code), secrets.token_hex(24), session["user_id"], row[0]))
            if changed.rowcount != 1:
                return redirect(url_for("login_page"))
        return redirect(url_for("recovery_saved"), code=303)

    @app.get("/account/recovery-code/saved")
    def recovery_saved():
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        return screen("saved")

    @app.route("/forgot-password", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    @limiter.limit("8 per hour", methods=["POST"], key_func=lambda: request.form.get("username", "").strip()[:20])
    def forgot_password():
        if request.method == "GET":
            return screen("verify")
        if not valid_form():
            return screen("verify", "페이지를 새로 열어 다시 시도해 주세요.", 403)
        session.pop("reset_grant", None)
        username = request.form.get("username", "").strip()
        code = request.form.get("code", "")
        with get_db() as conn:
            row = conn.execute("""
                SELECT u.id, r.digest, r.revision FROM users u
                JOIN recovery_codes r ON r.user_id=u.id WHERE u.username=?
            """, (username,)).fetchone()
        valid = MIN_RECOVERY_CODE_LENGTH <= len(code) <= 128 and check_password_hash(row["digest"] if row else dummy_digest, code)
        if not valid or not row:
            return screen("verify", "아이디와 복구 코드를 확인해 주세요.", 400)
        session["reset_grant"] = {"id": row["id"], "revision": row["revision"], "expires": time.time() + 300}
        return redirect(url_for("reset_password"), code=303)

    @app.route("/reset-password", methods=["GET", "POST"])
    @limiter.limit("8 per minute", methods=["POST"])
    def reset_password():
        grant = session.get("reset_grant")
        if not grant or grant["expires"] <= time.time():
            session.pop("reset_grant", None)
            return redirect(url_for("forgot_password"))
        if request.method == "GET":
            return screen("reset")
        if not valid_form():
            return screen("reset", "페이지를 새로 열어 다시 시도해 주세요.", 403)
        password = request.form.get("password", "")
        if not 4 <= len(password) <= 128 or password != request.form.get("confirm", ""):
            return screen("reset", "새 비밀번호와 확인 값을 확인해 주세요.", 400)
        with get_db() as conn:
            # Consumption and password update commit together. Other grants for this code expire too.
            changed = conn.execute("DELETE FROM recovery_codes WHERE user_id=? AND revision=?",
                                   (grant["id"], grant["revision"]))
            if changed.rowcount != 1:
                session.pop("reset_grant", None)
                return screen("verify", "복구 코드를 다시 확인해 주세요.", 400)
            conn.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(password), grant["id"]))
        session.clear()
        return screen("done")
