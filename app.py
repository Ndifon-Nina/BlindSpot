import os
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect

from config import Config
from database import (
    add_finding,
    check_password,
    close_db,
    create_scan,
    create_user,
    get_findings_for_scan,
    get_scan,
    get_scans_for_user,
    get_user_by_email,
    get_user_by_id,
    init_db,
)
from scanner import scan_website


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    csrf = CSRFProtect(app)

    os.makedirs("instance", exist_ok=True)

    with app.app_context():
        init_db()

    app.teardown_appcontext(close_db)

    def login_required(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if "user_id" not in session:
                flash("Please log in to continue.")
                return redirect(url_for("login"))
            return view(**kwargs)

        return wrapped_view

    @app.context_processor
    def inject_session_user():
        user = None
        user_id = session.get("user_id")
        if user_id is not None:
            user = get_user_by_id(user_id)
        return {"current_user": user}

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return response

    @app.route("/")
    def index():
        return render_template("index.html", active_page="home")

    @app.route("/how-it-works")
    def how_it_works():
        return render_template("how_it_works.html", active_page="how")

    @app.route("/security-tips")
    def security_tips():
        return render_template("security_tips.html", active_page="tips")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            password_confirm = request.form.get("password_confirm", "")

            if not name:
                flash("Please enter your name.")
            elif "@" not in email or "." not in email:
                flash("Please enter a valid email address.")
            elif len(password) < 8:
                flash("Password must be at least 8 characters.")
            elif password != password_confirm:
                flash("Passwords do not match.")
            elif get_user_by_email(email) is not None:
                flash("That email is already registered. Try logging in.")
            else:
                create_user(name, email, password)
                flash("Account created! You can now log in.")
                return redirect(url_for("login"))
        return render_template("register.html", active_page="register")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")

            user = check_password(email, password)
            if user is None:
                flash("Invalid email or password.")
            else:
                session.clear()
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                return redirect(url_for("dashboard"))
        return render_template("login.html", active_page="login")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been logged out.")
        return redirect(url_for("index"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = get_user_by_id(session["user_id"])
        scans = get_scans_for_user(user["id"])
        return render_template("dashboard.html", active_page="dashboard", user=user, scans=scans)

    @app.route("/scan", methods=["GET", "POST"])
    @login_required
    def scan():
        if request.method == "POST":
            url = request.form.get("url", "").strip()
            permitted = request.form.get("permission") == "yes"

            if not permitted:
                flash("You must confirm that you own this website or have permission to test it.")
            elif not (url.startswith("http://") or url.startswith("https://")):
                flash("Please enter a valid URL, starting with http:// or https://")
            else:
                user_id = session["user_id"]
                response, findings = scan_website(url)

                if response is None:
                    flash("We couldn't reach this website. Please check the URL and try again.")
                else:
                    score = 100 - (len(findings) * 10)
                    if score < 0:
                        score = 0

                    scan_id = create_scan(user_id, url, score)
                    for finding in findings:
                        add_finding(
                            scan_id,
                            finding["check_type"],
                            finding["severity"],
                            finding["title"],
                            finding["description"],
                            finding["recommendation"],
                        )
                    return redirect(url_for("results", scan_id=scan_id))
        return render_template("scan.html", active_page="scan", url=request.form.get("url", ""))

    @app.route("/results/<int:scan_id>")
    @login_required
    def results(scan_id):
        scan = get_scan(scan_id)
        if scan is None or scan["user_id"] != session["user_id"]:
            flash("Scan not found.")
            return redirect(url_for("dashboard"))

        findings = get_findings_for_scan(scan_id)
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in findings if f["severity"] == "LOW")
        return render_template(
            "results.html",
            active_page="dashboard",
            scan=scan,
            findings=findings,
            high=high,
            medium=medium,
            low=low,
        )

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=Config.PORT, debug=Config.DEBUG)