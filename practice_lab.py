from flask import Flask, make_response

app = Flask(__name__)


@app.route("/")
def home():
    response = make_response("<h1>My small shop</h1><p>Welcome!</p>")
    response.set_cookie("session_id", "abc123")
    return response


@app.route("/.env")
def env_file():
    return "DB_PASSWORD=supersecret123\nAPI_KEY=sk-test-456\n"


@app.route("/.git/config")
def git_config():
    return "[remote \"origin\"]\n\turl = git@github.com:secret/repo.git\n"


@app.route("/backup.zip")
def backup():
    return "PK\x03\x04fake-backup-contents"


@app.route("/backup/")
def backup_dir():
    return (
        "<html><body><h1>Index of /backup/</h1>"
        "<ul><li>passwords.txt</li><li>admin_notes.txt</li><li>database_dump.sql</li></ul>"
        "</body></html>"
    )


@app.errorhandler(404)
def not_found(error):
    return (
        "<h1>Traceback (most recent call last)</h1>"
        "<p>File \"C:\\secret_app\\app.py\", line 42, in view</p>"
        "<p>sqlite3.OperationalError: no such table: users</p>",
        404,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055, debug=False)