"""
ShopLab — pre-authentication vulnerable web app for local scanner testing.

Every issue is reachable without logging in. The app is deliberately insecure.
Run it only on a machine and network you are allowed to test. Do not put it
on the public internet.

    pip install -r requirements.txt
    python app.py

On Linux or Kali, Gunicorn can serve the same app:

    gunicorn -c gunicorn.conf.py app:app

Default listen address is http://0.0.0.0:8080
Override with LAB_HOST and LAB_PORT.
"""

from __future__ import annotations

import base64
import io
import json
import mimetypes
import os
import pickle
import sqlite3
import subprocess
import tarfile
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote
from urllib.request import urlopen

from flask import Flask, Response, abort, jsonify, request
from jinja2.exceptions import TemplateError
from werkzeug.exceptions import HTTPException

ROOT = Path(__file__).resolve().parent
WWW = ROOT / "lab_www"
PAGES = ROOT / "pages"
FIXTURES = ROOT / "fixtures"
DATA = ROOT / "data"
DB_PATH = DATA / "lab.db"

app = Flask(__name__, static_folder=None)
app.config["SECRET_KEY"] = "lab-secret-key-do-not-use"
app.config["DB_PASSWORD"] = "Winter2024!"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Intentionally absent on every response:
# Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options,
# Content-Security-Policy, Referrer-Policy.
REMOVED_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
)

COVERAGE = (
    ("Auth bypass", "/admin, /login, /staff, /api/me"),
    ("Clickjacking", "/account"),
    ("Command injection", "/tools/ping"),
    ("CORS misconfiguration", "/api/account"),
    ("CSRF", "/account"),
    ("Directory listing", "/backup/ and /uploads/"),
    ("HTML injection", "/preview and /search"),
    ("IDOR", "/api/users/1 and /order?id=1001"),
    ("LFI", "/view?file=welcome.txt"),
    ("RCE", "/hello, /tools/calc, /upload, /preferences"),
    ("Security headers", "Every response"),
    ("Sensitive data exposure", "/.env, /debug, /static/js/config.js, /backup/"),
    ("SQL injection", "/product?id=1, /search?q=mug, /login"),
    ("VCS metadata exposure", "/.git/HEAD and /.svn/entries"),
    ("XSS", "/search (reflected), /comments (stored), /dom (DOM)"),
)

SITEMAP_PATHS = (
    "/",
    "/search?q=mug",
    "/product?id=1",
    "/api/product?id=1",
    "/login",
    "/comments",
    "/preview?content=Welcome",
    "/dom?name=visitor",
    "/account",
    "/order?id=1001",
    "/api/users/1",
    "/api/orders/1001",
    "/api/account",
    "/api/me",
    "/api/admin/users",
    "/admin",
    "/staff",
    "/tools/ping?host=127.0.0.1",
    "/tools/calc?expr=1+1",
    "/view?file=welcome.txt",
    "/hello?name=guest",
    "/upload",
    "/uploads/",
    "/preferences",
    "/backup/",
    "/backups/",
    "/debug",
    "/config.json",
    "/appsettings.json",
    "/web.config",
    "/phpinfo.php",
    "/server-status",
    "/static/js/config.js",
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.aws/credentials",
    "/backup.zip",
    "/robots.txt",
    "/sitemap.xml",
)

USERS = (
    (1, "admin", "Winter2024!", "admin", "admin@shop.lab", "900-00-0001"),
    (2, "alice", "alice123", "user", "alice@shop.lab", "900-00-0002"),
    (3, "bob", "bob123", "user", "bob@shop.lab", "900-00-0003"),
)

PRODUCTS = (
    (1, "Field Notebook", 18.0, "Hardcover notebook"),
    (2, "Mechanical Keyboard", 79.0, "Compact keyboard"),
    (3, "Ceramic Mug", 12.0, "12oz shop mug"),
)

ORDERS = (
    (1001, 2, "Field Notebook", "12 King Street, Austin, TX", "4111111111111111", "123"),
    (1002, 3, "Mechanical Keyboard", "88 Pine Ave, Denver, CO", "5500000000000004", "456"),
    (1003, 2, "Ceramic Mug", "12 King Street, Austin, TX", "4111111111111111", "123"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,
    role TEXT,
    email TEXT,
    ssn TEXT
);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    price REAL,
    description TEXT
);
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author TEXT,
    body TEXT
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    item TEXT,
    address TEXT,
    card_number TEXT,
    cvv TEXT
);
CREATE TABLE IF NOT EXISTS accounts (
    session_id TEXT PRIMARY KEY,
    email TEXT,
    balance REAL
);
"""


def esc(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def init_storage() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    WWW.mkdir(parents=True, exist_ok=True)
    (WWW / "uploads").mkdir(parents=True, exist_ok=True)
    (WWW / "backup").mkdir(parents=True, exist_ok=True)
    PAGES.mkdir(parents=True, exist_ok=True)
    FIXTURES.mkdir(parents=True, exist_ok=True)

    write_text(
        PAGES / "welcome.txt",
        "Welcome to the ShopLab document center.\nPublic policy documents live here.\n",
    )
    write_text(
        PAGES / "policy.txt",
        "Shipping policy: orders ship in two business days.\n",
    )
    write_text(
        FIXTURES / "passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "shop:x:1000:1000:ShopLab:/home/shop:/bin/bash\n",
    )

    env_body = (
        "APP_ENV=production\n"
        "DB_HOST=10.0.0.8\n"
        "DB_USER=shop\n"
        "DB_PASSWORD=Winter2024!\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "SECRET_KEY=lab-secret-key-do-not-use\n"
        "STRIPE_SECRET=dummy_stripe_secret_for_local_lab\n"
    )
    write_text(WWW / ".env", env_body)
    write_text(
        WWW / ".aws" / "credentials",
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    )
    write_text(
        WWW / "static" / "js" / "config.js",
        "window.APP_CONFIG = {\n"
        '  apiKey: "dummy_stripe_secret_for_local_lab",\n'
        '  awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",\n'
        '  awsSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n'
        '  adminPassword: "Winter2024!",\n'
        '  internalHost: "http://10.0.0.15/admin"\n'
        "};\n",
    )
    write_text(
        WWW / "config.json",
        json.dumps(
            {
                "dbHost": "10.0.0.8",
                "dbUser": "shop",
                "dbPassword": "Winter2024!",
                "stripeSecret": "dummy_stripe_secret_for_local_lab",
            },
            indent=2,
        ),
    )
    write_text(
        WWW / "appsettings.json",
        json.dumps(
            {
                "ConnectionStrings": {
                    "Default": "Server=10.0.0.8;Database=shop;User Id=sa;Password=Winter2024!;"
                },
                "ApiKey": "dummy_stripe_secret_for_local_lab",
            },
            indent=2,
        ),
    )
    write_text(
        WWW / "web.config",
        "<configuration>\n"
        "  <connectionStrings>\n"
        '    <add name="Default" connectionString="Server=10.0.0.8;Database=shop;User Id=sa;Password=Winter2024!;" />\n'
        "  </connectionStrings>\n"
        "</configuration>\n",
    )
    write_text(WWW / "web.config.bak", (WWW / "web.config").read_text(encoding="utf-8"))
    write_text(
        WWW / "config.php.bak",
        "<?php\n"
        '$db_pass = "Winter2024!";\n'
        '$aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";\n'
        "?>\n",
    )
    sql_dump = (
        "-- ShopLab database backup\n"
        "INSERT INTO users VALUES (1,'admin','Winter2024!','admin','admin@shop.lab','900-00-0001');\n"
        "INSERT INTO users VALUES (2,'alice','alice123','user','alice@shop.lab','900-00-0002');\n"
        "INSERT INTO orders VALUES (1001,2,'Field Notebook','12 King Street, Austin, TX','4111111111111111','123');\n"
    )
    write_text(WWW / "backup" / "database.sql.bak", sql_dump)
    write_text(WWW / "database.sql", sql_dump)
    write_text(WWW / "dump.sql", sql_dump)
    write_text(WWW / "backup" / "config.php.bak", (WWW / "config.php.bak").read_text(encoding="utf-8"))
    write_text(
        WWW / "backup" / "customers.csv",
        "name,email,ssn,card\n"
        "Alice,alice@shop.lab,900-00-0002,4111111111111111\n"
        "Bob,bob@shop.lab,900-00-0003,5500000000000004\n",
    )
    write_text(
        WWW / "backup" / "id_rsa",
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBALabExampleKeyMaterialNotARealPrivateKey1234567890\n"
        "-----END RSA PRIVATE KEY-----\n",
    )

    gz_buffer = io.BytesIO()
    with tarfile.open(fileobj=gz_buffer, mode="w:gz") as archive:
        payload = env_body.encode("utf-8")
        info = tarfile.TarInfo(name="config.env")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    (WWW / "backup" / "site-backup.tar.gz").write_bytes(gz_buffer.getvalue())

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        archive.writestr(".env", env_body)
        archive.writestr("config.php", (WWW / "config.php.bak").read_text(encoding="utf-8"))
    (WWW / "backup.zip").write_bytes(zip_buffer.getvalue())

    write_text(WWW / ".git" / "HEAD", "ref: refs/heads/main\n")
    write_text(
        WWW / ".git" / "config",
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = false\n"
        "\tbare = false\n"
        "[remote \"origin\"]\n"
        "\turl = https://deployer:Winter2024%21@git.internal.lab/acme/shop.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"main\"]\n"
        "\tremote = origin\n"
        "\tmerge = refs/heads/main\n",
    )
    write_text(WWW / ".git" / "description", "Unnamed repository; edit this file 'description' to name the repository.\n")
    write_text(WWW / ".git" / "COMMIT_EDITMSG", "add production secrets\n")
    write_text(WWW / ".git" / "info" / "exclude", "# exclude patterns\n")
    write_text(WWW / ".git" / "refs" / "heads" / "main", "0123456789abcdef0123456789abcdef01234567\n")
    write_text(
        WWW / ".git" / "logs" / "HEAD",
        "0000000000000000000000000000000000000000 0123456789abcdef0123456789abcdef01234567 "
        "student <student@shop.lab> 1700000000 +0000\tcommit (initial): add production secrets\n",
    )
    write_text(
        WWW / ".svn" / "entries",
        "10\n\ndir\n0\nhttps://svn.internal.lab/repos/shop/trunk\nhttps://svn.internal.lab/repos/shop\n\n\n\n\n\n",
    )
    svn_db = WWW / ".svn" / "wc.db"
    if svn_db.exists():
        svn_db.unlink()
    svn = sqlite3.connect(svn_db)
    svn.execute("CREATE TABLE REPOSITORY (id INTEGER PRIMARY KEY, root TEXT)")
    svn.execute(
        "INSERT INTO REPOSITORY(root) VALUES ('https://svn.internal.lab/repos/shop/trunk')"
    )
    svn.commit()
    svn.close()

    write_text(
        WWW / "phpinfo.php",
        "<html><head><title>phpinfo()</title></head><body>"
        "<h1>PHP Version 8.1.2</h1><table>"
        "<tr><td>DB_PASSWORD</td><td>Winter2024!</td></tr>"
        "<tr><td>AWS_SECRET_ACCESS_KEY</td><td>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</td></tr>"
        "<tr><td>STRIPE_SECRET</td><td>dummy_stripe_secret_for_local_lab</td></tr>"
        "</table></body></html>\n",
    )
    write_text(
        WWW / "server-status.html",
        "<html><head><title>Apache Server Status</title></head><body>"
        "<h1>Apache Server Status for shop.lab</h1>"
        "<p>Server Version: Apache/2.4.58</p>"
        "<pre>DB_PASSWORD=Winter2024!\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</pre>"
        "</body></html>\n",
    )

    with db() as conn:
        ensure_schema(conn)


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0:
        conn.executemany(
            "INSERT INTO users(id, username, password, role, email, ssn) VALUES (?, ?, ?, ?, ?, ?)",
            USERS,
        )
    if conn.execute("SELECT COUNT(*) AS c FROM products").fetchone()["c"] == 0:
        conn.executemany(
            "INSERT INTO products(id, name, price, description) VALUES (?, ?, ?, ?)",
            PRODUCTS,
        )
    if conn.execute("SELECT COUNT(*) AS c FROM orders").fetchone()["c"] == 0:
        conn.executemany(
            "INSERT INTO orders(id, user_id, item, address, card_number, cvv) VALUES (?, ?, ?, ?, ?, ?)",
            ORDERS,
        )


@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        ensure_schema(conn)
        yield conn
        conn.commit()
    finally:
        conn.close()


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    return [dict(row) for row in rows]


def table_html(rows: list[sqlite3.Row], escape_cells: bool = False) -> str:
    if not rows:
        return "<p>No results.</p>"
    keys = rows[0].keys()
    head = "".join(f"<th>{esc(key)}</th>" for key in keys)
    body = []
    for row in rows:
        cells = []
        for key in keys:
            value = "" if row[key] is None else str(row[key])
            cells.append(f"<td>{esc(value) if escape_cells else value}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return "<table><thead><tr>" + head + "</tr></thead><tbody>" + "".join(body) + "</tbody></table>"


CSS = """
body { margin: 0; font-family: Georgia, "Times New Roman", serif; color: #1c1915; background: #f6f3ee; }
header { background: #243028; color: #f6f3ee; padding: 18px 28px; }
header a { color: #f6f3ee; margin-right: 14px; text-decoration: none; }
header .brand { font-weight: 700; letter-spacing: 0.04em; }
.banner { background: #f3e1c2; color: #5c3b08; padding: 10px 28px; }
main { max-width: 980px; margin: 0 auto; padding: 28px; }
h1 { font-weight: 600; margin-top: 0; }
table { border-collapse: collapse; width: 100%; background: white; }
th, td { border: 1px solid #ddd4c8; padding: 8px 10px; text-align: left; vertical-align: top; }
form { margin: 16px 0; }
input, textarea, button { font: inherit; padding: 8px; }
button, .btn { background: #243028; color: white; border: 0; padding: 8px 14px; text-decoration: none; display: inline-block; }
.card { background: white; border: 1px solid #e4dcd0; padding: 14px 16px; margin: 12px 0; }
pre { white-space: pre-wrap; word-break: break-word; background: white; padding: 12px; border: 1px solid #e4dcd0; }
footer { color: #6d645b; padding: 8px 28px 28px; }
"""

NAV = """
<header>
  <a class="brand" href="/">ShopLab</a>
  <a href="/search?q=mug">Search</a>
  <a href="/product?id=1">Products</a>
  <a href="/comments">Reviews</a>
  <a href="/account">Account</a>
  <a href="/order?id=1001">Orders</a>
  <a href="/admin">Admin</a>
  <a href="/login">Login</a>
  <a href="/tools/ping?host=127.0.0.1">Tools</a>
  <a href="/view?file=welcome.txt">Documents</a>
  <a href="/backup/">Backups</a>
  <a href="/debug">Debug</a>
</header>
<div class="banner">Pre-auth lab. Every page is reachable without logging in. Local scanner testing only.</div>
"""


def page(title: str, body: str, status: int = 200):
    html = (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"robots\" content=\"noindex\">"
        f"<title>{esc(title)}</title><style>{CSS}</style>"
        "<link rel=\"sitemap\" type=\"application/xml\" href=\"/sitemap.xml\">"
        "</head><body>"
        "<!-- TODO: rotate credentials admin / Winter2024! -->"
        f"{NAV}<main>{body}</main>"
        "<footer>Intentionally vulnerable ShopLab. Do not expose this server.</footer>"
        "<script src=\"/static/js/config.js\"></script>"
        "</body></html>"
    )
    return html, status, {"Content-Type": "text/html; charset=utf-8"}


def make_token(role: str = "user", user: str = "guest") -> str:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"user": user, "role": role}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}."


def decode_unsigned(token: str | None) -> dict | None:
    if not token or "." not in token:
        return None
    parts = token.split(".")
    if len(parts) < 2 or not parts[1]:
        return None
    data = parts[1]
    pad = "=" * (-len(data) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(data + pad))
    except Exception:
        return None


def request_token() -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.cookies.get("access_token")


def bypass_granted() -> bool:
    if request.args.get("admin", "").lower() in {"1", "true", "yes"}:
        return True
    if request.args.get("role", "").lower() == "admin":
        return True
    if request.args.get("debug") == "1":
        return True
    forwarded = request.headers.get("X-Forwarded-For", "")
    if "127.0.0.1" in forwarded or "localhost" in forwarded.lower():
        return True
    if request.headers.get("X-Original-URL") or request.headers.get("X-Rewrite-URL"):
        return True
    if request.headers.get("X-Custom-IP-Authorization") == "127.0.0.1":
        return True
    if request.headers.get("X-Forwarded-User", "").lower() == "admin":
        return True
    override = request.headers.get("X-HTTP-Method-Override", "").upper()
    if override in {"POST", "PUT", "PATCH", "DELETE"}:
        return True
    auth = request.headers.get("Authorization", "").lower()
    if auth in {"bearer null", "bearer admin", "bearer undefined"}:
        return True
    payload = decode_unsigned(request_token())
    if payload and str(payload.get("role", "")).lower() == "admin":
        return True
    return False


def current_session() -> tuple[str, bool]:
    sid = request.cookies.get("lab_session")
    if sid:
        return sid, False
    return uuid.uuid4().hex, True


def remember_session(response: Response, sid: str) -> Response:
    # HttpOnly and Secure are intentionally off. SameSite is intentionally omitted.
    response.set_cookie("lab_session", sid, max_age=7 * 24 * 3600, httponly=False, secure=False, path="/")
    return response


def account_for(sid: str) -> dict:
    with db() as conn:
        row = conn.execute(
            "SELECT email, balance FROM accounts WHERE session_id = ?",
            (sid,),
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO accounts(session_id, email, balance) VALUES (?, ?, ?)",
                (sid, "user@shop.lab", 1000.0),
            )
            return {"email": "user@shop.lab", "balance": 1000.0}
        return {"email": row["email"], "balance": row["balance"]}


def directory_listing(url_prefix: str, folder: Path) -> str:
    names = sorted(path.name for path in folder.iterdir() if not path.name.startswith("."))
    items = ["<li><a href=\"../\">Parent Directory</a></li>"]
    for name in names:
        items.append(f"<li><a href=\"{esc(name)}\">{esc(name)}</a></li>")
    title = f"Index of {url_prefix}"
    return (
        "<!doctype html><html><head><title>"
        + esc(title)
        + "</title></head><body><h1>"
        + esc(title)
        + "</h1><ul>"
        + "".join(items)
        + "</ul></body></html>"
    )


def safe_file(folder: Path, name: str):
    root = folder.resolve()
    target = (folder / name).resolve()
    root_prefix = str(root) + os.sep
    if target != root and not str(target).startswith(root_prefix):
        abort(403)
    if target.is_dir():
        return Response(directory_listing("/" + folder.name + "/", target), mimetype="text/html")
    if not target.is_file():
        abort(404)
    return file_response(target)


def file_response(path: Path, mime: str | None = None):
    if not path.is_file():
        abort(404)
    if mime is None:
        guessed, _ = mimetypes.guess_type(path.name)
        if path.suffix in {".php", ".html"}:
            mime = "text/html; charset=utf-8"
        elif path.suffix == ".js":
            mime = "text/javascript; charset=utf-8"
        elif path.suffix == ".json":
            mime = "application/json"
        elif path.suffix in {".db", ".gz", ".zip"} or path.name.endswith(".tar.gz"):
            mime = "application/octet-stream"
        elif path.name == "web.config" or path.suffix in {".config", ".bak"}:
            mime = "text/plain; charset=utf-8"
        else:
            mime = guessed or "text/plain; charset=utf-8"
    return Response(path.read_bytes(), mimetype=mime)


def normalize_traversal(raw: str) -> str:
    value = raw.replace("\x00", "")
    previous = None
    while previous != value:
        previous = value
        value = unquote(value)
    value = value.replace("\\", "/")
    for token in ("....//", "..../", "..;/"):
        value = value.replace(token, "../")
    return value


def read_local(requested: str) -> str:
    target = os.path.normpath(os.path.join(str(PAGES), requested))
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(100_000)
    except OSError as exc:
        lowered = requested.replace("\\", "/").lower()
        if "etc/passwd" in lowered or lowered.endswith("/passwd") or lowered == "passwd":
            return (FIXTURES / "passwd").read_text(encoding="utf-8")
        if lowered.endswith("win.ini"):
            winini = Path(os.environ.get("WINDIR", r"C:\Windows")) / "win.ini"
            try:
                return winini.read_text(encoding="utf-8", errors="replace")[:20_000]
            except OSError:
                pass
        return f"Unable to read {target}: {exc}"


def read_requested(raw: str) -> str:
    requested = normalize_traversal(raw.strip())
    lowered = requested.lower()
    if lowered.startswith("php://filter"):
        resource = "welcome.txt"
        marker = "resource="
        if marker in requested:
            resource = requested.split(marker, 1)[1]
        return base64.b64encode(read_local(resource).encode("utf-8", errors="replace")).decode()
    if lowered.startswith(("http://", "https://", "file://")):
        try:
            with urlopen(requested, timeout=4) as remote:
                return remote.read(100_000).decode("utf-8", errors="replace")
        except Exception as exc:
            return f"Remote read failed: {exc}"
    return read_local(requested)


def run_command(user_value: str) -> str:
    ping = f"ping -n 1 {user_value}" if os.name == "nt" else f"ping -c 1 {user_value}"
    try:
        if os.name == "nt":
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ping],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=8,
            )
        else:
            completed = subprocess.run(
                ping,
                shell=True,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=8,
            )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return "Command timed out\n" + output
    return (completed.stdout or "") + (completed.stderr or "")


def first_value(*names: str, default: str | None = None) -> str | None:
    for name in names:
        if name in request.values:
            return request.values.get(name, "")
    return default


@app.before_request
def cors_preflight():
    if request.method == "OPTIONS":
        return Response("", status=204)


@app.after_request
def relax_browser_controls(response: Response):
    origin = request.headers.get("Origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = request.headers.get(
            "Access-Control-Request-Headers",
            "Content-Type, Authorization",
        )
    for header in REMOVED_SECURITY_HEADERS:
        response.headers.pop(header, None)
    if "access_token" not in request.cookies:
        response.set_cookie(
            "access_token",
            make_token("user", "guest"),
            httponly=False,
            secure=False,
            path="/",
        )
    return response


@app.route("/")
def home():
    with db() as conn:
        products = conn.execute("SELECT id, name, price FROM products ORDER BY id").fetchall()
    cards = []
    for product in products:
        cards.append(
            "<div class=\"card\"><strong>"
            + esc(product["name"])
            + "</strong><p>$"
            + esc(f"{product['price']:.2f}")
            + f"</p><a href=\"/product?id={product['id']}\">View</a></div>"
        )
    coverage = "".join(
        f"<tr><td>{esc(name)}</td><td><code>{esc(where)}</code></td></tr>" for name, where in COVERAGE
    )
    body = (
        "<h1>ShopLab</h1>"
        "<p>Small shop used as an unauthenticated scan target. No login is required for any module below.</p>"
        + "".join(cards)
        + "<h2>Scanner coverage</h2>"
        "<table><thead><tr><th>Module</th><th>Where it lives</th></tr></thead><tbody>"
        + coverage
        + "</tbody></table>"
        "<p><a href=\"/hello?name=guest\">Greeting</a> · "
        "<a href=\"/preview?content=Welcome\">Announcement preview</a> · "
        "<a href=\"/dom?name=visitor\">Welcome widget</a> · "
        "<a href=\"/upload\">Support upload</a> · "
        "<a href=\"/preferences\">Import preferences</a> · "
        "<a href=\"/tools/calc?expr=1+1\">Quote calculator</a></p>"
    )
    return page("ShopLab", body)


@app.route("/search", methods=["GET", "POST"])
def search():
    has_query = "q" in request.values
    q = request.values.get("q", "")
    error = None
    with db() as conn:
        if has_query:
            sql = (
                "SELECT id, name, price, description FROM products "
                f"WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
            )
            try:
                rows = conn.execute(sql).fetchall()
            except sqlite3.Error as exc:
                rows = []
                error = f"sqlite3.OperationalError: {exc} | query: {sql}"
        else:
            rows = conn.execute("SELECT id, name, price, description FROM products").fetchall()
    body = (
        "<h1>Search</h1>"
        "<form method=\"get\" action=\"/search\">"
        "<input name=\"q\" value=\"" + q + "\">"
        "<button type=\"submit\">Search</button></form>"
        "<h2>Results for " + q + "</h2>"
    )
    if error:
        body += "<pre>" + error + "</pre>"
    body += table_html(rows, escape_cells=False)
    return page("Search", body)


@app.route("/product", methods=["GET", "POST"])
def product():
    raw_id = request.values.get("id", "1")
    error = None
    sql = f"SELECT id, name, price, description FROM products WHERE id = {raw_id}"
    with db() as conn:
        try:
            rows = conn.execute(sql).fetchall()
        except sqlite3.Error as exc:
            rows = []
            error = f"sqlite3.OperationalError: {exc} | query: {sql}"
    body = (
        "<h1>Product</h1>"
        "<form method=\"get\" action=\"/product\">"
        "<input name=\"id\" value=\"" + esc(raw_id) + "\">"
        "<button type=\"submit\">Lookup</button></form>"
    )
    if error:
        body += "<pre>" + esc(error) + "</pre>"
    body += table_html(rows, escape_cells=False)
    return page("Product", body)


@app.route("/api/product")
def api_product():
    raw_id = request.values.get("id", "1")
    sql = f"SELECT id, name, price, description FROM products WHERE id = {raw_id}"
    with db() as conn:
        try:
            rows = rows_to_dicts(conn.execute(sql).fetchall())
        except sqlite3.Error as exc:
            return jsonify({"error": f"sqlite3.OperationalError: {exc}", "query": sql}), 500
    return jsonify(rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = (
        "<h1>Login</h1>"
        "<form method=\"post\" action=\"/login\">"
        "<p><input name=\"username\" placeholder=\"Username\"></p>"
        "<p><input name=\"password\" type=\"password\" placeholder=\"Password\"></p>"
        "<button type=\"submit\">Sign in</button></form>"
    )
    if "username" not in request.values and "password" not in request.values:
        return page("Login", form)
    username = request.values.get("username", "")
    password = request.values.get("password", "")
    sql = (
        "SELECT id, username, password, role, email, ssn FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    with db() as conn:
        try:
            rows = conn.execute(sql).fetchall()
        except sqlite3.Error as exc:
            return page("Login", form + "<pre>sqlite3.OperationalError: " + esc(exc) + " | query: " + esc(sql) + "</pre>")
    if not rows:
        return page("Login", form + "<p>Invalid credentials.</p>")
    listing = "".join(
        f"<li>{esc(row['username'])} / {esc(row['password'])} / {esc(row['role'])} / {esc(row['email'])}</li>"
        for row in rows
    )
    body = (
        form
        + "<p>Authenticated as "
        + esc(rows[0]["username"])
        + " ("
        + esc(rows[0]["role"])
        + ").</p><ul>"
        + listing
        + "</ul>"
    )
    return page("Login", body)


@app.route("/comments", methods=["GET", "POST"])
def comments():
    message = ""
    with db() as conn:
        if request.method == "POST" or "body" in request.form:
            author = request.form.get("author", "guest")
            body_text = request.form.get("body", "")
            if body_text:
                conn.execute("INSERT INTO comments(author, body) VALUES (?, ?)", (author, body_text))
                message = "<p>Review saved.</p>"
        rows = conn.execute("SELECT id, author, body FROM comments ORDER BY id").fetchall()
    rendered = []
    for row in rows:
        rendered.append(
            "<div class=\"card\"><strong>"
            + str(row["author"])
            + "</strong><div class=\"review\">"
            + str(row["body"])
            + "</div></div>"
        )
    form = (
        "<h1>Reviews</h1>"
        + message
        + "<form method=\"post\" action=\"/comments\">"
        "<p><input name=\"author\" placeholder=\"Name\"></p>"
        "<p><textarea name=\"body\" placeholder=\"Review\"></textarea></p>"
        "<button type=\"submit\">Post review</button></form>"
        + "".join(rendered)
    )
    return page("Reviews", form)


@app.route("/preview")
def preview():
    content = first_value("content", "message", "html", "q", default="Welcome") or ""
    body = (
        "<h1>Announcement preview</h1>"
        "<form method=\"get\" action=\"/preview\">"
        "<textarea name=\"content\">" + content + "</textarea>"
        "<button type=\"submit\">Preview</button></form>"
        "<div id=\"preview\" class=\"card\">" + content + "</div>"
    )
    return page("Preview", body)


@app.route("/dom")
def dom():
    body = """
    <h1>Welcome widget</h1>
    <div id="out"></div>
    <script>
      const params = new URLSearchParams(window.location.search);
      const fromHash = window.location.hash ? decodeURIComponent(window.location.hash.slice(1)) : "";
      const value = params.get("name") || fromHash || "visitor";
      document.getElementById("out").innerHTML = value;
    </script>
    """
    return page("Welcome", body)


@app.route("/account", methods=["GET"])
def account():
    sid, _created = current_session()
    state = account_for(sid)
    body = (
        "<h1>Account settings</h1>"
        "<p>Email: <span id=\"email\">" + esc(state["email"]) + "</span></p>"
        "<p>Balance: $<span id=\"balance\">" + esc(f"{float(state['balance']):.2f}") + "</span></p>"
        "<form method=\"post\" action=\"/account/email\">"
        "<label>Email <input name=\"email\" value=\"" + esc(state["email"]) + "\"></label> "
        "<button type=\"submit\">Update email</button></form>"
        "<form id=\"transfer\" method=\"post\" action=\"/account/transfer\">"
        "<label>To <input name=\"to\" value=\"bob\"></label> "
        "<label>Amount <input name=\"amount\" value=\"1\"></label> "
        "<button type=\"submit\">Transfer</button></form>"
    )
    html, status, headers = page("Account settings", body)
    response = Response(html, status=status, headers=headers)
    return remember_session(response, sid)


@app.route("/account/email", methods=["POST", "GET"])
def update_email():
    sid, _created = current_session()
    before = account_for(sid)
    email = request.values.get("email", "")
    # No CSRF token. Origin and Referer are not checked.
    if email:
        with db() as conn:
            conn.execute("UPDATE accounts SET email = ? WHERE session_id = ?", (email, sid))
        after = email
    else:
        after = before["email"]
    body = (
        "<h1>Email updated</h1>"
        "<p>Previous email: " + esc(before["email"]) + "</p>"
        "<p>Current email: <span id=\"email\">" + esc(after) + "</span></p>"
        "<p><a href=\"/account\">Back to account</a></p>"
    )
    html, status, headers = page("Email updated", body)
    response = Response(html, status=status, headers=headers)
    return remember_session(response, sid)


@app.route("/account/transfer", methods=["POST", "GET"])
def transfer():
    sid, _created = current_session()
    before = account_for(sid)
    recipient = request.values.get("to", "")
    raw_amount = request.values.get("amount", "")
    balance = float(before["balance"])
    moved = 0.0
    if recipient and raw_amount:
        try:
            moved = float(raw_amount)
        except ValueError:
            moved = 0.0
        balance = balance - moved
        with db() as conn:
            conn.execute("UPDATE accounts SET balance = ? WHERE session_id = ?", (balance, sid))
    body = (
        "<h1>Transfer</h1>"
        "<p>Previous balance: " + esc(f"{float(before['balance']):.2f}") + "</p>"
        "<p>Sent " + esc(f"{moved:.2f}") + " to " + esc(recipient) + ".</p>"
        "<p>Current balance: <span id=\"balance\">" + esc(f"{balance:.2f}") + "</span></p>"
        "<p><a href=\"/account\">Back to account</a></p>"
    )
    html, status, headers = page("Transfer", body)
    response = Response(html, status=status, headers=headers)
    return remember_session(response, sid)


@app.route("/order", methods=["GET", "POST"])
def order_page():
    raw = request.values.get("id", "1001")
    try:
        order_id = int(raw)
    except ValueError:
        return page("Order", "<h1>Order</h1><p>Unknown order.</p>", 404)
    with db() as conn:
        if request.method == "POST" and "address" in request.values:
            conn.execute(
                "UPDATE orders SET address = ? WHERE id = ?",
                (request.values.get("address", ""), order_id),
            )
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None:
        return page("Order", "<h1>Order</h1><p>Unknown order.</p>", 404)
    body = (
        "<h1>Order "
        + esc(order_id)
        + "</h1>"
        + table_html([row], escape_cells=True)
        + "<form method=\"post\" action=\"/order\">"
        + f"<input type=\"hidden\" name=\"id\" value=\"{order_id}\">"
        + "<p><input name=\"address\" value=\"" + esc(row["address"]) + "\"></p>"
        + "<button type=\"submit\">Update address</button></form>"
        + f"<p><a href=\"/api/orders/{order_id}\">API</a></p>"
    )
    return page("Order", body)


@app.route("/api/users/<int:user_id>", methods=["GET", "POST", "PUT", "PATCH"])
def api_user(user_id: int):
    payload = request.get_json(silent=True) or {}
    email = request.values.get("email", payload.get("email"))
    with db() as conn:
        if email and request.method in {"POST", "PUT", "PATCH"}:
            conn.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        nxt = conn.execute("SELECT id FROM users WHERE id > ? ORDER BY id LIMIT 1", (user_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    data = dict(row)
    if nxt:
        data["next"] = f"/api/users/{nxt['id']}"
    return jsonify(data)


@app.route("/api/orders/<int:order_id>", methods=["GET", "POST", "PUT", "PATCH"])
def api_order(order_id: int):
    payload = request.get_json(silent=True) or {}
    address = request.values.get("address", payload.get("address"))
    with db() as conn:
        if address and request.method in {"POST", "PUT", "PATCH"}:
            conn.execute("UPDATE orders SET address = ? WHERE id = ?", (address, order_id))
        row = conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/account")
def api_account():
    email = "alice@shop.lab"
    sid = request.cookies.get("lab_session")
    if sid:
        with db() as conn:
            row = conn.execute("SELECT email FROM accounts WHERE session_id = ?", (sid,)).fetchone()
            if row:
                email = row["email"]
    return jsonify(
        {
            "email": email,
            "ssn": "900-00-0002",
            "phone": "512-555-0142",
            "apiToken": "tok_lab_9f3a2c1b8e",
            "cardNumber": "4111111111111111",
            "address": "12 King Street, Austin, TX",
        }
    )


@app.route("/api/me")
def api_me():
    payload = decode_unsigned(request_token()) or {"user": "guest", "role": "user"}
    if str(payload.get("role", "")).lower() == "admin":
        with db() as conn:
            users = rows_to_dicts(conn.execute("SELECT * FROM users").fetchall())
        return jsonify(
            {
                "user": payload.get("user", "admin"),
                "role": "admin",
                "dbPassword": app.config["DB_PASSWORD"],
                "users": users,
            }
        )
    return jsonify({"user": payload.get("user", "guest"), "role": payload.get("role", "user")})


@app.route("/api/admin/users")
def api_admin_users():
    with db() as conn:
        users = rows_to_dicts(conn.execute("SELECT * FROM users").fetchall())
    return jsonify(users)


@app.route("/admin")
@app.route("/admin/")
@app.route("/administrator")
def admin():
    with db() as conn:
        rows = conn.execute("SELECT id, username, password, role, email, ssn FROM users").fetchall()
    body = "<h1>Admin panel</h1><p>User directory</p>" + table_html(rows, escape_cells=True)
    return page("Admin panel", body)


@app.route("/staff", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def staff():
    if request.method == "GET" and not bypass_granted():
        return page("Staff", "<h1>Staff only</h1><p>Forbidden.</p><p><a href=\"/login\">Login</a></p>", 403)
    body = (
        "<h1>Payroll</h1>"
        "<p>CEO salary: 250000</p>"
        "<p>Database password: Winter2024!</p>"
        "<p>Stripe secret: dummy_stripe_secret_for_local_lab</p>"
    )
    return page("Staff reports", body)


@app.route("/tools/ping", methods=["GET", "POST"])
def ping_tool():
    host = first_value("host", "ip", "target", "address", "cmd", "command", default="127.0.0.1")
    output = run_command(host or "127.0.0.1")
    body = (
        "<h1>Connectivity check</h1>"
        "<form method=\"get\" action=\"/tools/ping\">"
        "<input name=\"host\" value=\"" + esc(host or "") + "\">"
        "<button type=\"submit\">Ping</button></form>"
        "<pre>" + esc(output) + "</pre>"
    )
    return page("Ping", body)


@app.route("/tools/calc", methods=["GET", "POST"])
def calculator():
    expr = first_value("expr", "expression", "q", default=None)
    result = ""
    if expr:
        try:
            result = repr(eval(expr))  # noqa: S307 - lab sink
        except Exception as exc:
            result = repr(exc)
    body = (
        "<h1>Quote calculator</h1>"
        "<form method=\"get\" action=\"/tools/calc\">"
        "<input name=\"expr\" value=\"" + esc(expr or "1+1") + "\">"
        "<button type=\"submit\">Calculate</button></form>"
    )
    if expr:
        body += "<p>Result: " + esc(result) + "</p>"
    return page("Calculator", body)


@app.route("/view")
def view_file():
    requested = first_value("file", "page", "path", "template", "doc", default="welcome.txt") or "welcome.txt"
    content = read_requested(requested)
    body = (
        "<h1>Documents</h1>"
        "<form method=\"get\" action=\"/view\">"
        "<input name=\"file\" value=\"" + esc(requested) + "\">"
        "<button type=\"submit\">Open</button></form>"
        "<pre>" + esc(content) + "</pre>"
    )
    return page("Documents", body)


@app.route("/hello")
def hello():
    name = first_value("name", "template", "message", default="guest") or "guest"
    try:
        rendered = app.jinja_env.from_string("Hello " + name).render()
    except TemplateError as exc:
        rendered = "Template error: " + str(exc)
    except Exception as exc:
        rendered = "Template error: " + str(exc)
    body = (
        "<h1>Greeting</h1>"
        "<form method=\"get\" action=\"/hello\">"
        "<input name=\"name\" value=\"" + esc(name if "{{" not in name else "") + "\">"
        "<button type=\"submit\">Greet</button></form>"
        "<p id=\"greeting\">" + rendered + "</p>"
    )
    return page("Greeting", body)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    notice = ""
    if request.method == "POST":
        uploaded = request.files.get("file")
        if uploaded and uploaded.filename:
            filename = Path(uploaded.filename).name
            if filename:
                destination = WWW / "uploads" / filename
                uploaded.save(destination)
                notice = f"<p>Saved <a href=\"/uploads/{esc(filename)}\">{esc(filename)}</a></p>"
    body = (
        "<h1>Support upload</h1>"
        + notice
        + "<form method=\"post\" action=\"/upload\" enctype=\"multipart/form-data\">"
        "<input type=\"file\" name=\"file\">"
        "<button type=\"submit\">Upload</button></form>"
        "<p><a href=\"/uploads/\">Uploaded files</a></p>"
    )
    return page("Upload", body)


@app.route("/uploads/")
@app.route("/uploads")
def uploads_index():
    return Response(directory_listing("/uploads/", WWW / "uploads"), mimetype="text/html")


@app.route("/uploads/<path:name>")
def uploaded_file(name: str):
    target = (WWW / "uploads" / name).resolve()
    root = (WWW / "uploads").resolve()
    if not str(target).startswith(str(root) + os.sep):
        abort(403)
    if not target.is_file():
        abort(404)
    ext = target.suffix.lower()
    mime = {
        ".html": "text/html; charset=utf-8",
        ".htm": "text/html; charset=utf-8",
        ".svg": "image/svg+xml",
        ".xml": "application/xml",
        ".js": "text/javascript; charset=utf-8",
        ".txt": "text/plain; charset=utf-8",
    }.get(ext)
    return file_response(target, mime)


@app.route("/preferences", methods=["GET", "POST"])
def preferences():
    notice = ""
    if request.method == "POST":
        content_type = request.content_type or ""
        try:
            if "octet-stream" in content_type:
                blob = request.get_data(cache=False) or b""
            else:
                raw = request.values.get("data", "")
                blob = base64.b64decode(raw) if raw else b""
            loaded = pickle.loads(blob)  # noqa: S301 - lab sink
            notice = "<p>Imported preferences: " + esc(repr(loaded)) + "</p>"
        except Exception as exc:
            notice = "<pre>" + esc(exc) + "</pre>"
    body = (
        "<h1>Import preferences</h1>"
        + notice
        + "<form method=\"post\" action=\"/preferences\">"
        "<textarea name=\"data\" placeholder=\"Base64 payload\"></textarea>"
        "<button type=\"submit\">Import</button></form>"
    )
    return page("Preferences", body)


@app.route("/backup")
@app.route("/backup/")
@app.route("/backups")
@app.route("/backups/")
def backup_index():
    return Response(directory_listing("/backup/", WWW / "backup"), mimetype="text/html")


@app.route("/backup/<path:name>")
@app.route("/backups/<path:name>")
def backup_file(name: str):
    return safe_file(WWW / "backup", name)


@app.route("/debug")
def debug():
    env_body = (WWW / ".env").read_text(encoding="utf-8")
    with db() as conn:
        users = conn.execute("SELECT username, password, email, ssn FROM users").fetchall()
    config_dump = {key: str(value) for key, value in app.config.items()}
    body = (
        "<h1>Debug</h1>"
        "<h2>Environment</h2><pre>" + esc(env_body) + "</pre>"
        "<h2>Config</h2><pre>" + esc(json.dumps(config_dump, indent=2)) + "</pre>"
        + table_html(users, escape_cells=True)
    )
    return page("Debug", body)


@app.route("/robots.txt")
def robots():
    body = (
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /backup/\n"
        "Disallow: /.env\n"
        "Disallow: /.git/\n"
        "Disallow: /.svn/\n"
        "Disallow: /.aws/\n"
        "Disallow: /debug\n"
        "Disallow: /server-status\n"
        "Disallow: /phpinfo.php\n"
        "Disallow: /web.config\n"
        "Disallow: /appsettings.json\n"
        "Disallow: /config.json\n"
        "Sitemap: /sitemap.xml\n"
    )
    return Response(body, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    root = request.url_root.rstrip("/")
    urls = "\n".join(f"  <url><loc>{esc(root + path)}</loc></url>" for path in SITEMAP_PATHS)
    xml = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n"
        + urls
        + "\n</urlset>\n"
    )
    return Response(xml, mimetype="application/xml")


EXPOSED_FILES = (
    ("/.env", WWW / ".env", "text/plain; charset=utf-8"),
    ("/.aws/credentials", WWW / ".aws" / "credentials", "text/plain; charset=utf-8"),
    ("/database.sql", WWW / "database.sql", "text/plain; charset=utf-8"),
    ("/dump.sql", WWW / "dump.sql", "text/plain; charset=utf-8"),
    ("/backup.zip", WWW / "backup.zip", "application/zip"),
    ("/web.config", WWW / "web.config", "text/xml"),
    ("/web.config.bak", WWW / "web.config.bak", "text/plain; charset=utf-8"),
    ("/config.json", WWW / "config.json", "application/json"),
    ("/config.php.bak", WWW / "config.php.bak", "text/plain; charset=utf-8"),
    ("/appsettings.json", WWW / "appsettings.json", "application/json"),
    ("/phpinfo.php", WWW / "phpinfo.php", "text/html; charset=utf-8"),
    ("/server-status", WWW / "server-status.html", "text/html; charset=utf-8"),
    ("/static/js/config.js", WWW / "static" / "js" / "config.js", "text/javascript; charset=utf-8"),
)


def register_exposed_files() -> None:
    for route, path, mime in EXPOSED_FILES:
        def handler(path=path, mime=mime):
            return file_response(path, mime)

        endpoint = "exposed_" + route.strip("/").replace("/", "_").replace(".", "_")
        app.add_url_rule(route, endpoint=endpoint, view_func=handler)


register_exposed_files()


@app.route("/.git/<path:subpath>")
def git_metadata(subpath: str):
    return safe_file(WWW / ".git", subpath)


@app.route("/.svn/<path:subpath>")
def svn_metadata(subpath: str):
    return safe_file(WWW / ".svn", subpath)


@app.route("/favicon.ico")
def favicon():
    return Response("", status=204)


@app.errorhandler(404)
def not_found(_exc):
    reflected = request.full_path
    previous = None
    while previous != reflected:
        previous = reflected
        reflected = unquote(reflected)
    return page("Not found", "<h1>Not found</h1><p>" + reflected + "</p>", 404)


@app.errorhandler(Exception)
def on_error(exc):
    if isinstance(exc, HTTPException):
        return exc
    return page("Error", "<pre>" + esc(exc) + "</pre>", 500)


init_storage()


if __name__ == "__main__":
    init_storage()
    host = os.environ.get("LAB_HOST", "0.0.0.0")
    port = int(os.environ.get("LAB_PORT", "8080"))
    print(f"ShopLab listening on http://{host}:{port}")
    print("Pre-auth vulnerable lab. Use it only on a network you are allowed to test.")
    app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
