"""MeshMessenger Admin Panel — FastAPI dashboard.
Безопасность:
- Сессии per-client: случайный токен в HttpOnly+SameSite cookie, серверный реестр
  с TTL. Старого глобального `admin_session` больше нет.
- Пароль: только `MESH_WEB_PASS`. Без env — генерируется случайный и печатается
  в stdout при старте (дефолта `admin123` больше нет).
- Сравнение пароля через hmac.compare_digest.
- /ban /unban /delete /api/stats требуют auth; POST-формы защищены CSRF-токеном.
- Лимит попыток входа: 10 / 5 мин с одного IP.
"""
import hmac
import json
import os
import re
import secrets
import time
from collections import defaultdict

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="MeshMessenger Admin")
templates = Jinja2Templates(directory="templates")

ACCOUNTS_FILE = os.environ.get("MESH_ACCOUNTS", "accounts.json")

WEB_PASS = os.environ.get("MESH_WEB_PASS")
if not WEB_PASS:
    WEB_PASS = secrets.token_urlsafe(24)
    print("!!! MESH_WEB_PASS не задан — сгенерирован временный пароль админки:", WEB_PASS,
          flush=True)
elif WEB_PASS == "admin123":
    print("!!! ВНИМАНИЕ: используется дефолтный пароль admin123 — задайте MESH_WEB_PASS!",
          flush=True)

SESSION_TTL = 12 * 3600
COOKIE_NAME = "mesh_admin"
# token -> {"csrf": str, "exp": float}
_sessions: dict = {}
# ip -> [count, window_start]
_login_attempts: dict = defaultdict(lambda: [0, 0.0])

USERNAME_RE = re.compile(r"^[A-Za-z0-9_@.\-]{1,32}$")


def load_accounts():
    try:
        with open(ACCOUNTS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_accounts(data):
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _get_session(request: Request):
    token = request.cookies.get(COOKIE_NAME, "")
    if not token:
        return None
    sess = _sessions.get(token)
    if not sess:
        return None
    if sess["exp"] < time.time():
        _sessions.pop(token, None)
        return None
    return sess


def _authed(request: Request):
    """Сессия или None (для HTML — редирект на логин)."""
    return _get_session(request)


def _require_api_auth(request: Request):
    if not _get_session(request):
        raise HTTPException(status_code=401, detail="unauthorized")
    return True


def _check_csrf(request: Request, sess: dict, token: str):
    if not token or not hmac.compare_digest(token, sess.get("csrf", "")):
        raise HTTPException(status_code=403, detail="bad csrf token")


def _valid_username(username: str) -> bool:
    return bool(USERNAME_RE.match(username or ""))


def _set_session_cookie(resp: RedirectResponse) -> str:
    token = secrets.token_urlsafe(32)
    _sessions[token] = {"csrf": secrets.token_urlsafe(24), "exp": time.time() + SESSION_TTL}
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", max_age=SESSION_TTL)
    return token


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    sess = _get_session(request)
    if not sess:
        return templates.TemplateResponse("login.html", {"request": request})
    accounts = load_accounts()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "accounts": accounts,
        "total": len(accounts),
        "csrf": sess["csrf"],
    })


@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    ip = request.client.host if request.client else "?"
    now = time.time()
    count, start = _login_attempts[ip]
    if now - start > 300:
        count, start = 0, now
    if count >= 10:
        raise HTTPException(status_code=429, detail="too many attempts, try later")
    _login_attempts[ip] = [count + 1, start]

    if not hmac.compare_digest(password or "", WEB_PASS):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверный пароль",
        }, status_code=401)
    _login_attempts.pop(ip, None)
    resp = RedirectResponse("/", status_code=303)
    _set_session_cookie(resp)
    return resp


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get(COOKIE_NAME, "")
    _sessions.pop(token, None)
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie(COOKIE_NAME)
    return resp


@app.post("/ban/{username}")
async def ban_user(request: Request, username: str, csrf: str = Form("")):
    sess = _authed(request)
    if not sess:
        return RedirectResponse("/", status_code=303)
    _check_csrf(request, sess, csrf)
    if not _valid_username(username):
        raise HTTPException(status_code=400, detail="bad username")
    accounts = load_accounts()
    if username in accounts:
        accounts[username]["banned"] = True
        save_accounts(accounts)
    return RedirectResponse("/", status_code=303)


@app.post("/unban/{username}")
async def unban_user(request: Request, username: str, csrf: str = Form("")):
    sess = _authed(request)
    if not sess:
        return RedirectResponse("/", status_code=303)
    _check_csrf(request, sess, csrf)
    if not _valid_username(username):
        raise HTTPException(status_code=400, detail="bad username")
    accounts = load_accounts()
    if username in accounts:
        accounts[username]["banned"] = False
        save_accounts(accounts)
    return RedirectResponse("/", status_code=303)


@app.post("/delete/{username}")
async def delete_user(request: Request, username: str, csrf: str = Form("")):
    sess = _authed(request)
    if not sess:
        return RedirectResponse("/", status_code=303)
    _check_csrf(request, sess, csrf)
    if not _valid_username(username):
        raise HTTPException(status_code=400, detail="bad username")
    accounts = load_accounts()
    if username in accounts:
        del accounts[username]
        save_accounts(accounts)
    return RedirectResponse("/", status_code=303)


@app.get("/api/stats")
async def api_stats(request: Request):
    _require_api_auth(request)
    accounts = load_accounts()
    return {
        "total_users": len(accounts),
        "users": list(accounts.keys()),
    }
