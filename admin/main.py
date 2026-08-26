"""MeshMessenger Admin Panel — FastAPI dashboard."""
import json
import os
from pathlib import Path
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="MeshMessenger Admin")
templates = Jinja2Templates(directory="templates")

ACCOUNTS_FILE = os.environ.get("MESH_ACCOUNTS", "accounts.json")
WEB_PASS = os.environ.get("MESH_WEB_PASS", "admin123")
admin_session = {"authed": False}


def load_accounts():
    try:
        with open(ACCOUNTS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_accounts(data):
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not admin_session["authed"]:
        return templates.TemplateResponse("login.html", {"request": request})
    accounts = load_accounts()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "accounts": accounts,
        "total": len(accounts),
    })


@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    if password != WEB_PASS:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверный пароль",
        })
    admin_session["authed"] = True
    return RedirectResponse("/", status_code=303)


@app.get("/logout")
async def logout():
    admin_session["authed"] = False
    return RedirectResponse("/", status_code=303)


@app.post("/ban/{username}")
async def ban_user(username: str):
    accounts = load_accounts()
    if username in accounts:
        accounts[username]["banned"] = True
        save_accounts(accounts)
    return RedirectResponse("/", status_code=303)


@app.post("/unban/{username}")
async def unban_user(username: str):
    accounts = load_accounts()
    if username in accounts:
        accounts[username]["banned"] = False
        save_accounts(accounts)
    return RedirectResponse("/", status_code=303)


@app.post("/delete/{username}")
async def delete_user(username: str):
    accounts = load_accounts()
    if username in accounts:
        del accounts[username]
        save_accounts(accounts)
    return RedirectResponse("/", status_code=303)


@app.get("/api/stats")
async def api_stats():
    accounts = load_accounts()
    return {
        "total_users": len(accounts),
        "users": list(accounts.keys()),
    }
