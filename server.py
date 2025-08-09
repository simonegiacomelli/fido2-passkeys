import os, base64, secrets, pickle, threading
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialDescriptor, AuthenticatorData, PublicKeyCredentialType, UserVerificationRequirement

PREFERRED = UserVerificationRequirement.PREFERRED

def b64ud(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "Passkey Demo")
ALLOWED_ORIGINS = {o.strip() for o in os.getenv("ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",") if o.strip()}

app = FastAPI()

server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME), attestation="none", verify_origin=lambda o: o in ALLOWED_ORIGINS)

DB_FILE = os.getenv("DB_FILE", os.path.join(os.path.dirname(__file__), "users.pickle"))
DB_LOCK = threading.Lock()
USERS: Dict[str, Dict[str, Any]] = {}

def db_load():
    global USERS
    try:
        with open(DB_FILE, "rb") as f:
            USERS = pickle.load(f)
    except Exception:
        USERS = {}

def db_save():
    with DB_LOCK:
        tmp = DB_FILE + ".tmp"
        with open(tmp, "wb") as f:
            pickle.dump(USERS, f, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, DB_FILE)

db_load()

def user_get_or_create(username: str, display_name: Optional[str]) -> Dict[str, Any]:
    u = USERS.get(username)
    if not u:
        u = {"id": secrets.token_bytes(16), "name": username, "displayName": display_name or username, "credentials": []}
        USERS[username] = u
    elif display_name:
        u["displayName"] = display_name
    return u

def find_user_by_cred_id(cred_id: bytes) -> Optional[str]:
    for uname, u in USERS.items():
        for c in u["credentials"]:
            if c["id"] == cred_id: return uname
    return None

def pk_descriptors(u: Dict[str, Any]):
    return [PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=c["id"]) for c in u["credentials"]]

def update_counter(u: Dict[str, Any], cred_id: bytes, counter: int):
    for c in u["credentials"]:
        if c["id"] == cred_id:
            c["sign_count"] = max(c.get("sign_count", 0), counter)
            return

SESS_FILE = os.getenv("SESS_FILE", os.path.join(os.path.dirname(__file__), "sessions.pickle"))
SESS_LOCK = threading.Lock()
SESSIONS: Dict[str, Dict[str, Any]] = {}

def sess_load():
    global SESSIONS
    try:
        with open(SESS_FILE, "rb") as f:
            SESSIONS = pickle.load(f)
    except Exception:
        SESSIONS = {}

def sess_save():
    with SESS_LOCK:
        tmp = SESS_FILE + ".tmp"
        with open(tmp, "wb") as f:
            pickle.dump(SESSIONS, f, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, SESS_FILE)

sess_load()

def get_session(req: Request) -> Dict[str, Any]:
    sid = req.headers.get("id")
    if not sid: raise HTTPException(401, "missing session id")
    s = SESSIONS.get(sid)
    if s is None: raise HTTPException(401, "invalid session id")
    return s

@app.post("/session/new")
async def session_new():
    sid = secrets.token_urlsafe(32)
    SESSIONS[sid] = {}
    sess_save()
    return JSONResponse({"id": sid})

@app.post("/webauthn/register-options")
async def register_options(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip()
    display_name = (body.get("displayName") or "").strip() or None
    if not username: raise HTTPException(400, "username required")
    u = user_get_or_create(username, display_name)
    opts, state = server.register_begin(PublicKeyCredentialUserEntity(name=u["name"], id=u["id"], display_name=u["displayName"]), pk_descriptors(u), user_verification=PREFERRED, resident_key_requirement=PREFERRED)
    s = get_session(req)
    s["reg"] = {"u": username, "state": state}
    sess_save()
    return JSONResponse(dict(opts))

@app.post("/webauthn/register-verify")
async def register_verify(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip()
    cred = body.get("credential") or {}
    s = get_session(req)
    st = s.get("reg")
    if not st or st.get("u") != username: raise HTTPException(400, "registration state missing")
    res = server.register_complete(st["state"], cred)
    cd = res.credential_data
    USERS[username]["credentials"].append({"id": cd.credential_id, "data": cd, "sign_count": res.counter, "transports": cred.get("response", {}).get("transports") or []})
    s.pop("reg", None)
    sess_save()
    db_save()
    return JSONResponse({"ok": True})

@app.post("/webauthn/authenticate-options")
async def authenticate_options(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip() or None
    descriptors = None
    if username:
        u = USERS.get(username)
        if not u: raise HTTPException(404, "unknown user")
        descriptors = pk_descriptors(u)
    opts, state = server.authenticate_begin(descriptors, user_verification=PREFERRED)
    s = get_session(req)
    s["auth"] = {"state": state}
    sess_save()
    return JSONResponse(dict(opts))

@app.post("/webauthn/authenticate-verify")
async def authenticate_verify(req: Request):
    body = await req.json()
    cred = body.get("credential") or {}
    s = get_session(req)
    st = s.get("auth")
    if not st: raise HTTPException(400, "authentication state missing")
    raw_id = b64ud(cred.get("rawId") or cred.get("id"))
    uname = find_user_by_cred_id(raw_id)
    if not uname: raise HTTPException(404, "credential not recognized")
    u = USERS[uname]
    server.authenticate_complete(st["state"], [c["data"] for c in u["credentials"]], cred)
    ad = AuthenticatorData(b64ud(cred["response"]["authenticatorData"]))
    update_counter(u, raw_id, ad.counter)
    s.pop("auth", None)
    sess_save()
    db_save()
    return JSONResponse({"ok": True, "username": uname})

@app.get("/health")
async def health():
    return {"ok": True}

@app.get("/", include_in_schema=False)
async def index():
    path = os.path.join(os.path.dirname(__file__), "index.html")
    if not os.path.exists(path): raise HTTPException(404, "index.html not found")
    return FileResponse(path, media_type="text/html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)
