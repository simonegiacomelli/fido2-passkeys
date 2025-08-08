import os, base64, secrets
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException
# from fastapi.responses import JSONResponse
from fastapi.responses import JSONResponse, FileResponse
from starlette.middleware.sessions import SessionMiddleware
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialDescriptor, AuthenticatorData

def b64ud(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "Passkey Demo")
ALLOWED_ORIGINS = set([o.strip() for o in os.getenv("ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",") if o.strip()])

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", secrets.token_urlsafe(32)))

rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp, attestation="none", verify_origin=lambda origin: origin in ALLOWED_ORIGINS)

USERS: Dict[str, Dict[str, Any]] = {}

def user_get_or_create(username: str, display_name: Optional[str]) -> Dict[str, Any]:
    u = USERS.get(username)
    if not u:
        u = {"id": secrets.token_bytes(16), "name": username, "displayName": display_name or username, "credentials": []}
        USERS[username] = u
    else:
        if display_name: u["displayName"] = display_name
    return u

def find_user_by_cred_id(cred_id: bytes) -> Optional[str]:
    for uname, u in USERS.items():
        for c in u["credentials"]:
            if c["id"] == cred_id: return uname
    return None

@app.post("/webauthn/register/options")
async def register_options(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip()
    display_name = (body.get("displayName") or "").strip() or None
    if not username: raise HTTPException(400, "username required")
    u = user_get_or_create(username, display_name)
    descriptors = [PublicKeyCredentialDescriptor(id=c["id"]) for c in u["credentials"]]
    opts, state = server.register_begin(PublicKeyCredentialUserEntity(name=u["name"], id=u["id"], display_name=u["displayName"]), descriptors, user_verification="preferred", resident_key_requirement="preferred")
    req.session["reg"] = {"u": username, "state": state}
    return JSONResponse(opts.to_json())

@app.post("/webauthn/register/verify")
async def register_verify(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip()
    cred = body.get("credential") or {}
    st = req.session.get("reg")
    if not st or st.get("u") != username: raise HTTPException(400, "registration state missing")
    res = server.register_complete(st["state"], cred)
    cd = res.credential_data
    USERS[username]["credentials"].append({"id": cd.credential_id, "data": cd, "sign_count": res.counter, "transports": cred.get("response", {}).get("transports") or []})
    req.session.pop("reg", None)
    return JSONResponse({"ok": True})

@app.post("/webauthn/authenticate/options")
async def authenticate_options(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip() or None
    descriptors = None
    if username:
        u = USERS.get(username)
        if not u: raise HTTPException(404, "unknown user")
        descriptors = [PublicKeyCredentialDescriptor(id=c["id"]) for c in u["credentials"]]
    opts, state = server.authenticate_begin(descriptors, user_verification="preferred")
    req.session["auth"] = {"state": state}
    return JSONResponse(opts.to_json())

@app.post("/webauthn/authenticate/verify")
async def authenticate_verify(req: Request):
    body = await req.json()
    cred = body.get("credential") or {}
    st = req.session.get("auth")
    if not st: raise HTTPException(400, "authentication state missing")
    raw_id = b64ud(cred.get("rawId") or cred.get("id"))
    uname = find_user_by_cred_id(raw_id)
    if not uname: raise HTTPException(404, "credential not recognized")
    u = USERS[uname]
    server.authenticate_complete(st["state"], [c["data"] for c in u["credentials"]], cred)
    ad = AuthenticatorData(b64ud(cred["response"]["authenticatorData"]))
    for c in u["credentials"]:
        if c["id"] == raw_id:
            c["sign_count"] = max(c.get("sign_count", 0), ad.sign_count)
            break
    req.session.pop("auth", None)
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
    uvicorn.run(app, host="0.0.0.0", port=8000)
