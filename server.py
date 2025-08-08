import os, base64, secrets
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialUserEntity, PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity, \
    AttestationObject, AuthenticatorData


# from fido2.rp import PublicKeyCredentialRpEntity
# from fido2.client import ClientData
# from fido2.ctap2 import AttestationObject, AuthenticatorData

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

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

def json_creation_options(state: Dict[str, Any], user: Dict[str, Any], exclude_ids):
    return {
        "publicKey": {
            "rp": {"id": RP_ID, "name": RP_NAME},
            "user": {"id": b64u(user["id"]), "name": user["name"], "displayName": user["displayName"]},
            "challenge": b64u(state["challenge"]),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
            "timeout": 60000,
            "attestation": "none",
            "excludeCredentials": [{"type": "public-key", "id": b64u(cid)} for cid in exclude_ids],
            "authenticatorSelection": {"residentKey": "preferred", "userVerification": "preferred"}
        }
    }

def json_request_options(state: Dict[str, Any], allow_ids):
    o = {
        "publicKey": {
            "rpId": RP_ID,
            "challenge": b64u(state["challenge"]),
            "timeout": 60000,
            "userVerification": "preferred"
        }
    }
    if allow_ids:
        o["publicKey"]["allowCredentials"] = [{"type": "public-key", "id": b64u(cid)} for cid in allow_ids]
    return o

@app.post("/webauthn/register/options")
async def register_options(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip()
    display_name = (body.get("displayName") or "").strip() or None
    if not username: raise HTTPException(400, "username required")
    u = user_get_or_create(username, display_name)
    creds = [PublicKeyCredentialDescriptor("public-key", c["id"]) for c in u["credentials"]]
    _, state = server.register_begin(PublicKeyCredentialUserEntity(id=u["id"], name=u["name"], display_name=u["displayName"]), creds, user_verification="preferred", resident_key_requirement="preferred")
    req.session["reg"] = {"u": username, "state": state}
    return JSONResponse(json_creation_options(state, u, [c["id"] for c in u["credentials"]]))

@app.post("/webauthn/register/verify")
async def register_verify(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip()
    cred = body.get("credential") or {}
    st = req.session.get("reg")
    if not st or st.get("u") != username: raise HTTPException(400, "registration state missing")
    client = ClientData(b64ud(cred["response"]["clientDataJSON"]))
    att = AttestationObject(b64ud(cred["response"]["attestationObject"]))
    auth_data = server.register_complete(st["state"], client, att)
    USERS[username]["credentials"].append({
        "id": auth_data.credential_id,
        "public_key": auth_data.credential_public_key,
        "sign_count": auth_data.sign_count,
        "transports": cred.get("response", {}).get("transports") or []
    })
    req.session.pop("reg", None)
    return JSONResponse({"ok": True})

@app.post("/webauthn/authenticate/options")
async def authenticate_options(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip() or None
    allow_ids = None
    if username:
        u = USERS.get(username)
        if not u: raise HTTPException(404, "unknown user")
        allow_ids = [c["id"] for c in u["credentials"]]
    _, state = server.authenticate_begin(allow_ids)
    req.session["auth"] = {"state": state}
    return JSONResponse(json_request_options(state, allow_ids))

@app.post("/webauthn/authenticate/verify")
async def authenticate_verify(req: Request):
    body = await req.json()
    cred = body.get("credential") or {}
    st = req.session.get("auth")
    if not st: raise HTTPException(400, "authentication state missing")
    cred_id = b64ud(cred.get("rawId") or cred.get("id"))
    uname = find_user_by_cred_id(cred_id)
    if not uname: raise HTTPException(404, "credential not recognized")
    u = USERS[uname]
    key = next(c["public_key"] for c in u["credentials"] if c["id"] == cred_id)
    client = ClientData(b64ud(cred["response"]["clientDataJSON"]))
    authr = AuthenticatorData(b64ud(cred["response"]["authenticatorData"]))
    sig = b64ud(cred["response"]["signature"])
    server.authenticate_complete(st["state"], {cred_id: key}, cred_id, client, authr, sig)
    for c in u["credentials"]:
        if c["id"] == cred_id:
            c["sign_count"] = max(c.get("sign_count", 0), authr.sign_count)
            break
    req.session.pop("auth", None)
    return JSONResponse({"ok": True, "username": uname})

@app.get("/health")
async def health():
    return {"ok": True}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
