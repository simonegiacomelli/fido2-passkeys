import os
import secrets
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialDescriptor, \
    AuthenticatorData, PublicKeyCredentialType, UserVerificationRequirement

from helper import FileMap, b64dec

PREFERRED = UserVerificationRequirement.PREFERRED

RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "Passkey Demo")
ALLOWED_ORIGINS = {o.strip() for o in os.getenv("ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",") if
                   o.strip()}

app = FastAPI()

server = Fido2Server(PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME), attestation="none",
                     verify_origin=lambda o: o in ALLOWED_ORIGINS)

USERS_FILE = os.getenv("USERS_FILE", os.path.join(os.path.dirname(__file__), "users.json"))
SESS_FILE = os.getenv("SESS_FILE", os.path.join(os.path.dirname(__file__), "sessions.json"))

users = FileMap(USERS_FILE)
sessions = FileMap(SESS_FILE)


def user_get_or_create(username: str, display_name: Optional[str]) -> Dict[str, Any]:
    return users.lock(lambda m: m.setdefault(username, {"user_id": secrets.token_bytes(16), "name": username,
                                                        "displayName": display_name or username,
                                                        "credentials": []}) if username not in m else (m[
                                                                                                           username].update(
        {"displayName": display_name}) if display_name else None) or m[username])


def find_user_by_cred_id(cred_id: bytes) -> Optional[str]:
    for uname, u in users.read().items():
        for c in u["credentials"]:
            if c["data"].credential_id == cred_id:
                return uname
    return None


def pk_descriptors(u: Dict[str, Any]):
    return [PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=c["data"].credential_id) for c in
            u["credentials"]]


def update_counter(uname: str, cred_id: bytes, counter: int):
    users.lock(lambda m: next(
        (c.update({"sign_count": max(c.get("sign_count", 0), counter)}) for c in m.get(uname, {}).get("credentials", [])
         if c["data"].credential_id == cred_id), None))


def get_sid(req: Request) -> str:
    sid = req.headers.get("id")
    if not sid:
        raise HTTPException(401, "missing session id")
    if sid not in sessions.read():
        raise HTTPException(401, "invalid session id")
    return sid


@app.post("/session/new")
async def session_new():
    sid = secrets.token_urlsafe(32)
    sessions.lock(lambda m: m.setdefault(sid, {}))
    return JSONResponse({"id": sid})


@app.post("/webauthn/register-begin")
async def register_begin(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip()
    display_name = (body.get("displayName") or "").strip() or None
    if not username:
        raise HTTPException(400, "username required")
    u = user_get_or_create(username, display_name)
    opts, state = server.register_begin(
        PublicKeyCredentialUserEntity(name=u["name"], id=u["user_id"], display_name=u["displayName"]),
        pk_descriptors(u),
        user_verification=PREFERRED,
        resident_key_requirement=PREFERRED,
    )
    sid = get_sid(req)
    sessions.lock(lambda m: m.setdefault(sid, {}).update({"reg": {"u": username, "state": state}}))
    return JSONResponse(dict(opts))


@app.post("/webauthn/register-complete")
async def register_complete(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip()
    sid = get_sid(req)
    s = sessions.read().get(sid) or {}
    st = s.get("reg")
    if not st or st.get("u") != username:
        raise HTTPException(400, "registration state missing")
    cred = body.get("credential") or {}
    res = server.register_complete(st["state"], cred)
    cd = res.credential_data
    users.lock(lambda m: m[username]["credentials"].append(
        {"data": cd, "sign_count": res.counter, "transports": cred.get("response", {}).get("transports") or []}))
    sessions.lock(lambda m: m.get(sid, {}).pop("reg", None))
    return JSONResponse({"ok": True})


@app.post("/webauthn/authenticate-begin")
async def authenticate_begin(req: Request):
    body = await req.json()
    username = (body.get("username") or "").strip() or None
    descriptors = None
    if username:
        u = users.read().get(username)
        if not u:
            raise HTTPException(404, "unknown user")
        descriptors = pk_descriptors(u)
    opts, state = server.authenticate_begin(descriptors, user_verification=PREFERRED)
    sid = get_sid(req)
    sessions.lock(lambda m: m.setdefault(sid, {}).update({"auth": {"state": state}}))
    return JSONResponse(dict(opts))


@app.post("/webauthn/authenticate-complete")
async def authenticate_complete(req: Request):
    body = await req.json()
    sid = get_sid(req)
    s = sessions.read().get(sid) or {}
    st = s.get("auth")
    if not st:
        raise HTTPException(400, "authentication state missing")
    cred = body.get("credential") or {}
    raw_id = b64dec(cred.get("rawId") or cred.get("id"))
    uname = find_user_by_cred_id(raw_id)
    if not uname:
        raise HTTPException(404, "credential not recognized")
    u = users.read()[uname]
    server.authenticate_complete(st["state"], [c["data"] for c in u["credentials"]], cred)
    ad = AuthenticatorData(b64dec(cred["response"]["authenticatorData"]))
    update_counter(uname, raw_id, ad.counter)
    sessions.lock(lambda m: m.get(sid, {}).pop("auth", None))
    return JSONResponse({"ok": True, "username": uname})


@app.get("/", include_in_schema=False)
async def index():
    path = os.path.join(os.path.dirname(__file__), "index.html")
    if not os.path.exists(path):
        raise HTTPException(404, "index.html not found")
    return FileResponse(path, media_type="text/html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="localhost", port=8000)
