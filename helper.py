import json, base64
from fido2.webauthn import AttestedCredentialData
from fido2.cose import CoseKey
from fido2 import cbor


def b64enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def json_encode(o):
    if isinstance(o, AttestedCredentialData):
        return {
            "type": "AttestedCredentialData",
            "aaguid": bytes(o.aaguid).hex(),
            "credential_id": b64enc(o.credential_id),
            "public_key_cbor": b64enc(cbor.encode(o.public_key))
        }
    if isinstance(o, (bytes, bytearray, memoryview)):
        return {"__bytes__": b64enc(bytes(o))}
    if hasattr(o, "_asdict"):
        return o._asdict()
    if hasattr(o, "__dict__"):
        return o.__dict__
    return str(o)


def json_decode(obj):
    if isinstance(obj, dict) and obj.get("type") == "AttestedCredentialData":
        aaguid = bytes.fromhex(obj["aaguid"])
        cred_id = b64dec(obj["credential_id"])
        pub_key = CoseKey.parse(cbor.decode(b64dec(obj["public_key_cbor"])))
        return AttestedCredentialData.create(aaguid, cred_id, pub_key)
    if isinstance(obj, dict) and "__bytes__" in obj:
        return b64dec(obj["__bytes__"])
    return obj


def dumps(o) -> str:
    return json.dumps(o, default=json_encode, indent=2)


def loads(s: str):
    return json.loads(s, object_hook=json_decode)
