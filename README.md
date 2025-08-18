# fido2-passkeys

Minimal, self-contained demo of passkeys (WebAuthn) using FastAPI + `fido2`.
It serves a static `index.html` and exposes the WebAuthn endpoints a real backend would provide.
Data is persisted to a simple pickle file.

## What’s inside

```
.
├── server.py         # FastAPI backend (registration + authentication)
├── index.html        # Minimal client (create/sign-in with passkeys)
└── requirements.txt  # Dependencies
```

## Quick start

```bash
uv venv
uv pip install -r requirements.txt
uv run server.py
```

Open:
[http://localhost:8000](http://localhost:8000)

Notes:

* Use **localhost** (not 127.0.0.1). WebAuthn rejects IPs for RP ID.

## How it works

* **Registration**

    * `POST /webauthn/register-begin`
    * `POST /webauthn/register-complete`
* **Authentication**

    * `POST /webauthn/authenticate-begin`
    * `POST /webauthn/authenticate-complete`
* **UI**

    * `GET /` → serves `index.html`

The server validates challenges and origins, stores credential data, and updates signature counters.

## Persistence

* Simple file persistence via json.
* This is for demos/tests only. For production, use a real database and proper schemas.

## Intended use

* Local development and experimentation with passkeys/WebAuthn.
* A starting point to integrate passkeys into your own stack by replacing the storage layer and tightening security.

## Production checklist (non-exhaustive)

* Real domain and HTTPS
* Strong session management and CSRF protections where applicable
* Robust origin/RP ID configuration
* Database storage and migrations
* Auditing, logging, and rate limiting

## TODO
* Cleanup the 4 key methods to make them simpler and the 'code reads like well-written prose'
* Ask ChatGPT to add a UML mermaid.js diagram to explain passkeys to someone with zero knowledge about it