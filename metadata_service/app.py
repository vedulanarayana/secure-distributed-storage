import os
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response

from anomaly.features import extract_features
from anomaly.score import score_event
from client.manifest import verify_manifest
from metadata_service.auth import generate_api_key, hash_key
from metadata_service.db import MetadataStore
from metadata_service.rbac import has_permission

ACCESS_WINDOW_SECONDS = 300


def create_app(db_path: str | None = None, hmac_secret: bytes | None = None) -> FastAPI:
    db_path = db_path or os.environ.get("METADATA_DB_PATH", "data/metadata.db")
    hmac_secret = hmac_secret or os.environ.get(
        "METADATA_HMAC_SECRET", "dev-only-shared-hmac-secret-change-me"
    ).encode()

    app = FastAPI(title="Metadata Service")
    store = MetadataStore(db_path)

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def get_current_user(
        request: Request,
        x_user_id: str = Header(...),
        x_api_key: str = Header(...),
    ) -> str:
        if not store.verify_user(x_user_id, x_api_key):
            store.log_access(x_user_id, None, "auth", client_ip(request), 0, False)
            raise HTTPException(status_code=401, detail="invalid credentials")
        return x_user_id

    def record_and_score(
        user_id: str,
        file_id: str | None,
        action: str,
        source_ip: str,
        bytes_transferred: int,
        success: bool,
    ) -> bool:
        """Log the access, then score it against the anomaly model.

        Flags feed into the RBAC layer as a step-up-auth signal - see
        THREAT_MODEL.md for why this never silently blocks on its own.
        """
        log_id = store.log_access(user_id, file_id, action, source_ip, bytes_transferred, success)
        recent = store.recent_events(user_id, ACCESS_WINDOW_SECONDS)
        current = {"timestamp": time.time(), "bytes_transferred": bytes_transferred, "success": success}
        features = extract_features(recent, current)
        score, flagged = score_event(features)
        store.update_flag(log_id, score, flagged)
        return flagged

    @app.post("/users")
    async def create_user(payload: dict):
        user_id = payload["user_id"]
        api_key = generate_api_key()
        store.create_user(user_id, hash_key(api_key))
        return {"user_id": user_id, "api_key": api_key}

    @app.post("/files")
    async def create_file(payload: dict, request: Request, user_id: str = Depends(get_current_user)):
        file_id = payload["file_id"]
        manifest = payload["manifest"]
        signature = payload["signature"]

        if not verify_manifest(hmac_secret, manifest, signature):
            raise HTTPException(status_code=400, detail="manifest signature verification failed")

        store.create_file(file_id, owner_id=user_id, manifest=manifest, signature=signature)
        store.grant_permission(user_id, file_id, "owner")
        record_and_score(user_id, file_id, "upload_manifest", client_ip(request), len(str(manifest)), True)
        return {"file_id": file_id, "status": "registered"}

    @app.post("/files/{file_id}/share")
    async def share_file(
        file_id: str, payload: dict, request: Request, user_id: str = Depends(get_current_user)
    ):
        if not has_permission(store, user_id, file_id, "owner"):
            record_and_score(user_id, file_id, "share", client_ip(request), 0, False)
            raise HTTPException(status_code=403, detail="only the file owner may share access")

        recipient_id = payload["user_id"]
        store.set_wrapped_key(file_id, recipient_id, payload["wrapped_key"])
        store.grant_permission(recipient_id, file_id, payload.get("permission", "read"))
        record_and_score(user_id, file_id, "share", client_ip(request), 0, True)
        return {"status": "shared", "file_id": file_id, "user_id": recipient_id}

    @app.get("/files/{file_id}/manifest")
    async def get_manifest(
        file_id: str, request: Request, response: Response, user_id: str = Depends(get_current_user)
    ):
        if not has_permission(store, user_id, file_id, "read"):
            record_and_score(user_id, file_id, "download_manifest", client_ip(request), 0, False)
            raise HTTPException(status_code=403, detail="access denied")

        row = store.get_file(file_id)
        if row is None:
            raise HTTPException(status_code=404, detail="file not found")

        flagged = record_and_score(
            user_id, file_id, "download_manifest", client_ip(request), len(row["manifest_raw"]), True
        )
        if flagged:
            response.headers["X-Step-Up-Required"] = "true"
        return {"manifest": row["manifest"], "signature": row["signature"]}

    @app.get("/files/{file_id}/keys/{recipient_id}")
    async def get_wrapped_key(
        file_id: str, recipient_id: str, caller_id: str = Depends(get_current_user)
    ):
        if caller_id != recipient_id and not has_permission(store, caller_id, file_id, "owner"):
            raise HTTPException(status_code=403, detail="access denied")

        wrapped = store.get_wrapped_key(file_id, recipient_id)
        if wrapped is None:
            raise HTTPException(status_code=404, detail="no key available for this user/file")
        return {"wrapped_key": wrapped}

    @app.get("/admin/flags")
    async def list_flags():
        return {"flags": store.list_flagged()}

    return app


app = create_app()
