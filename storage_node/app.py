import hashlib
import os

from fastapi import FastAPI, HTTPException, Request, Response

from storage_node.db import ChunkStore


def create_app(node_id: str | None = None, db_path: str | None = None) -> FastAPI:
    node_id = node_id or os.environ.get("NODE_ID", "node-1")
    db_path = db_path or os.environ.get("DB_PATH", f"data/{node_id}.db")

    app = FastAPI(title=f"Storage Node ({node_id})")
    store = ChunkStore(db_path)

    @app.put("/chunks/{chunk_hash}")
    async def put_chunk(chunk_hash: str, request: Request):
        ciphertext = await request.body()
        computed = hashlib.sha256(ciphertext).hexdigest()
        if computed != chunk_hash:
            raise HTTPException(
                status_code=400,
                detail="content hash mismatch: ciphertext does not match requested address",
            )
        store.put(chunk_hash, ciphertext)
        return {"hash": chunk_hash, "size": len(ciphertext), "node": node_id}

    @app.get("/chunks/{chunk_hash}")
    async def get_chunk(chunk_hash: str):
        data = store.get(chunk_hash)
        if data is None:
            raise HTTPException(status_code=404, detail="chunk not found")
        return Response(content=data, media_type="application/octet-stream")

    @app.get("/health")
    async def health():
        return {"status": "ok", "node": node_id}

    return app


app = create_app()
