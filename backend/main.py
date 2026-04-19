"""
Best Practices Doctor - FastAPI Application
Main entry point with ephemeral port and lifecycle management.
"""
import asyncio
import secrets
import time
import uuid
import sys
import os
import socket
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse, ORJSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from config import settings, write_discovery_file, cleanup_port_file
from api.routes import router
from core.logging_setup import configure_logging


configure_logging()
logger = logging.getLogger(__name__)

try:
    import orjson as _orjson  # type: ignore

    DEFAULT_RESPONSE_CLASS = ORJSONResponse
except Exception:
    _orjson = None
    DEFAULT_RESPONSE_CLASS = JSONResponse


def get_ephemeral_port() -> int:
    """Get an available ephemeral port."""
    if settings.port != 0:
        return settings.port
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((settings.host, 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle."""
    # Startup
    # When launched via `python main.py`, main() sets these values so Tauri can
    # discover the backend. When launched via `uvicorn main:app`, they will be
    # missing; run in "dev/standalone" mode without discovery file.
    port = getattr(app.state, "port", None)
    token = getattr(app.state, "token", None)
    run_id = getattr(app.state, "run_id", None)

    discovery_path = None
    if port is not None and token and run_id:
        discovery_path = write_discovery_file(run_id, int(port), str(token))
        app.state.discovery_path = discovery_path
        logger.info("Backend started", extra={"host": settings.host, "port": port, "discovery": str(discovery_path)})
    else:
        logger.info("Backend started (standalone mode)")
    
    yield
    
    # Shutdown
    if discovery_path is not None and discovery_path.exists():
        # Windows can temporarily lock files (e.g., AV/indexer). Be resilient.
        try:
            discovery_path.unlink()
        except PermissionError:
            for _ in range(10):
                try:
                    await asyncio.sleep(0.05)
                    if discovery_path.exists():
                        discovery_path.unlink()
                    break
                except FileNotFoundError:
                    break
                except PermissionError:
                    continue
    logger.info("Backend shutdown complete")


app = FastAPI(
    title="Best Practices Doctor",
    description="Local Laravel/PHP code quality auditor",
    version="1.0.0",
    lifespan=lifespan,
    default_response_class=DEFAULT_RESPONSE_CLASS,
)

# CORS - strict for Tauri (localhost only)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:1420",
        "http://127.0.0.1:1420",
        "tauri://localhost",
        "https://tauri.localhost",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(router)


@app.get("/")
async def root():
    """Human-friendly landing endpoint (helps when opening the backend URL in a browser)."""
    return {
        "name": "Best Practices Doctor Backend",
        "api_base": "/api",
        "health": "/api/health",
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for Tauri."""
    return {"status": "healthy", "version": "1.0.0"}


def handle_signal(signum, frame):
    """Handle shutdown signals gracefully."""
    # Note: Modern FastAPI/Uvicorn often handles this, but we keep it for robustness
    cleanup_port_file()
    sys.exit(0)


import argparse

def main() -> None:
    """Run the backend with an ephemeral port and discovery file."""
    # Parse CLI arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", type=str, help="Unique run ID from Tauri")
    args = parser.parse_args()

    # Generate unique run ID and token
    # Use provided run_id (from Tauri) or fallback to random (dev mode)
    run_id = args.run_id if args.run_id else secrets.token_hex(8)
    token = secrets.token_urlsafe(32)
    
    app.state.run_id = run_id
    app.state.token = token
    os.environ["APP_AUTH_TOKEN"] = token
    os.environ["BPD_STARTED_AT"] = str(int(time.time()))
    
    # Get ephemeral port
    port = get_ephemeral_port()
    app.state.port = port
    
    # Run server
    uvicorn.run(
        app,
        host=settings.host,
        port=port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
