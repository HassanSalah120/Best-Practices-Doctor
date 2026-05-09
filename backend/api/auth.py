from fastapi import Request, HTTPException
import os
from config import settings


async def verify_token(request: Request):
    """
    Middleware to verify the security token.
    Allows Health Check and SSE (via query param if needed, or headers).
    """
    # Skip for public endpoints
    if request.url.path in ["/api/health", "/api/version"]:
        return

    # Skip for OPTIONS (preflight)
    if request.method == "OPTIONS":
        return

    # Local/dev mode: auth can be disabled explicitly.
    if not settings.require_auth:
        return

    # Get token from environment (set by main.py)
    expected_token = os.environ.get("APP_AUTH_TOKEN", "")
    if not expected_token:
        # Fallback to local dev if not set (optional, or strict for production)
        return

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        # Check query param as fallback for SSE (EventSource doesn't support headers easily)
        token_query = request.query_params.get("token")
        if token_query == expected_token:
            return
        
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Missing or invalid security token"
        )

    token = auth_header.split(" ")[1]
    if token != expected_token:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Invalid security token"
        )
