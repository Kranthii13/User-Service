"""
AI capability catalog — auto-derived from this service's OpenAPI schema.

Every registered route becomes a discoverable capability for LifeFlow AI.
Adding a new endpoint (with a docstring) automatically makes it available to
the AI chat — no manual registry file to maintain.
"""
from typing import Any, Dict, List

from fastapi import APIRouter, Request

router = APIRouter(tags=["System"])

_SKIP_PATHS = {
    "/", "/health", "/health/", "/ready", "/ready/",
    "/capabilities", "/capabilities/",
    "/docs", "/docs/", "/redoc", "/redoc/",
    "/openapi.json", "/openapi.json/",
}

_SKIP_TAGS = {"health", "system", "internal", "meta"}
_SKIP_METHODS = {"head", "options", "trace"}
# Routers are mounted at BOTH the root and under "/api/<service>". The gateway
# public path for a service call is "/api/<service>" + root-mounted path, so
# advertise only the root-mounted copies to avoid duplicates.
_API_PREFIX = "/api/"


def _resolve(schema: Dict[str, Any], components: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve a single $ref hop to the target component schema."""
    if not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if not ref:
        return schema
    name = str(ref).rsplit("/", 1)[-1]
    return components.get("schemas", {}).get(name, schema)


def build_capabilities(app: Any, service_key: str) -> Dict[str, Any]:
    """Build the AI-readable capability manifest from the app OpenAPI schema."""
    schema = app.openapi()
    components = schema.get("components", {})
    capabilities: List[Dict[str, Any]] = []

    for path, methods in schema.get("paths", {}).items():
        if path.startswith(_API_PREFIX):
            continue
        if path in _SKIP_PATHS:
            continue
        for verb, op in methods.items():
            if verb in _SKIP_METHODS or verb == "parameters":
                continue
            tags = [str(t).lower() for t in op.get("tags", [])]
            if _SKIP_TAGS.intersection(tags):
                continue

            summary = (
                op.get("summary")
                or (op.get("description") or "").strip().split("\n")[0]
                or f"{verb.upper()} {path}"
            )
            description = op.get("description") or ""

            params: List[Dict[str, Any]] = []
            for p in op.get("parameters", []):
                resolved = _resolve(p.get("schema"), components)
                params.append({
                    "name": p.get("name"),
                    "in": p.get("in"),
                    "required": bool(p.get("required") or p.get("in") == "path"),
                    "type": resolved.get("type") or p.get("schema", {}).get("type", "any"),
                    "default": p.get("schema", {}).get("default"),
                    "description": p.get("description"),
                })

            request_body = op.get("requestBody") or {}
            body_schema = (
                request_body.get("content", {})
                .get("application/json", {})
                .get("schema", {})
            )
            if body_schema:
                resolved_body = _resolve(body_schema, components)
                body_required = set(resolved_body.get("required", []) or [])
                for pname, prop in (resolved_body.get("properties") or {}).items():
                    params.append({
                        "name": pname,
                        "in": "body",
                        "required": pname in body_required,
                        "type": prop.get("type", "any"),
                        "default": prop.get("default"),
                        "description": prop.get("description"),
                    })

            capabilities.append({
                "name": f"{verb.upper()} {path}",
                "method": verb.upper(),
                "path": path,
                "summary": str(summary)[:300],
                "description": str(description)[:600],
                "params": params,
            })

    return {
        "service": service_key,
        "capabilities": capabilities,
    }


@router.get("/capabilities")
def capabilities_endpoint(request: Request) -> Dict[str, Any]:
    """GET /capabilities — AI service catalog for this backend service."""
    service_key = getattr(request.app.state, "service_key", "service")
    return build_capabilities(request.app, service_key)