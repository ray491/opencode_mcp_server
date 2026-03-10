from odoo import http
from odoo.exceptions import AccessDenied
from odoo.http import request


def _truthy(value):
    return str(value or "").lower() in {"1", "true", "yes", "y"}


def _require_token(payload):
    token = request.env["ir.config_parameter"].sudo().get_param("mcp.token")
    if not token:
        return
    provided = None
    if isinstance(payload, dict):
        provided = payload.get("token")
    if not provided:
        provided = request.httprequest.headers.get("X-MCP-Token")
    if provided != token:
        raise AccessDenied("Invalid MCP token")


def _authenticate(payload):
    params = request.env["ir.config_parameter"].sudo()
    require_auth = _truthy(params.get_param("mcp.require_auth", "1"))
    login = None
    api_key = None
    if isinstance(payload, dict):
        login = payload.get("login")
        api_key = payload.get("api_key")
    if not login:
        login = request.httprequest.headers.get("X-Odoo-Login")
    if not api_key:
        api_key = request.httprequest.headers.get("X-Odoo-Api-Key")
    db = None
    if isinstance(payload, dict):
        db = payload.get("db")
    if not db:
        db = request.params.get("db") or request.db
    if login and api_key and db:
        uid = request.session.authenticate(db, login, api_key)
        if not uid:
            raise AccessDenied("Invalid Odoo credentials")
        return request.env(user=uid)
    if require_auth:
        raise AccessDenied("Authentication required")
    return request.env


def _check_model_access(model: str, operation: str):
    params = request.env["ir.config_parameter"].sudo()
    default_deny = _truthy(params.get_param("mcp.default_deny", "1"))
    access = (
        request.env["mcp.model.access"]
        .sudo()
        .search([("model_id.model", "=", model)], limit=1)
    )
    if not access:
        if default_deny:
            raise AccessDenied("Model not enabled for MCP")
        return
    allowed = {
        "read": access.can_read,
        "create": access.can_create,
        "write": access.can_write,
        "unlink": access.can_unlink,
    }.get(operation)
    if not allowed:
        raise AccessDenied("Operation not allowed for this model")


class MCPController(http.Controller):
    @http.route(
        "/mcp/ping",
        type="json",
        auth="none",
        methods=["POST"],
        csrf=False,
    )
    def ping(self, **payload):
        _require_token(payload)
        _authenticate(payload)
        return {"ok": True}

    @http.route(
        "/mcp/models",
        type="json",
        auth="none",
        methods=["POST"],
        csrf=False,
    )
    def models(self, **payload):
        _require_token(payload)
        _authenticate(payload)
        models = request.env["ir.model"].sudo().search([])
        access_records = request.env["mcp.model.access"].sudo().search([])
        access_map = {rec.model_id.model: rec for rec in access_records}
        result = []
        for rec in models:
            access = access_map.get(rec.model)
            result.append(
                {
                    "model": rec.model,
                    "name": rec.name,
                    "transient": rec.transient,
                    "can_read": bool(access and access.can_read),
                    "can_create": bool(access and access.can_create),
                    "can_write": bool(access and access.can_write),
                    "can_unlink": bool(access and access.can_unlink),
                }
            )
        return result

    @http.route(
        "/mcp/fields",
        type="json",
        auth="none",
        methods=["POST"],
        csrf=False,
    )
    def fields(self, **payload):
        _require_token(payload)
        env = _authenticate(payload)
        model = payload.get("model")
        if not model:
            raise ValueError("model is required")
        _check_model_access(model, "read")
        field_names = payload.get("field_names") or None
        return env[model].fields_get(field_names)

    @http.route(
        "/mcp/search_read",
        type="json",
        auth="none",
        methods=["POST"],
        csrf=False,
    )
    def search_read(self, **payload):
        _require_token(payload)
        env = _authenticate(payload)
        model = payload.get("model")
        if not model:
            raise ValueError("model is required")
        _check_model_access(model, "read")
        domain = payload.get("domain") or []
        fields = payload.get("fields") or None
        limit = int(payload.get("limit") or 0) or None
        offset = int(payload.get("offset") or 0)
        order = payload.get("order") or None
        return env[model].search_read(
            domain=domain,
            fields=fields,
            limit=limit,
            offset=offset,
            order=order,
        )

    @http.route(
        "/mcp/read",
        type="json",
        auth="none",
        methods=["POST"],
        csrf=False,
    )
    def read(self, **payload):
        _require_token(payload)
        env = _authenticate(payload)
        model = payload.get("model")
        if not model:
            raise ValueError("model is required")
        _check_model_access(model, "read")
        ids = payload.get("ids") or []
        fields = payload.get("fields") or None
        return env[model].browse(ids).read(fields=fields)

    @http.route(
        "/mcp/create",
        type="json",
        auth="none",
        methods=["POST"],
        csrf=False,
    )
    def create(self, **payload):
        _require_token(payload)
        env = _authenticate(payload)
        model = payload.get("model")
        if not model:
            raise ValueError("model is required")
        _check_model_access(model, "create")
        values = payload.get("values") or {}
        record = env[model].create(values)
        fields = payload.get("fields") or None
        if fields:
            return record.read(fields=fields)
        return {"id": record.id}

    @http.route(
        "/mcp/write",
        type="json",
        auth="none",
        methods=["POST"],
        csrf=False,
    )
    def write(self, **payload):
        _require_token(payload)
        env = _authenticate(payload)
        model = payload.get("model")
        if not model:
            raise ValueError("model is required")
        _check_model_access(model, "write")
        ids = payload.get("ids") or []
        values = payload.get("values") or {}
        updated = env[model].browse(ids).write(values)
        return {"updated": bool(updated), "count": len(ids)}

    @http.route(
        "/mcp/unlink",
        type="json",
        auth="none",
        methods=["POST"],
        csrf=False,
    )
    def unlink(self, **payload):
        _require_token(payload)
        env = _authenticate(payload)
        model = payload.get("model")
        if not model:
            raise ValueError("model is required")
        _check_model_access(model, "unlink")
        ids = payload.get("ids") or []
        deleted = env[model].browse(ids).unlink()
        return {"deleted": bool(deleted), "count": len(ids)}
