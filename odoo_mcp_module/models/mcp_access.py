from odoo import fields, models


class McpModelAccess(models.Model):
    _name = "mcp.model.access"
    _description = "MCP Model Access"
    _order = "model_id"

    model_id = fields.Many2one(
        "ir.model",
        string="Model",
        required=True,
        ondelete="cascade",
    )
    can_read = fields.Boolean(default=True)
    can_create = fields.Boolean(default=False)
    can_write = fields.Boolean(default=False)
    can_unlink = fields.Boolean(default=False)

    _sql_constraints = [
        ("mcp_model_unique", "unique(model_id)", "Model must be unique."),
    ]
