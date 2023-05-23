import jwt
import logging
from datetime import datetime, timedelta
from odoo import fields, models
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT
from odoo.http import request

_logger = logging.getLogger(__name__)

# we can make the expiry as a value taken from the
token_expiry_date_in = "project_api.access_token_token_expiry_date_in"


def create_token(data):
    return jwt.encode(data, "secret", algorithm="HS256")


class UserAccessToken(models.Model):
    _name = "user.access.token"
    _description = "User Access Token"

    token = fields.Char("Token", required=True)
    scope = fields.Char(string="Scope")
    user_id = fields.Many2one("res.users", string="User", required=True)
    token_expiry_date = fields.Datetime(string="Token Expiry Date", required=True)
    is_expired = fields.Boolean("is_expired", default=False)

    _sql_constraints = [
        ('unique_token', 'UNIQUE(token)', ('token can not be duplicated'))
    ]

    def find_or_create_token(self, user_id=None, create=False):
        if not user_id:
            user_id = self.env.user.id
            
        access_token = self.env["user.access.token"].sudo().search([("user_id", "=", user_id)], order="id DESC", limit=1)
        if access_token:
            access_token = access_token[0]
            if access_token.has_expired():
                access_token = None
        if not access_token and create:
            token_expiry_date = datetime.now() + timedelta(days=1)
            payload_data = {
                "uid": self.env.user.id,
                "name": self.env.user.name,
                "username": self.env.user.login,
                "database": request.db,
                "company": self.env.user.company_id.name,
               # "user_context": self.env.user.context_get(),
                "expire_date": token_expiry_date.isoformat(" ")
            }
            vals = {
                "user_id": user_id,
                "scope": "userinfo",
                "token_expiry_date": token_expiry_date.strftime(DEFAULT_SERVER_DATETIME_FORMAT),
                "token": create_token(payload_data),
            }
            access_token = self.env["user.access.token"].sudo().create(vals)
        if not access_token:
            return None
        return (access_token.token, access_token.token_expiry_date.isoformat(" "))

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.

        :param scopes: An iterable containing the scopes to check or None
        """
        self.ensure_one()
        return not self.has_expired() and self._allow_scopes(scopes)

    def invalidate_token(self):
        self.token_expiry_date = datetime.now()
        self.is_expired = True
    
    def has_expired(self):
        self.ensure_one()
        return datetime.now() > fields.Datetime.from_string(self.token_expiry_date)

    def _allow_scopes(self, scopes):
        self.ensure_one()
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)


class Users(models.Model):
    _inherit = "res.users"

    token_id = fields.One2many("user.access.token", "user_id", string="Access Tokens")
