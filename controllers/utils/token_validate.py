import logging
import functools
from odoo.addons.odoo_api_token.controllers.utils.http_common import invalid_response
from odoo.addons.odoo_api_token.controllers.utils.response_types import ACCESS_TOKEN_NOT_FOUND, ACCESS_TOKEN_INVALID
from odoo.http import request

_logger = logging.getLogger(__name__)


def validate_token(func):
    @functools.wraps(func)
    def wrap(self, *args, **kwargs):
        if request.httprequest.headers.get("access_token"):
            access_token = request.httprequest.headers.get("access_token")
        elif request.httprequest.params.get("access_token"):
            access_token = request.httprequest.params.get("access_token")
        else:
            return invalid_response(ACCESS_TOKEN_NOT_FOUND[0], "missing access token in request header/parametter", ACCESS_TOKEN_NOT_FOUND[1])
        
        access_token_data = request.env["user.access.token"].sudo().search([("token", "=", access_token), ("is_expired", "=", False)],
                                                                          order="id DESC", limit=1)
        
        if access_token_data:
            current_token = access_token_data.find_or_create_token(user_id=access_token_data.user_id.id)
            
            if current_token and current_token[0] != access_token:
                return invalid_response(ACCESS_TOKEN_INVALID[0], "token seems to have expired or invalid", ACCESS_TOKEN_INVALID[1])
        else:
            return invalid_response(ACCESS_TOKEN_NOT_FOUND[0], "User not logged", ACCESS_TOKEN_NOT_FOUND[1])

        request.session.uid = access_token_data.user_id.id
        request.update_env(user=access_token_data.user_id.id)
        return func(self, *args, **kwargs)
    return wrap
