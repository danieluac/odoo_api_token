import json
import logging
import werkzeug.wrappers

from odoo import http
from odoo.addons.odoo_api_token.controllers.utils.http_common import invalid_response
from odoo.exceptions import AccessDenied, AccessError
from odoo.http import request
from odoo.addons.odoo_api_token.controllers.utils.token_validate import validate_token


_logger = logging.getLogger(__name__)

class AuthAccessToken(http.Controller):

    def get_login_params(self, post):
        params = {"db": None, "login": None, "password": None}
        params = {key: post.get(key) for key in params if post.get(key)}

        if not params.get("db"):
            params["db"] = request.db
        
        if not all([params.get("db"), params.get("login"), params.get("password")]):
            headers = request.httprequest.headers
            params = {"db": None, "login": None, "password": None}
            params = {key: headers.get(key) for key in params if headers.get(key)}

            if not params.get("db"):
                params["db"] = request.db
                
            if not all([params.get("db"), params.get("login"), params.get("password")]):
                return invalid_response(
                    "missing error", "either of the following are missing [db, username,password]", 403,
                )

        return params
    
    def get_token_success_login(self, uid):

        _logger.info("Updating env with uid logged")
        request.session.uid = uid
        request.update_env(user=uid)
        access_token, expire_date = request.env["user.access.token"].sudo().find_or_create_token(user_id=uid, create=True)
        # Successful response:
        return werkzeug.wrappers.Response(
            status=200,
            content_type="application/json; charset=utf-8",
            headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
            response=json.dumps(
                {
                    "access_token": access_token,
                    "expire_date": expire_date
                }
            ),
        )

    @http.route("/api/v1/login-hr", methods=["POST"], type="http", auth="none", csrf=False)
    def auth_hr_login(self, **post):
        params = self.get_login_params(post)
        if isinstance(params, werkzeug.wrappers.Response):
            return params

        hr_uid = request.env["hr.employee"].sudo().search([
            ("work_email", "=", params.get("login")),
            ("barcode", "=", params.get("password"))
        ], limit=1)

        if not hr_uid:
            return invalid_response("Access Denied", "Login, password or db invalid")
        elif not hr_uid.user_id:
            return invalid_response("Access Denied", "Login, password or db invalid")
        
        uid = hr_uid.user_id.id
        
        request.session.uid = uid
        request.update_env(user=uid)

        return self.get_token_success_login(uid)

    @http.route("/api/v1/login", methods=["POST"], type="http", auth="none", csrf=False)
    def auth_login(self, **post):
        """
        The token URL to be used for getting the access_token:
        """
        params = self.get_login_params(post)

        if isinstance(params, werkzeug.wrappers.Response):
            return params

        db, username, password = (
            params.get("db") if "db" in params else None,
            params.get("login") if "login" in params else None,
            params.get("password") if "password" in params else None,
        )

        try:
            request.session.authenticate(db, username, password)
        except AccessError as aee:
            return invalid_response("Access error", "Error: %s" % aee.name)
        except AccessDenied as ade:
            return invalid_response("Access denied", "Login, password or db invalid")
        except Exception as e:
            # Invalid database:
            info = "The database name is not valid {}".format((e))
            error = "invalid_database"
            _logger.error(info)
            return invalid_response("wrong database name", error, 403)

        uid = request.session.uid
        # odoo login failed:
        if not uid:
            info = "authentication failed"
            error = "authentication failed"
            _logger.error(info)
            return invalid_response(401, error, info)

        return self.get_token_success_login(uid)

    @http.route("/api/v1/api-key/login", methods=["POST"], type="http", auth="none", csrf=False)
    def auth_api_token(self, **post):
        params = self.get_login_params(post)

        if isinstance(params, werkzeug.wrappers.Response):
            return params
        elif not params or ("password" not in params):
            return invalid_response("missing error",
                                    "either of the following are missing [username,password]", 403)

        _logger.info("Checking Api Key for login %s" % params.get("login"))
        uid = request.env["res.users.apikeys"].sudo()._check_credentials(scope="rpc", key=params.get("password"))

        if not uid:
            info = "authentication failed"
            error = "authentication failed"
            _logger.error(info)
            return invalid_response(401, error, info)

        return self.get_token_success_login(uid)

    @validate_token
    @http.route("/api/v1/logout", methods=["POST", "GET"], type="http", auth="none", csrf=False)
    def auth_logout(self):
        access_token = request.env["user.access.token"].sudo().search([("user_id", "=", request.env.user.id)])
        if access_token:
            access_token.invalidate_token()
        
        return werkzeug.wrappers.Response(
            status=200,
            content_type="application/json; charset=utf-8",
            headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
            response=json.dumps(
                {
                    "message": " user logged out"
                }
            ),
        )
