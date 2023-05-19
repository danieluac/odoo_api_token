import json
import logging
import werkzeug.wrappers

from odoo import http
from odoo.addons.odoo_api_token.controllers.utils.http_common import invalid_response
from odoo.exceptions import AccessDenied, AccessError
from odoo.http import request

_logger = logging.getLogger(__name__)

class AuthAccessToken(http.Controller):

    def get_login_params(self, post):
        params = ["db", "login", "password"]
        params = {key: post.get(key) for key in params if post.get(key)}

        if not params.get("db"):
            params["db"] = request.db

        if not all([params.get("db"), params.get("login"), params.get("password")]):
            headers = request.httprequest.headers
            params = {key: headers.get(key) for key in params if headers.get(key)}

            if not params.get("db"):
                params["db"] = request.db

            if not all([params.get("db"), params.get("login"), params.get("password")]):
                return invalid_response(
                    "missing error", "either of the following are missing [db, username,password]", 403,
                )
            
        return params
    
    def get_token_success_login(self, uid):
        access_token = request.env["user.access.token"].find_or_create_token(user_id=uid, create=True)
        # Successful response:
        return werkzeug.wrappers.Response(
            status=200,
            content_type="application/json; charset=utf-8",
            headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
            response=json.dumps(
                {
                    "uid": uid,
                    "user_context": request.env.user.context_get() if uid else {},
                    "access_token": access_token,
                    "company_name": request.env.user.company_id.name,
                    "country": request.env.user.country_id.name,
                    "contact_address": request.env.user.contact_address,
                }
            ),
        )

    @http.route("/api/v1/login-hr", methods=["POST"], type="http", auth="none", csrf=False)
    def auth_hr_login(self, **post):
        params = self.get_login_params(post)

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

        db, username, password = (
            params.get("db"),
            post.get("login"),
            post.get("password"),
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

    @http.route("/api/login/token_api_key", methods=["GET"], type="http", auth="none", csrf=False)
    def api_login_api_key(self, **post):
        # The request post body is empty the credetials maybe passed via the headers.
        headers = request.httprequest.headers
        db = headers.get("db")
        api_key = headers.get("api_key")
        _credentials_includes_in_headers = all([db, api_key])
        if not _credentials_includes_in_headers:
            # Empty 'db' or 'username' or 'api_key:
            return invalid_response(
                "missing error", "either of the following are missing [db ,api_key]", 403,
            )
        # Login in odoo database:
        user_id = request.env["res.users.apikeys"]._check_credentials(scope="rpc", key=api_key)
        # request.session.authenticate(db, username, api_key)
        if not user_id:
            info = "authentication failed"
            error = "authentication failed"
            _logger.error(info)
            return invalid_response(401, error, info)

        uid = user_id
        user_obj = request.env['res.users'].sudo().browse(int(uid))

        # Generate tokens
        access_token = request.env["api.access_token"].find_or_create_token(user_id=uid, create=True)
        # Successful response:
        return werkzeug.wrappers.Response(
            status=200,
            content_type="application/json; charset=utf-8",
            headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
            response=json.dumps(
                {
                    "uid": uid,
                    # "user_context": request.session.get_context() if uid else {},
                    "company_id": user_obj.company_id.id if uid else None,
                    "company_ids": user_obj.company_ids.ids if uid else None,
                    "partner_id": user_obj.partner_id.id,
                    "access_token": access_token,
                    "company_name": user_obj.company_id.name,
                    "country": user_obj.country_id.name,
                    "contact_address": user_obj.contact_address,
                }
            ),
        )
