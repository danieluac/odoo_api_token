# -*- coding: utf-8 -*-
from odoo import http
from odoo.addons.api_token.controllers.utils import token_validate
#
#


class HellowApi(http.Controller):
    @http.route(
        '/api',
        auth='public',
        type="json",
        website=False,
        csrf=False,
        methods=["GET", "POST"]
    )
    def index(self, **kw):
        print("Getting parameters")
        print(kw)
        contact_list = []
        for x in http.request.env["res.partner"].sudo().search([]):

            contact_list.append({
                "id": x.id,
                "name": x.name
            })
        return kw

    @http.route('/index', auth='public', type="http", website=False, csrf=False, methods=["GET", "POST"])
    def index_i(self, **kw):
        return "HEllo"
