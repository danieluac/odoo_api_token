# -*- coding: utf-8 -*-
import logging
import json
import werkzeug.wrappers
from odoo import http
from odoo.addons.odoo_api_token.controllers.utils.token_validate import validate_token
from odoo.http import request
#
#
_logger = logging.getLogger(__name__)


class HellowApi(http.Controller):
    @validate_token
    @http.route(
        '/api/v1/projects',
        auth='none',
        type="http",
        website=False,
        csrf=False,
        methods=["GET"]
    )
    def index_projects(self, **kw):
        project_list = []
        _logger.info("showing project list for user with login %s" % request.env.user.login)
        for project in http.request.env["project.project"].sudo().search([]):
            followers = [x.id for x in project.message_follower_ids.mapped("partner_id")]
            if followers and request.env.user.partner_id.id in followers:
                tasks_list = []
                for task in project.tasks:
                    tasks_list.append({
                        "id": task.id,
                        "name": task.name,
                    })

                project_list.append({
                    "id": project.id,
                    "name": project.name,
                    "tasks": tasks_list,
                })
        if not project_list:
            return werkzeug.wrappers.Response(
                status=404,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    {
                        "message": "No projects to list",
                        "data": project_list
                    }
                ),
            )        
        return werkzeug.wrappers.Response(
                status=200,
                content_type="application/json; charset=utf-8",
                headers=[("Cache-Control", "no-store"), ("Pragma", "no-cache")],
                response=json.dumps(
                    {
                        "data": project_list
                    }
                ),
            )

