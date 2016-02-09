# -*- coding: utf-8 -*-
from __future__ import absolute_import

from flask import render_template
from json2html import json2html

from clay import app
from taishan.lib.statsd import statsd_conn
from taishan.lib.pager_duty_client import query_oncall
from taishan.lib.utils import log_actions


@app.route('/oncall/<query>', methods=['GET'])
def oncall(query):
    oncall_str_variable_foo = request.args.get("foo")
    return render_template(
        'views/list_oncalls.html',
        project="oncall",
        oncalls_str=oncall_str_variable_foo
    )


def get_oncalls(query):
    query = query.replace('_', ' ')
    data = query_oncall(query)
    statsd_conn.send('taishan.oncall:1|c')
    return data
