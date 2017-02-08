"""Endpoints for opening the mobile app."""
import os
import re
import urllib



from flask import jsonify, redirect, render_template, request
#import flask


from lib.lib_one.temporary_token import Turtle

"""
from clay import app, config, stats
from clay_assets import AssetHelper
from clay_genghis.lib import utils as genghis_utils
from requests.exceptions import RequestException
from upi.exceptions import NotFound, UberAPIError

from partners.helpers import geolocation, populous
from partners.helpers.base import templated
from partners.lib import caesar_lib, events, flipr_client, util
from partners.lib.flipr_client import FliprServiceError
from partners.lib.genghis_helpers import gettext as _
from partners.models.driver import Driver
from partners.models import user_tag

from partners.lib.urls import (
    is_freecandy,
    is_yangtze,
    replace_hostname,
    replace_hostname_with_proxy_header
)
"""


def main_alt_2():
    # setup flask 
    app = flask.Flask(__name__)
    with app.test_request_context():
        some_arg_vuln = request.args.get('foo')
        arg_not_vuln = "asdf"
        second(some_arg_vuln, "ggg")
        print 'done!'

def second(arg1, arg2):
    now_tainted = arg1
    now_also_tainted = now_tainted
    user = "asd"
    url = "asdf"
    yet_again = now_also_tainted

    baxter_the_turtle = Turtle(user)
    #baxter_the_turtle.chomp(user, url, now_also_tainted)
    baxter_the_turtle.chomp(user, url, yet_again)

    ret = os.system("doing something that isn't making a class")

if __name__ == "__main__":
    main_alt_2()
