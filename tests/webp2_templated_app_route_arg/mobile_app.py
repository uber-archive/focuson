"""Endpoints for opening the mobile app."""
from __future__ import absolute_import

import os
import re
import urllib

from clay import app, config, stats
from clay_assets import AssetHelper
from clay_genghis.lib import utils as genghis_utils
from flask import jsonify, redirect, render_template, request
from requests.exceptions import RequestException
from upi.exceptions import NotFound, UberAPIError

from partners.helpers import geolocation, populous
from partners.helpers.base import templated
from partners.lib import caesar_lib, events, flipr_client, util
from partners.lib.flipr_client import FliprServiceError
from partners.lib.genghis_helpers import gettext as _
from partners.models.driver import Driver
from partners.models import user_tag

@app.route('/app', methods=['GET'])
@app.route('/driver-app', methods=['GET'])
def redirect_to_drive_now():
    """Legacy endpoint.

    We're redirecting traffic to /drive-now
    """
    return redirect(
        '/drive-now',
        code=302
    )


#XXXXXXXXXX Note, the thing we return into the template var is android_deep_link_collin! This is important
@app.route('/open-app/<foo>/', methods=['GET'])
@templated('mobile_app/open-app.html')
def open_app(foo):
    #android_deep_link_collin 



    android_fallback_link = request.args.get(
        'android_fallback_link',
        config.get('byod.download_link.android'),
    )
    iphone_deep_link = request.args.get(
        'iphone_deep_link',
        config.get('deep_link.iphone'),
    )
    iphone_fallback_link = request.args.get(
        'iphone_fallback_link',
        config.get('byod.download_link.iphone'),
    )



    collin2 = foo
    return {
        'os_family': util.formatted_os_family(),
        'android_deep_link': collin2,
        'android_fallback_link': not_real,
        'iphone_deep_link': not_real2,
        'iphone_fallback_link': iphone_fallback_link,
    }


