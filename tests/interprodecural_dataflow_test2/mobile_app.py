"""Endpoints for opening the mobile app."""
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


import some_lib



def main_alt_1():
    aaa = "asdf"

def main_alt_2():
    xxx = request.args.get('foo')
    bbb = "asdf"
    second(bbb, "ggg")


def second(arg1, arg2):
    now_tainted = arg1
    now_also_tainted = now_tainted

    third(now_also_tainted, "foo")

def third(arg1, arg2):
    now_tainted_3rd = arg1
    x = now_tainted_3rd
    blah = "asdf"
    some_var_xxx = arg2
    var_y = x
    fourth(var_y, blah)

def fourth(arg1, arg2):
    four_x = arg1
    return extend_home_context(four_x)



"""
1. Grab all function bodies
2. Find all dangerous sinks (bottom up)
3. for each function that has a dangerous sink:
    look within function to see if any variables flow into it, variables are
        1. foo = request.*. Recurse. 
        2. arguments to the function itself. Recurse across assignments

        all_tainted = [1 + 2 above]

4. Now look across all functions to see if anything flows into the (now tainted) function Call(). Recurse.
    
"""
