"""Endpoints for opening the mobile app."""
import os
import re
import urllib


@app.route('/first-layer-open-app', methods=['GET'])

def main_alt_1():
    aaa = "asdf"

def main_alt_2():
    xxx = request.args.get('foo')
    bbb = "asdf"
    second(bbb, "ggg")


def first_layer():
    android_deep_link= request.args.get('android_deep_link')
    second(android_deep_link, "asdf")

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
