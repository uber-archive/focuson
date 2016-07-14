#!/usr/bin/env python
from __future__ import print_function

import ast
import sys
import operator
import os
import os.path
from collections import defaultdict, namedtuple, OrderedDict

import git

from auth_types import BADNESS_ORDER, DEFAULT_AUTH_TYPE, STR_TO_AUTH_TYPE


def try_index(list_obj, obj):
    try:
        return list_obj.index(obj)
    except ValueError:
        return -1


def cmp_auth_types(auth_type_a, auth_type_b):
    return cmp(
        try_index(BADNESS_ORDER, auth_type_a),
        try_index(BADNESS_ORDER, auth_type_b)
    )


def sort_routes(route_a, route_b):
    auth_type_a, auth_type_b = route_a[0], route_b[0]
    return cmp_auth_types(auth_type_a, auth_type_b)


RouteResult = namedtuple("RouteResult",
                         ("route", "auth_type", "path", "rel_path",
                          "lineno", "route_lineno", "match", "route_name",
                          "commit"))


def find_decorated_funcs(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if hasattr(node, "decorator_list"):
                yield node


def get_all_routes(root_dir):
    """
    routes is the list of parsed view=foo.show() type routes we now want to map to a file and function

    for each matching route -> file::func return the parse tree for that func
    """
    files = {}

    views_dir = os.path.join(root_dir, "Uber", "uber", "views")

    routes = get_route_info(root_dir)

    # Collect all the files that contain routable functions
    for route_name in routes:
        # Lop off the view name so we just have the path
        modules_split = route_name.split(".")
        assert(len(modules_split) > 1)
        modules_split = modules_split[:-1]

        files[os.path.join(views_dir, *modules_split) + ".py"] = modules_split

    for path, modules_split in files.items():
        if not os.path.isfile(path):
            raise Exception("WTF? %s isn't a valid view path" % path)
        with file(path) as f:
            file_contents = f.read()
        tree = ast.parse(file_contents)
        for node in find_decorated_funcs(tree):
            for dec in node.decorator_list:
                full_node_name = ".".join(modules_split + [node.name])
                # Not a routable function? Don't care.
                if full_node_name not in routes:
                    continue
                auth_type = sniff_decorator_for_access(dec)
                if not auth_type:
                    continue

                rel_path = os.path.relpath(path, views_dir)
                yield RouteResult(full_node_name, auth_type, path, rel_path,
                                  node.lineno, *routes[full_node_name])
                break


def is_uberapi_decorator(dec):
    if isinstance(dec, ast.Call) and hasattr(dec, "func"):
        if isinstance(dec.func, ast.Name) and hasattr(dec.func, "id"):
            """
                Few different forms here but one looks like this:
                Call(func=Name(id='UberAPI', ctx=Load()), args=[], keywords=[
                    keyword(arg='auth', value=Call(func=Attribute(value=Name(id='api_auth', ctx=Load()), attr='service_wall_factory', ctx=Load()), args=[
                        Str(s='dispatch'),
                        Str(s='hailstorm'),
                      ], keywords=[], starargs=None, kwargs=None)),
            """
            return dec.func.id == "UberAPI"
    return False


def norm_auth_name(name):
    return name.replace("api_auth.", "").replace("_factory", "")


# Returns the auth_type for a decorator, or None if it's some other decorator
def sniff_decorator_for_access(dec):
    if not is_uberapi_decorator(dec):
        return None

    # Get the arg for the auth function, e.g. @UberAPI(auth=auth_arg)
    if not hasattr(dec, "keywords"):
        return DEFAULT_AUTH_TYPE

    auth_kwargs = filter(lambda x: x.arg == "auth", dec.keywords)
    if not auth_kwargs:
        return DEFAULT_AUTH_TYPE

    auth_arg = auth_kwargs[0].value

    if isinstance(auth_arg, ast.Str):
        # e.g. @UberAPI(auth="admin")
        return STR_TO_AUTH_TYPE.get(auth_arg.s, "unknown")

    elif isinstance(auth_arg, ast.Call):
        if hasattr(auth_arg, "func"):
            auth_func = auth_arg.func
            if hasattr(auth_func, "value") and hasattr(auth_func, "attr"):
                # e.g. @UberAPI(auth=api_auth.service_wall_factory('dispatch'))
                # e.g. @UberAPI(auth=api_auth.token_or_service('coral', 'edison'))
                if auth_func.value.id == "api_auth":
                    return norm_auth_name(auth_func.attr)
            if hasattr(auth_func, "id"):
                # Only one case of this (as of 07/11/16):
                # from uber.lib.api_auth import service_wall_factory
                # @UberAPI(auth=service_wall_factory('safari'))
                return norm_auth_name(auth_func.id)

    elif isinstance(auth_arg, (ast.Attribute, ast.Name)):
        # e.g. @UberAPI(auth=api_auth.token_wall)
        # e.g. @UberAPI(auth=api_auth.admin_insecure_wall)
        # e.g. @UberAPI(auth=api_auth.api_global_cert_issuer_wall)
        return norm_auth_name(get_fully_qualified_func_name(auth_arg))

    # (This is the only thing we're returning unknown for - 07/11/16)

    # return "unknown" for everything else, including:
    # @UberAPI(auth=api_auth.user_wall_factory(
    #    'payment_profile',
    #    object_getter=_pp_object_getter(rollout_setting_name='pp_deposit_request'))
    #    if not config.get('money.payment.airtel_money.skip_check_bonus_auth', True)
    #    else "no_auth_required")
    # It's hard to determine statically which auth wall it'd use.
    return "unknown"


def get_fully_qualified_func_name(v):
    name_parts = []
    while hasattr(v, "attr"):
        name_parts.append(v.attr)
        v = v.value
    name_parts.append(v.id)
    return ".".join(reversed(name_parts))


class RouteVisitor(ast.NodeVisitor):
    def __init__(self):
        self.routable_funcs = {}

    @staticmethod
    def is_add_route_call(call):
        if hasattr(call, "func"):
            func = call.func
            if hasattr(func, "id"):
                return func.id == "add_route"
        return False

    def visit_Expr(self, node):
        if not hasattr(node, 'value'):
            return
        if not isinstance(node.value, ast.Call):
            return
        call = node.value
        if not self.is_add_route_call(call):
            return

        route_name = call.args[0].s
        route_match = call.args[1].s

        for kw in call.keywords:
            k = kw.arg
            v = kw.value
            if k == "view":
                if hasattr(v, "value"):
                    full_name = get_fully_qualified_func_name(v)
                    if "." not in full_name:
                        # Crap, someone imported the view into the local
                        # namespace so we don't know the fully qualified
                        # name. Why would you do that?
                        return
                    self.routable_funcs[full_name] = (v.lineno, route_match, route_name)
        self.generic_visit(node)


def get_route_info(root_path):
    routing_path = os.path.join(root_path, "Uber", "uber", "routing.py")
    with open(routing_path) as f:
        file_contents = f.read()
    tree = ast.parse(file_contents)
    visitor = RouteVisitor()
    visitor.visit(tree)
    all_routes = visitor.routable_funcs

    # Get the commit that added each route and tack it onto the details
    route_linenos = sorted(set(x[0] for x in all_routes.values()))
    repo = git.Repo(root_path)
    blame_by_line = get_line_blames(repo, routing_path, route_linenos)
    for name, details in all_routes.iteritems():
        all_routes[name] = details + (blame_by_line[details[0]],)
    return all_routes


def get_routes_by_auth_type(all_routes):
    # for different types see lib/api_auth.py
    routes_by_auth_type = defaultdict(list)

    for route in all_routes:
        routes_by_auth_type[route.auth_type].append(
            route
        )
    routes_by_auth_type = OrderedDict(
        sorted(routes_by_auth_type.items(), cmp=sort_routes)
    )
    for k, v in routes_by_auth_type.iteritems():
        v.sort(key=operator.attrgetter("route"))
    return routes_by_auth_type


def get_line_blames(repo, filename, linenos):
    tlc = 0
    line_blames = {}
    for commit, lines in repo.blame('HEAD', filename):
        # 1-indexed to 0-indexed
        these_lines = set()
        for lineno in linenos:
            if tlc <= (lineno - 1) < (tlc + len(lines)):
                these_lines.add(lineno)
        for lineno in these_lines:
            line_blames[lineno] = commit
        tlc += len(lines)
    return line_blames
