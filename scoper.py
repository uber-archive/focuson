#!/usr/bin/python

from jinja2 import Environment, meta
import jinja2
import sys
import os
import ast
import pprint
import subprocess
from jinja2.loaders import ModuleLoader
from jinja2.exceptions import TemplateSyntaxError
import astpp



def usage():
    if len(sys.argv) < 2:
        print "Usage: %s <dir to scan>" % sys.argv[0]
        sys.exit(1)
    target_dir = sys.argv[1]
    template_dir = target_dir + os.sep + "templates"
    if not os.path.isdir(target_dir) or not os.path.isdir(template_dir):
        print "%s needs to be a directory under which there will be a templates/ directory" % target_dir
        sys.exit(1)
    return target_dir



def get_auth_type_for_routes(views_dir, routes_list):
    """
    routes is the list of parsed view=foo.show() type routes we now want to map to a file and function

    for each matching route -> file::func return the parse tree for that func
    """
    routes_to_auth_type = {}
    for r in routes_list:
        fn = r.split(".")
        assert(len(fn) == 2)
        fn = fn[0]
        potential_fn_for_a_route = views_dir + os.sep + fn + ".py"
        # XXX this is wasteful of memory, if we have 100 routes in one .py we will read/parse and store that one file 100 times
        if os.path.isfile(potential_fn_for_a_route):
            file_contents = file(potential_fn_for_a_route).read()
            tree = ast.parse(file_contents)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if hasattr(node, "decorator_list"):
                        for dec in node.decorator_list:
                            if isinstance(dec, ast.Call) and hasattr(dec, "func"):
                                if isinstance(dec.func, ast.Name) and hasattr(dec.func, "id"):
                                    name_of_deco = dec.func.id
                                    if name_of_deco == "UberAPI":
                                        """
                                        Few different forms here but one looks like this:
                                        Call(func=Name(id='UberAPI', ctx=Load()), args=[], keywords=[
                                            keyword(arg='auth', value=Call(func=Attribute(value=Name(id='api_auth', ctx=Load()), attr='service_wall_factory', ctx=Load()), args=[
                                                Str(s='dispatch'),
                                                Str(s='hailstorm'),
                                              ], keywords=[], starargs=None, kwargs=None)),
                                        """
                                        if hasattr(dec, "keywords"):
                                            if not len(dec.keywords) > 0:
                                                #print 'ugggggggggggggggggggggh some different auth deco pattern.... look into this later..........\n'
                                                #print astpp.dump(dec)
                                                """
                                                Call(func=Name(id='UberAPI', ctx=Load()), args=[
                                                    Call(func=Attribute(value=Name(id='api_auth', ctx=Load()), attr='admin_or_service', ctx=Load()), args=[
                                                        Str(s='ubill'),
                                                        Str(s='unvaulter'),
                                                      ], keywords=[], starargs=None, kwargs=None),
                                                  ], keywords=[], starargs=None, kwargs=None)


                                                @UberAPI(auth=api_auth.admin_not_restricted_or_service(
                                                    'lucy',
                                                ), use_json_dt=False)
                                                """

                                                #auth_type = dec.func.args[0].func.attr
                                                #routes_to_auth_type[r] = auth_type
                                                # TODO this doesn't really matter so we can ignore for now...
                                                continue


                                            if not dec.keywords[0].arg == "auth":
                                                #print "ugggggggggggggggggggggggggh some other different error........ ignoring for now.........\n"
                                                #print astpp.dump(dec)
                                                continue

                                            assert(dec.keywords[0].arg == "auth")
                                            auth_call = dec.keywords[0].value
                                            if isinstance(auth_call, ast.Str):
                                                auth_type = auth_call.s

                                                # Auth type, file path, line number (of function def) (at, fp, lineno) 
                                                routes_to_auth_type[r] = (auth_type, potential_fn_for_a_route, node.lineno)

                                            if isinstance(auth_call, ast.Call):
                                                #print astpp.dump(dec.keywords[0])
                                                if not auth_call.func.value.id == "api_auth":
                                                    print 'uggggggggggggggggggggggggggh something else weird is wrong...............'
                                                    continue
                                                auth_type = auth_call.func.attr
                                                #routes_to_auth_type[r] = auth_type
                                                routes_to_auth_type[r] = (auth_type, potential_fn_for_a_route, node.lineno)
    return routes_to_auth_type


def is_call_an_add_route(call):
    if hasattr(call, "func"):
        func = call.func
        if hasattr(func, "id"):
            if func.id == "add_route":
                return True
    return False

# ugh a global.... 
routable_func_names = []

class route_visitor(ast.NodeVisitor):
    global routable_func_names
    def visit_Expr(self, node):
        expr = node
        if hasattr(expr,'value'):
            if isinstance(expr.value, ast.Call):
                call = expr.value
                if is_call_an_add_route(call):
                    for kw in call.keywords:
                        k = kw.arg
                        v = kw.value
                        if k == "view":
                            if hasattr(v, "value"):
                                if hasattr(v.value, "id"):
                                    # for ex above = 'vehiclde_view_groups.show'
                                    full_routable_func_name = v.value.id + '.' + v.attr
                                    routable_func_names.append(full_routable_func_name)
        self.generic_visit(node)


def get_routes(path):
    global routable_func_names
    file_contents = file(path).read()
    tree = ast.parse(file_contents)
    route_visitor().visit(tree)
    return routable_func_names


def main():
    pp = pprint.PrettyPrinter(indent=4)
    target_dir = usage()

    route_path = "/Users/collin/src/api/Uber/uber/routing.py"
    routes = get_routes(route_path)
    views_dir = target_dir + os.sep + "views"
    #print "%d routes." % len(routes)

    route_to_auth_type = get_auth_type_for_routes(views_dir, routes)


    anon_auth = []
    token_auth = []
    admin_auth = []
    service_auth = []
    #print "%d routes with auth types we can grok" % len(route_to_auth_type.keys())

    # for different types see lib/api_auth.py
    for route,(at, fp, lineno) in route_to_auth_type.iteritems():
        if at == "token":
            print fp + " +" + str(lineno)
            token_auth.append(route)
            continue
        if at == "token_or_service":
            print fp + " +" + str(lineno)
            token_auth.append(route)
            continue
        if at == "GAPING_SECURITY_HOLE":
            print fp + " +" + str(lineno)
            anon_auth.append(route)
            continue

        if at == "no_auth_required":
            print fp + " +" + str(lineno)
            anon_auth.append(route)
            continue

        if at == "service_wall_factory":
            service_auth.append(route)
            continue
        if at == "admin":
            admin_auth.append(route)
            continue

        if at == "admin_not_restricted":
            admin_auth.append(route)
            continue

        if at == "super_admin":
            admin_auth.append(route)
            continue



if __name__ == "__main__":
    main()



