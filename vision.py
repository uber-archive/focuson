#!/usr/bin/env python

import sys
import os
import ast
import pprint
import subprocess
import astpp
import bulbs
from bulbs.neo4jserver import Graph, Config, NEO4J_URI
from bulbs.model import Node, Relationship
from bulbs.property import String, Integer, DateTime, Null
from bulbs.utils import current_datetime
import jinja2









"""
Rule families

1. Ast rules. Simple as they operate upon the AST
2. CFG rules. Don't know of any but they might exist, maybe around toctou or race conditions on files?
3. Dataflow rules. xss/sqli/etc
4. Human - blacklist of people who write bugs, interns, new people etc
5. Experimential - codebase analysis, person x commits to this area a bunch but this is their first commit to area y.


Specific future rules to write
1. <script> inside an .html template, see login/templates/analytics.html and login/views/base.py. Send to human.
"""




class funcPrinter(ast.NodeVisitor):
    def visit_FunctionDef(self, node):
        print node.name
        self.generic_visit(node)


class funk:
    def __init__(self, ast_tree=None):
        self.tree = ast_tree
        self.decos = []
        self.is_routable = False

class codeBundle:
    def __init__(self, path, tree):
        self.path = path
        self.tree = tree
        self.funcs = []
        self.git_jonx = []

class loginAnalysis:
    def __init__(self, base_file_dir=None, existing_ast=None):
        self.__base_file_dir = base_file_dir
        self.__existing_ast = existing_ast
        self.__routable = []
        self.__templates = {}
        # filename : code bundle
        # codebundle = { full path, list of functions, git history? } 
        self.__fn_to_cb = {}

    def injest_dir(self, rootdir):
        if not os.path.isdir(rootdir):
            raise Exception("directory %s passed in is not a dir" % rootdir)
        
        self.__base_file_dir = rootdir

        # walk the dirs/files
        for root, subdir, files in os.walk(self.__base_file_dir):
            for f in files:
                if f.endswith(".py"):
                    fullpath = root + os.sep + f
                    contents = file(fullpath).read()
                    tree = ast.parse(contents)
                    c = codeBundle(fullpath, tree)
                    self.__fn_to_cb[fullpath] = c

        #pp = pprint.PrettyPrinter(indent=4)
        #pp.pprint(self.__paths_to_ast)

    def is_known_borning_deco(self, deco):
        """ given a decorator in ast node form see if we want to discard it or not"""
        #Name(id='classmethod', ctx=Load())
        #Name(id='property', ctx=Load())
        if isinstance(deco, ast.Name):
            if deco.id == "classmethod":
                return True
            if deco.id == "property":
                return True
        if isinstance(deco, ast.Call):
            if hasattr(deco.func, "value") and deco.func.value == "mock":
                return True

        return False

    def is_routable(self, deco):
        """
        Routablility is an interesting property for us, especially in pythonland at uber. 
        Its a bit different per project most commonly as an app.route() decorator or in a big routes.py file (for api)
        """
        if isinstance(deco, ast.Call):
            if hasattr(deco.func, "attr"):
                if deco.func.attr == "route":
                    #print astpp.dump(dec.func)
                    return True

        """
        Call(func=Attribute(value=Name(id='app', ctx=Load()), attr='route', ctx=Load()),

            Call(func=Attribute(value=Name(id='app', ctx=Load()), attr='route', ctx=Load()), args=[
                Str(s='/admin'),
              ], keywords=[
                keyword(arg='methods', value=List(elts=[
                    Str(s='GET'),
                  ], ctx=Load())),
              ], starargs=None, kwargs=None),
        """

    def determine_routability(self):
        assert self.__fn_to_cb.keys() > 0

        #print 'building graph.........'
        #config = Config(NEO4J_URI, "neo4j", "foofoofoo")
        #g = Graph(config)
        #g.add_proxy("funcs", Funcdef)
        # a pointless comment to test arc

        for path, cb in self.__fn_to_cb.items():
            for node in ast.walk(cb.tree):
                if isinstance(node, ast.FunctionDef):
                    f = funk()
                    f.tree = node
                    if hasattr(node, "decorator_list"):
                        if len(node.decorator_list) > 0:
                            f.decos = node.decorator_list
                            for deco in node.decorator_list:
                                if self.is_routable(deco):
                                    self.__routable.append(node)
                                    f.is_routable = True

                    cb.funcs.append(f)

    def get_all_routable_funcs(self):
        for fn, cb in self.__fn_to_cb.items():
            for f in cb.funcs:
                if f.is_routable:
                    print fn + " +" + str(f.tree.lineno), f.tree.name

 

    def rule_no_csrf_protection(self):
        for fn, cb in self.__fn_to_cb.items():
            for f in cb.funcs:
                if f.is_routable:
                    # its routable so check if csrf.exempt is on
                    for dec in f.decos:
                        if isinstance(dec, ast.Attribute):
                            if dec.value.id == 'csrf' and dec.attr == 'exempt':
                                print "csrf protection turned off -> ",fn + " +" + str(f.tree.lineno), f.tree.name
                                #Attribute(value=Name(id='csrf', ctx=Load()), attr='exempt', ctx=Load())

    def rule_routable_but_no_service_auth(self):
        for fn, cb in self.__fn_to_cb.items():
            for f in cb.funcs:
                if f.is_routable:
                    for dec in f.decos:
                        if isinstance(dec, ast.Call) and hasattr(dec.func, "id"):
                            #print "\n\n"
                            #print astpp.dump(dec)
                            if dec.func.id == 'require_service_auth':
                                pass
                            else:
                                print "service authless func -> ",fn + " +" + str(f.tree.lineno), f.tree.name
        """
        Call(func=Name(id='require_service_auth', ctx=Load()), args=[
            Str(s='miapps'),
          ], keywords=[], starargs=None, kwargs=None)
        """

    def rule_find_incredibly_simple_jinja_xss(self):
        assert self.__base_file_dir
        # There are 5-10 more complex variations needed to cover our bases here, this is the very first and simple one I can do without "real" dataflow analysis.
        
        unsafe_tn_fn_pairs = []
        unsafe_tn_vn_pairs = []

        # Get template dir
        for root, subdir, files in os.walk(self.__base_file_dir):
            if "templates" in subdir:
                template_dir = os.getcwd() + os.sep + root + os.sep + "templates"

        # Transform templates from html -> py
        tloader = jinja2.FileSystemLoader(template_dir)
        env = jinja2.Environment(loader=tloader)
        for tn in env.list_templates():
            try:
                source, filename, _ = env.loader.get_source(env, tn)
                code = env.compile(source, tn, filename, True, True)
                parse_tree_of_templates = ast.parse(code)
                self.__templates[tn] = parse_tree_of_templates
            except jinja2.exceptions.TemplateSyntaxError as e:
                #print 'Could not compile "%s": %s' % (tn, e)
                continue

        # Scan/visit the py for  t_1 = environment.filters['safe']
        for tn, tree in self.__templates.items():
            for node in ast.walk(tree):
                # First step  - find the assignment of the |safe filter to a temp function
                if isinstance(node, ast.Assign):
                    """
                    1. html: <p>{{ more_info|safe }}</p> 
                    2. python: t_1 = environment.filters['safe']
                    3. python ast: value=Subscript(value=Attribute(value=Name(id='environment', ctx=Load()), attr='filters', ctx=Load()), slice=Index(value=Str(s='safe')), ctx=Load()))

                    The full representation on the templated python side looks like this

                    l_more_info = context.resolve('more_info')
                    ...
                    t_1 = environment.filters['safe']
                    ... 
                    yield u'</div><div class="more-information"> <p>%s</p></div></div> </div> <div class="footer"></div>' % ( t_1(l_more_info),)
                    """
                    if isinstance(node.value, ast.Subscript) and hasattr(node.value, "value"):
                        if isinstance(node.value.value, ast.Attribute):
                            if node.value.value.value.id == "environment" and node.value.value.attr == "filters":
                                if hasattr(node.value, 'slice'):
                                    if node.value.slice.value.s == 'safe':
                                        # We are now certain this is an instance of |safe, get the left side of the assignment
                                        safe_func_alias_name = str(node.targets[0].id)
                                        unsafe_tn_fn_pairs.append( (tn, safe_func_alias_name))
        
        # Second step - find the call of the temp function (representing |safe) upon a variable
        for (tn, safe_func_alias_name) in unsafe_tn_fn_pairs:
            for node in ast.walk(self.__templates[tn]):
                if isinstance(node, ast.Call):
                    if hasattr(node.func, 'id'):
                        if node.func.id == safe_func_alias_name:
                            if hasattr(node, 'args') and hasattr(node.args[0], 'id'):
                                v = str(node.args[0].id)
                                unsafe_tn_vn_pairs.append( (tn, v))
                                """
                                Call(func=Name(id='t_2', ctx=Load()), args=[
                                    Name(id='l_error', ctx=Load()),
                                  ], keywords=[], starargs=None, kwargs=None)
                                """



        # Third step - find the definition of the variable that had |safe 
        # We either
        # 1. Look for a call like l_more_info = context.resolve('more_info')
        # 2. Instead strip the leading "l_" from the temp jinja python variable name and use that. We only do this for cases where we dont find a resolve() call
        #  and we are only operating upon instances where there is a |safe filter anyway so we prefer to lose the precision and cast the net more widely. 
        final_unsafe_tn_vn_pairs = []
        for (tn, dangerous_var_name) in unsafe_tn_vn_pairs:
            confirmed_dangerous_var_names = []
            unconfirmed_dangerous_var_names = []
            #print tn
            #print "DANGER VARIABLE -> " + dangerous_var_name
            for node in ast.walk(self.__templates[tn]):
                if isinstance(node, ast.Assign):
                    if hasattr(node, "targets"):
                        if node.targets[0] and hasattr(node.targets[0], 'id'):
                            if node.targets[0].id == dangerous_var_name:
                                """
                                Assign(targets=[
                                    Name(id='l_collin_error', ctx=Store()),
                                  ], value=Call(func=Attribute(value=Name(id='context', ctx=Load()), attr='resolve', ctx=Load()), args=[
                                    Str(s='collin_error'),
                                  ], keywords=[], starargs=None, kwargs=None))
                                """ 
                                if isinstance(node.value, ast.Call):
                                    if node.value.func.value.id == "context" and node.value.func.attr == "resolve":
                                        if hasattr(node.value, 'args'):
                                            confirmed_dangerous_vn= str(node.value.args[0].s)
                                            confirmed_dangerous_var_names.append( confirmed_dangerous_vn)
                                            continue

                                # If we got here we can only get an unconfirmed var_name
                                v = node.targets[0].id
                                if v.startswith("l_"):
                                    unconfirmed_dangerous_var_names.append( v[2:])

            if len(confirmed_dangerous_var_names) > 0 or len(unconfirmed_dangerous_var_names) > 0:
                combined = list( set(confirmed_dangerous_var_names) | set(unconfirmed_dangerous_var_names))
                t = (tn, combined) 
                final_unsafe_tn_vn_pairs.append(t)

        for (tn, v) in final_unsafe_tn_vn_pairs:
            print tn, v
        # given listen of instances of |safe being used, get variable name and template file name (templates/signup_landing.html) and find all routable funcs that have a render_template() call using that template filename
        # for every render_template() parse the function body looking for the variable name being passed in to render_template
        # Check if that variable is user-controlled ($var = request.args['foo'])
        

def usage():
    if len(sys.argv) < 2:
        print "Usage: %s <dir to scan>" % sys.argv[0]
        sys.exit(1)

    target_dir = sys.argv[1]
    if not os.path.isdir(target_dir):
        print "Usage: %s <dir to scan>" % sys.argv[0]
        sys.exit(1)
    return target_dir



def main():
    pp = pprint.PrettyPrinter(indent=4)
    target_dir = usage()
    # future work - have an "analysis router" to look at project, see by loc it is 70% .py and send to the python analyizer. Ditto for javascript etc
    # More research suggests: have an analyzer for each project, patterns are different for login vs api vs web-p2
    la = loginAnalysis()
    la.injest_dir(target_dir)
    la.determine_routability()
    #la.rule_no_csrf_protection()
    #la.get_all_routable_funcs()
    #la.rule_routable_but_no_service_auth()
    la.rule_find_incredibly_simple_jinja_xss()


if __name__ == "__main__":
    main()



