#!/usr/bin/env python

import sys
import os
import ast
import pprint
import subprocess
import UserDict

import codegen
import astpp
import jinja2









"""
TODO:
    * Make auditor mode that just shows areas of interest, lots of request. or whatnot
    * Run against taishan, login, free-candy
    * Make it gracefully handle api/, run against it, learn stuff, improve

    * DONE - Get tainted source from app.route() method
    * DONE - Break up giant jinja2 xss rule into a big sink rule that gets interesting variables from the jinja2 but is otherwise just like the eval() test
    * LOTS MORE TESTS
    * add def/use for variables that are tainted but then redefined and safe
    * Handle taint prop through dicts....... dict creation specifically
    * Handle binOp cases where x = TAINTED; x = x + "some string"; eval(x)
    * Handle eval("foo bar baz %s" % x) case, x = tainted
    * Look through old bugs to find actual good sinks, json.dumps()? requests? urllib?


TODO:
    * Enhance jinja2 template parsing code to not only look at |safe but any variable that goes into a <script> block





Rule families

1. Ast rules. Simple as they operate upon the AST
2. CFG rules. Don't know of any but they might exist, maybe around toctou or race conditions on files?
3. Dataflow rules. xss/sqli/etc
4. Human - blacklist of people who write bugs, interns, new people etc
5. Experimential - codebase analysis, person x commits to this area a bunch but this is their first commit to area y.


Specific future rules to write
1. <script> inside an .html template, see login/templates/analytics.html and login/views/base.py. Send to human.
example: https://code.uberinternal.com/D220082
2. Copy robs rule around making a new jinja2 env since its easy to try, and fail, to turn on auto-escaping
3. Robs sqli examples
4. Add more to template xss rule, can also be done this way:
    template = Template(survey.message)
    final_message = template.render(url=final_url)
5. HTTP response splitting
6. XXE
7. yaml.load() https://code.uberinternal.com/D207794
8. pickle.load, http://kevinlondon.com/2015/08/15/dangerous-python-functions-pt2.html
9. Robs existing bandit rule for new jinja2 environs
"""



class Issue:
    def __init__(self, filename, func_name, variable_name, lineno = None):
        self.filename = filename
        self.func_name = func_name
        self.variable_name = variable_name
        self.lineno = lineno

    def __repr__(self):
        return "Issue with var %s in func %s in file %s" % (self.variable_name, self.func_name, self.filename)

# ugh a global.... 
routable_func_names = []

def is_call_an_add_route(call):
    if hasattr(call, "func"):
        func = call.func
        if hasattr(func, "id"):
            if func.id == "add_route":
                return True
    return False


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


class funcPrinter(ast.NodeVisitor):
    def visit_FunctionDef(self, node):
        print node.name
        self.generic_visit(node)

class DangerDict:
    def __init__(self, name, key):
        # name of the dict iself
        self.name = name
        # Name of key whose value is tainted
        self.key = key
    def __str__(self):
        return "%s['%s']" % (self.name, self.key)
    def __repr__(self):
        return "%s['%s']" % (self.name, self.key)


class NopFilters(UserDict.DictMixin):
    """A dictionary that only returns a stub filter for Jinja2"""

    def __init__(self):
        pass

    @staticmethod
    def _nop_filter(*args, **kwargs):
        return args[0]

    def has_key(self, key):
        return True

    def keys(self):
        return []

    def __getitem__(self, item):
        return self._nop_filter

    def __setitem__(self, key, value):
        raise NotImplementedError("stubbed")

    def __delitem__(self, key):
        raise NotImplementedError("stubbed")

class funk:
    """
    represents the function as its parsed by the ast module
    Eventually we want repo and committer (git blame) specific info here to make informed decisions
    """
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
        self.tainted_vars = []

    def __str__(self):
        return "%s %s" % (self.path, repr(self.tainted_vars))

    def __repr__(self):
        return "%s %s" % (self.path, repr(self.tainted_vars))




class loginAnalysis:
    def __init__(self, base_file_dir=None, existing_ast=None, debug=None):
        self.__base_file_dir = base_file_dir
        self.__existing_ast = existing_ast
        self.__routable = []
        self.__templates = {}
        # filename : code bundle
        # codebundle = { full path, list of functions, git history? } 
        self.__fn_to_cb = {}


        # templatename -> ast parse tree dict
        self.__template_parse_trees = {} 
        self.__tainted_variables = []

        # a security engineer is running this against a directory of code to 
        # find hints on where to look for bugs
        self.manual_mode = None
        self.verbose = None

        self.__api_routes = None

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

        n = 0
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
                                    n += 1

                    cb.funcs.append(f)
        if self.verbose:
            print "%d routable functions found" % (n)

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


    def is_dangerous_source_app_route(self, node):
        # This needs to take a func def and look at app.route calls then map to args of function? Im not even sure its a bit hairy
        """
        2. querystring args passed as argument to function via app.route(), ex:
            @app.route('/survey/<survey_id>', methods=['GET'])
            def query_survey(survey_id):
        """
        pass

    def is_dangerous_source_assignment(self, node):
        #Two families of dangerous stuff
        #1. Anything from request.*
        if isinstance(node, ast.Call):
            #print astpp.dump(node)

            # Handles foo = request.*
            if hasattr(node.func, "value") and hasattr(node.func.value, "value") and hasattr(node.func.value.value, 'id'):
                if node.func.value.value.id == 'request':
                    return True

            # handles: host = flask.request.headers.get('Host')
            if hasattr(node.func, "value") and hasattr(node.func.value, "value") and hasattr(node.func.value.value, "value") and hasattr(node.func.value.value.value, 'id') and hasattr(node.func.value.value, 'attr'):
                if node.func.value.value.value.id == 'flask' and node.func.value.value.attr == 'request':
                    return True
        return False

    def is_tainted(self, var, all_tainted_vars):
        # Take a variable and look it up in the tainted variables list to see if it is dangerous
        # This exists to handle the different variable assignment forms,
        # a = b is an ast.Assign, dicts and lists are different
        # var should always be just a string, a variable name to check

        # TODO Improvement, keep seperate lists of each type of tainted var, one for ast.Name, one for Subscript etc... will speed up minorly I imagine


        dangerous_dicts = [x for x in all_tainted_vars if isinstance(x, DangerDict)]

        # Simplist case, a = tainted; eval(a)
        if isinstance(var, ast.Name):
            if var in all_tainted_vars:
                return True

        # Dict subscript case, a = tainted, d = {"keyname" : a}; eval(d['keyname'])
        if isinstance(var, ast.Subscript):
            usage_name_of_dict = var.value.id
            usage_name_of_key = var.slice.value.s
            for dd in dangerous_dicts:
                if dd.name == usage_name_of_dict and dd.key == usage_name_of_key:
                    return True

        # Dict .get() case: a = tainted, d = {"keyname" : a}; eval(d.get("keyname"])
        if isinstance(var, ast.Call):
            if var.func.attr == "get":
                usage_name_of_dict = var.func.value.id
            if isinstance(var.args[0], ast.Str):
                usage_name_of_key = var.args[0].s
            for dd in dangerous_dicts:
                if dd.name == usage_name_of_dict and dd.key == usage_name_of_key:
                    return True



    def get_initial_tained_variables_inside_function(self, func_ast):
        tainted_variables = []
        for n in ast.walk(func_ast):
            if isinstance(n, ast.Assign):
                #print astpp.dump(n)
                if not hasattr(n.targets[0], "id"):
                    continue
                (lhs, rhs) = (n.targets[0].id, n.value)
                if self.is_dangerous_source_assignment(rhs):
                    tainted_variables.append(lhs)
        
            # Handle app.route("/foo/<some_argument>")
            if isinstance(n, ast.FunctionDef) and hasattr(n, "decorator_list"):
                if len(n.decorator_list) > 0:
                    for deco in n.decorator_list:
                        if isinstance(deco, ast.Call):
                            if hasattr(deco.func, "attr") and deco.func.attr == "route":
                                if hasattr(deco.args[0], "s"):
                                    route_string = deco.args[0].s
                                    if route_string.count("<") > 0:
                                        # We have a route string with args, map those to the args in the function then consider them tainted
                                        # ex: /signup/<city_name>/<flow_type_name>/confirmation/
                                        for arg in n.args.args:
                                            tainted_variables.append(arg.id)
                                else:
                                    # punt for now, only 2 instance
                                    continue
 
        return tainted_variables

    # This could be so much more elegant and recrusive and nice. 
    def propagate_taint(self, initial_tainted_variables, total_assigns):
        """
        Look through every assignment (within a function body) looking for assignments *from* variables we know are tainted. This set is seeded by the initial_tainted_variables list. 
        If we see an assignment from a known tainted right hand side variable to a lhs variable, make that lhs variable also tainted. 

        I haven't tested but this assumes the ordering of assignments is from start -> end of fun in the list we are passed in

        Instead of bare variable names ("a", "a2") this should really be module::class::func::variable name which will help later with analysis across function calls

        This code completely ignores if a variable we mark as tainted is later redefined to something else which should nullify the taint, to do this we need to do reaching definitions here
        https://en.wikipedia.org/wiki/Static_single_assignment_form
        """
        # Reset ugly hacky global...
        self.__tainted_variables = initial_tainted_variables

        for node in total_assigns:
           #print astpp.dump(assign) 

            if not hasattr(node.targets[0], "id"):
                continue
 
            (lhs, rhs) = (node.targets[0].id, node.value)
            # a = var_tainted case
            if isinstance(rhs, ast.Name):
                #print lhs, rhs.id
                if rhs.id in self.__tainted_variables:
                    self.__tainted_variables.append(lhs)

            # a = {'foo' : var_tainted, 'bar' : blah} case
            if isinstance(rhs, ast.Dict):
                k = rhs.keys
                v = rhs.values
                for v in rhs.values:
                    if isinstance(v, ast.Name):
                        if v.id in self.__tainted_variables:
                            # We found a tainted variable as the value in a dict definition, record the dangerous dict name and key which points to this value
                            dict_name = lhs
                            i = rhs.values.index(v)
                            key_name = rhs.keys[i].s
                            #print str(i), key_name, dict_name
                            self.__tainted_variables.append(DangerDict(dict_name, key_name))

        return self.__tainted_variables


    def api_routable_func_and_tainted(self, filename, node, tree, tainted_vars):
        """ Idea of this rule is to get all routable api funcs, then see if any tainted inputs exist in them.
        The result is a good set of places to look for bugs
        """
        permissive_auth_types = ["token", "token_or_service", "GAPING_SECURITY_HOLE", "no_auth_required"]
        permissive = []


        if hasattr(node, "decorator_list"):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and hasattr(dec, "func"):
                    if isinstance(dec.func, ast.Name) and hasattr(dec.func, "id"):
                        name_of_deco = dec.func.id
                        if name_of_deco == "UberAPI":
                            if hasattr(dec, "keywords"):
                                if not len(dec.keywords) > 0:
                                    continue
                                if not dec.keywords[0].arg == "auth":
                                    continue
                                assert(dec.keywords[0].arg == "auth")
                                auth_call = dec.keywords[0].value
                                if isinstance(auth_call, ast.Str):
                                    auth_type = auth_call.s
                                    if auth_type in permissive_auth_types:
                                        permissive.append(node)

                                if isinstance(auth_call, ast.Call):
                                    if hasattr(auth_call, "func") and hasattr(auth_call.func, "value") and hasattr(auth_call.func, "attr"):
                                        if not auth_call.func.value.id == "api_auth":
                                            continue
                                        auth_type = auth_call.func.attr
                                        if auth_type in permissive_auth_types:
                                            permissive.append(node)
            if permissive and len(tainted_vars) > 0:
                # TODO can do a lot of fun stuff here, look at body, no 403 permissions exception anywhere in the body? well that is one to look at more deeply
                print "%s +%d -> %s" % (filename, permissive[0].lineno, repr(tainted_vars))




    def find_tainted_flows(self, template_dir):
        """ Find all tainted variables then all dangerous sinks
            Given this information pass it into our collection of rules to emit issues
        """
        issues = []

        # This is a dict of template filenames -> list of dangerous variables
        # ex:  {onboarding/endorsement/index.html : ['mobile_country_iso2']}
        unsafe_templateside_info = self.get_unsafe_templateside_variables(template_dir)

        #r = get_routes("/Users/collin/src/api/Uber/uber/routing.py")
        #print repr(r)

        # For each function determine all the tainted variabls inside it and if any end up in a dangerous sink
        for fn, cb in self.__fn_to_cb.items():
            for f in cb.funcs:

                # ast = the function definition sub-ast
                tree = f.tree 

                # foreach function, get initial set of x = request.args('foo') 
                # then loop through assignments to follow assignment of x to any other variables
                initial_tainted_vars = self.get_initial_tained_variables_inside_function(f.tree)
                #print initial_tainted_vars

                total_assigns = [x for x in f.tree.body if type(x) == ast.Assign]
                tainted_vars = self.propagate_taint(initial_tainted_vars, total_assigns)
                if len(tainted_vars) > 0:
                    self.__fn_to_cb[fn].tainted_vars = tainted_vars
                    if self.manual_mode:
                        pass #print '%s:%d in %s -> '  % (fn, int(f.tree.lineno), f.tree.name) + repr(tainted_vars)
                        #print '%s:%d in %s -> '  % (fn, int(f.tree.lineno), f.tree.name) + repr(tainted_vars)

                # Find all instances of dangerous sinks
                for n in ast.walk(tree):
                    if isinstance(n, ast.Call):
                        self.webp2_render_template_sink_xss(fn, n, tree, tainted_vars, unsafe_templateside_info)
                        self.freecandy_render_template_xss(fn, n, tree, tainted_vars, unsafe_templateside_info)
                        self.urllib2_request_ssrf_check(n, tree, tainted_vars)
                        self.taishan_sqli_check(fn, n, tree, tainted_vars)

                    if isinstance(n, ast.FunctionDef):
                        self.webp2_templated_sink_xss(fn, n, tree, tainted_vars, unsafe_templateside_info)
                        self.csrf_exempt_check(n, tree, tainted_vars)
                        self.api_routable_func_and_tainted(fn, n, tree, tainted_vars)



        #issues = [ x for x in issues if x is not None]
        #print 'Issues: ' + repr(issues)

                #print astpp.dump(f.tree)



    def taishan_sqli_check(self, fn, n, tree, tainted_vars):
        pass
        # see T280774
        # we can look for any instance of filter() (normal arg or kwawg) and if tainted variables are in there raise alert
        #`.filter()`'s expression form (i.e. `.filter(Model.field == "whatever")` is always safe. The unsafe one is the string version `.filter("field = 'whatever'")`, see https://code.uberinternal.com/T266513#4926560

    def webp2_render_template_sink_xss(self, fn, node, tree, all_tainted_vars, unsafe_templateside_info):
        """
        This rule handles instances in webp2 code where we call render_template with a tainted var

        The concepts at play here:
        TEMPLATE: a template filename and an in-template varname
        all_tainted_vars: A list of variable names in this function that are tainted (come from user input)
         This render_template() call, a template filename and an optional way of passing in arguments, here we handle render_template("foo.html", foo=bar)

        We do a few comparisons below to determine if a given render_template call is...
        1. Rendering a template we know contains a |safe
        2. If the arguments to render_template actually fill the variable marked |safe
        3. For a variable that will be stuff into the |safe spot in the template, get the variable name on the python-side of things that will be going in
        4. Check to see if the variable going in is a tainted variable


        There are two common calling conventions for render_template() calls, a dict and keyword arguments.
        """

        # Handle flask.render_template() case
        if hasattr(node.func, "value"):
            if isinstance(node.func.value, ast.Name) and hasattr(node.func.value, "id"):
                if node.func.value.id == "flask" and node.func.attr == "render_template":
                    if hasattr(node, "args") and hasattr(node, "keywords"):
                        if hasattr(node.args[0], 's'):
                            template_filename_arg = node.args[0].s
                            if not unsafe_templateside_info.has_key(template_filename_arg):
                                return
                            # TODO - this needs to work just like the below, find a good way to do this without copy/pasting the code

 



        if not hasattr(node.func, "id"):
            return

        if node.func.id == 'render_template' and hasattr(node, "args") and hasattr(node, "keywords"):
            # The first arg to render_template() will always be "templatename.html"
            if hasattr(node.args[0], 's'):
                template_filename_arg = node.args[0].s
                # If templatenames dont match...
                if not unsafe_templateside_info.has_key(template_filename_arg):
                    return

                ts_vars = unsafe_templateside_info[template_filename_arg]
                if self.manual_mode:
                    print '%s:%d dangerous render_template() via %s' % (fn, node.lineno, repr(ts_vars))


                # arguments like: render_template("foo.html", {a=b, c=d})
                if len(node.args) == 2 and isinstance(node.args[1], ast.Dict):
                    arg_dict = node.args[1]

                    ak = arg_dict.keys
                    av = arg_dict.values
                    for k in arg_dict.keys:
                        if k.s in unsafe_templateside_info[template_filename_arg]:
                            i = arg_dict.keys.index(k)
                            v = av[i]
                            if v.id in all_tainted_vars:
                                print "TAINTED var \"%s\" to render_template() in %s:%d" % (v.id, fn, node.lineno)

                
                # arguments like: render_template("foo.html", a=b, c=d)
                if len(node.keywords) > 0:
                        rt_args = node.keywords
                        for x in rt_args:
                            rt_lhs = x.arg
                            if not hasattr(x.value, "id"):
                                # This means a keyword args value is a function call or something else, punt on this for now
                                continue
                            rt_rhs = x.value.id
                            if rt_lhs in unsafe_templateside_info[template_filename_arg]:
                                if rt_rhs in all_tainted_vars:
                                    print "TAINTED var \"%s\" to render_template() in %s:%d" % (rt_rhs, fn, node.lineno)





    def webp2_templated_sink_xss(self, source_filename, n, tree, all_tainted_vars, unsafe_tn_to_varnames):
        """
        Look for a function, that uses templated() with a template that is known to 
        have unsafe variables. Then check our known tainted vars to see if a tainted
        variable is the argument to the template, if so its a vuln 
        An example is: https://code.uberinternal.com/T99588
        @templated('tax_summary/index.html')

        unsafe_tn_to_varnames - this gives us unsafe variable names *on the template side*, we then need to connect that to the "call" to templated() (which is a return or extend_home_context()). Then we can see if our known tainted function level variables make it into arguments to tempalted
        """
        assert isinstance(n, ast.FunctionDef)
        issues = []

        # Two parts required here, a templated decorator and a return value of a tainted value INTO a known unsafe template value, most commonly done via a dict


        templated_danger_vars = []
        # If there is a templated() call to a dangerous template filename...
        if hasattr(n, "decorator_list"):
            if len(n.decorator_list) > 0:
                for deco in n.decorator_list:
                    if isinstance(deco, ast.Call):
                        if hasattr(deco.func, "id") and deco.func.id == 'templated':
                            if hasattr(deco, "args") and len(deco.args) > 0:
                                # We now have every instance of the @templated deco, now check to see if any are in our unsafe list
                                template_filename_arg = deco.args[0].s
                                if template_filename_arg.startswith("/"):
                                    template_filename_arg = template_filename_arg[1:]

                                # if templated(xxx) and xxx is an unsafe template...
                                if template_filename_arg in unsafe_tn_to_varnames.keys():
                                    templated_danger_vars = unsafe_tn_to_varnames[template_filename_arg]
        
        #if self.manual_mode:
        #    print "templated_danger_vars... %s" % repr(templated_danger_vars)

        # If the arguments to templated (the return value, as a dict) contained tainted vars...
        if len(templated_danger_vars) > 0:
            print "%s:%d templated() vars: %s" % (source_filename, n.lineno, repr(templated_danger_vars))
            #print repr(unsafe_tn_to_varnames.keys())
            for node in ast.walk(tree):
                if isinstance(node, ast.Return):
                    if isinstance(node.value, ast.Dict):
                        # This is tricky but all we are doing here is
                        # 1. getting all the (k,v) arguments to templated()
                        # 2. Checking if the k maps to a |safe-tagged variable name from a template
                        # 3. If it does, then we check if v, the pythonside variable going into the template slot with |safe, is tainted
                        if len(node.value.keys) > 0 and isinstance(node.value.keys[0], ast.Str):
                            intersect = [k for k in node.value.keys if k.s in templated_danger_vars]
                            L = []
                            for k in intersect:
                                i = node.value.keys.index(k)
                                try:
                                    L.append(node.value.values[i].id)
                                except:
                                    pass
                                    # TODO handle this someday, it only happened once across web-p2 so it is rare
                            pythonside_named_variables_flowing_into_unsafe_template_vars = L
                            overlap = [x for x in pythonside_named_variables_flowing_into_unsafe_template_vars if x in all_tainted_vars]

                            for v in overlap:
                                print "TAINTED var \"%s\" to @templated in %s +%d" % (v, source_filename, node.lineno)

                    if isinstance(node.value, ast.Call):
                        if hasattr(node.value.func, "id") and node.value.func.id == "extend_home_context":
                            pass
                            #print astpp.dump(node.value)
                            # TODO this work is lower-value, maybe do it someday. Only thing in the world that uses extend_home_context is web-p2 and in only ~40 places
                            #print 'got a cal.........'
                            #Call(func=Name(id='extend_home_context', ctx=Load()), args=[


    def csrf_exempt_check(self, n, tree, all_tainted_vars):
        return False

    def freecandy_render_template_xss(self, fn, n, tree, tainted_vars, unsafe_templateside_info):
        """freecandy has a few render_template() calls, a few templated() and a bunch of return smart_template()
        """
        # most look like return smart_template(template, **signup_args) so need to handle kwargs
        return False

    def eval_check(self, n, tree, all_tainted_vars):
        return False
    
    def attribute_based_jinja_xss(self, n, tree, all_tainted_vars):
        # in web-p2: find . -name "*.html" -exec grep -Hn '={{' {} \;|grep -v 'url_for'
        return False

    def urllib2_request_ssrf_check(self, n, tree, all_tainted_vars):
        #request = urllib2.Request( url="{}/{}".format(clay.config.get('login.host'), route.lstrip("/")), data=data, headers=headers)
        return False

    # TODO I think I need a genericized "is this variable name an argument to this function", has to be dict, bare arg, list maybe? keyword args.




    def build_cfg(self, ast_chunk):
        pass

    def build_dataflow_graph(self):
        pass
        # Big time.

    def build_list_of_uc_inputs(self):
        pass

    def find_template_dir(self):
        # web-p2 is web-p2/partners/templates
        # login is login/templates
        # TODO: look for invocations of `jinja2.Environment` and see if
        # we can pull the template directory / package from there? Should work
        # for most.
        template_dirs = set()
        for root, subdir, files in os.walk(self.__base_file_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                if fname.endswith(".html"):
                    with open(fpath, "rb") as f:
                        # Hmm, smells like a jinja template!
                        if b"{%" in f.read():
                            template_dirs.add(root)
        # If there are multiple template directories in a repo we might need
        # repo-specific overrides.
        return None if not template_dirs else os.path.commonprefix(template_dirs)



    def consume_dir_compile_templates(self, template_dir = None):
        templatename_to_parse_tree = {}

        if not template_dir:
            template_dir = self.find_template_dir()

        # There really are no .html teplates
        if not template_dir:
            return None

        # Transform templates from html -> py
        if self.verbose:
            print 'Template dir is.......' + repr(template_dir)
        tloader = jinja2.FileSystemLoader(template_dir)
        env = jinja2.Environment(loader=tloader)
        env.add_extension('jinja2.ext.autoescape')
        env.add_extension('jinja2.ext.do')
        # We might need some special support for this monstrosity
        env.add_extension('jinja2.ext.with_')
        env.filters = NopFilters()

        for tn in env.list_templates(".html"):
            try:
                source, filename, _ = env.loader.get_source(env, tn)
                code = env.compile(source, tn, filename, True, True)
                templatename_to_parse_tree[tn] = ast.parse(code)
            except jinja2.exceptions.TemplateSyntaxError as e:
                if self.verbose:
                    print 'Could not compile "%s": %s : %s' % (tn, e.lineno, e)
                continue
            except UnicodeDecodeError, e:
                if self.verbose:
                    print "Unicode problems with %s" % tn
                continue

        print "Processing %d py files and %d / %d templates..." % (len(self.__fn_to_cb.keys()), len(templatename_to_parse_tree.keys()), len(list(env.list_templates(".html"))))

        return templatename_to_parse_tree


    def get_unsafe_templateside_variables(self, template_dir = None):
        """
        Compile all templates into python, then look for dangerous spots in the template where there is variable subtitution.
        Currently this is:
        1. {{foo | safe}}
        2. a {{foo}} inside a <script> block

        After finding all these spots find the variables names that if substituted would create a vuln and return those
        """
        results = {}
        # output is template name : list of unsafe variables that if filled with user-controlled input would be xss
        #ex: d = {'templates/foo.html' : ['a', 'variable_blah']}



        tn_to_ast = self.consume_dir_compile_templates(template_dir)
        tn_to_unsafe_vars = self.find_all_safe_filter(tn_to_ast)
        #tn_to_unsafe_vars.append(self.find_all_attribute_xss(tn_to_ast))
        #tn_to_unsafe_vars.append(self.find_all_script_block_xss(tn_to_ast))
        return tn_to_unsafe_vars



    def find_all_safe_filter(self, tn_to_ast):
        """ Basic idea here is a few passes over the template asts, first to get calls to |safe, then to get the variables that filter is applied to
        
        returns a templatename and list of unsafe variables using the |safe filter.


        Lots going on here

        First we parsed the jinja2 .html template into python
        Then we parsed that python with the ast module
        the pattern for people using |safe in such python is that first the jinja does t_1 = environgment.filters['safe']
        Then we look for every ast.Call to t_1 whgich we know is |safe
        """


        # THINGS TO LOOK FOR AT THIS STAGE
        # attribute-based xss:   <input type="{{field_type}}" class="text-input" name="{{field_name or label}}" value="{{value}}" placeholder="{{label or field_name}}"></input>
        # <script>block based xss

        unsafe_tn_fn_pairs = []
        unsafe_tn_vn_pairs = []
        final_unsafe_tn_vn_pairs = {}

        if not tn_to_ast:
            return final_unsafe_tn_vn_pairs

        for tn, tree in tn_to_ast.items():

            for node in ast.walk(tree):

                # First step  - find the assignment of the |safe filter to a temp function
                if isinstance(node, ast.Assign):
                    """
                    1. html: <p>{{ more_info|safe }}</p> 
                    2. python: t_1 = environment.filters['safe']
                    3. python ast: value=Subscript(value=Attribute(value=Name(id='environment', ctx=Load()), attr='filters', ctx=Load()), slice=Index(value=Str(s='safe')), ctx=Load()))
                    """
                    if isinstance(node.value, ast.Subscript) and hasattr(node.value, "value"):
                        if isinstance(node.value.value, ast.Attribute):
                            if node.value.value.value.id == "environment" and node.value.value.attr == "filters":
                                if hasattr(node.value, 'slice'):
                                    if node.value.slice.value.s == 'safe':
                                        # This is an instance of safe, get the temporary variable its assigned to, ex: t_1 = environment.filters['safe'] 
                                        temp_vn = str(node.targets[0].id)
                                        unsafe_tn_fn_pairs.append( (tn, temp_vn))
                                        #print safe_func_alias_name
                                        #print astpp.dump(node)
 

        # unless the jinja code is nuts there should only ever be one instance of t_1 = |safe filter...
        for (tn, temp_vn) in unsafe_tn_fn_pairs:
            for node in ast.walk(tn_to_ast[tn]):
                if isinstance(node, ast.Call):

                    if hasattr(node.func, 'id'):
                        if node.func.id == temp_vn:
                            # This is the one filter case, ex: {{foo | safe}}
                            if hasattr(node, 'args') and hasattr(node.args[0], 'id'):
                                v = str(node.args[0].id)
                                unsafe_tn_vn_pairs.append( (tn, v))

                            # This is the two filter case, ex: {{ foo | tojson | safe }}
                            if hasattr(node, 'args') and hasattr(node.args[0], 'func'):
                                sub_func = node.args[0]
                                if hasattr(sub_func, 'args') and hasattr(sub_func.args[0], 'id'):
                                    v = str(sub_func.args[0].id)
                                    # total hack, if a variable is named _ that means its doing translations and that can never be user-controlled
                                    if v == "l__":
                                        continue

                                    unsafe_tn_vn_pairs.append( (tn, v))

        # Third step - find the definition of the variable that had |safe 
        # We either
        # 1. Look for a call like l_more_info = context.resolve('more_info')
        # 2. Instead strip the leading "l_" from the temp jinja python variable name and use that. We only do this for cases where we dont find a resolve() call
        #  and we are only operating upon instances where there is a |safe filter anyway so we prefer to lose the precision and cast the net more widely. 


        # format: {'foo/template_foo.html' : ['var_blah', 'var_doo']}

        for (tn, dangerous_var_name) in unsafe_tn_vn_pairs:
            confirmed_dangerous_var_names = []
            unconfirmed_dangerous_var_names = []

            for node in ast.walk(tn_to_ast[tn]):
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
                                if isinstance(node.value, ast.Call) and hasattr(node, 'value') and hasattr(node.value.func, 'value'):
                                    if node.value.func.value.id == "context" and node.value.func.attr == "resolve":
                                        if hasattr(node.value, 'args'):
                                            confirmed_dangerous_vn = str(node.value.args[0].s)
                                            confirmed_dangerous_var_names.append( confirmed_dangerous_vn)
                                            if not final_unsafe_tn_vn_pairs.has_key(tn):
                                                final_unsafe_tn_vn_pairs[tn] = [confirmed_dangerous_vn]
                                            else:
                                                final_unsafe_tn_vn_pairs[tn].append(confirmed_dangerous_vn)

        #print '44444444444444444444444444444..........' + repr(final_unsafe_tn_vn_pairs)


        # The ones we parse from the ast come in the form 'signup/foo.html'. Remove leading path info so they can potentially match
        template_string = os.sep + "templates" + os.sep
        really_final_unsafe_tn_vn_pairs = {}
        for tn,v in final_unsafe_tn_vn_pairs.items():
            if tn.startswith("/"):
                new_tn = tn[1:]
                really_final_unsafe_tn_vn_pairs[new_tn] = v
            else:
                really_final_unsafe_tn_vn_pairs[tn] = v
        final_unsafe_tn_vn_pairs = really_final_unsafe_tn_vn_pairs
 
        return final_unsafe_tn_vn_pairs
 


    def rule_find_incredibly_simple_jinja_xss(self):
        assert self.__base_file_dir
        # There are 5-10 more complex variations needed to cover our bases here, this is the very first and simple one I can do without "real" dataflow analysis.
        
        unsafe_tn_fn_pairs = []
        unsafe_tn_vn_pairs = []

        # Get template dir
        template_dir = self.find_template_dir()
        # Some repos don't even use Jinja
        if not template_dir:
            return
        print 'template dir....: ' + template_dir

        # Transform templates from html -> py
        tloader = jinja2.FileSystemLoader(template_dir)
        env = jinja2.Environment(loader=tloader)
        env.add_extension('jinja2.ext.autoescape')
        env.add_extension('jinja2.ext.do')
        # We might need some special support for this monstrosity
        env.add_extension('jinja2.ext.with_')
        env.filters = NopFilters()

        for tn in env.list_templates(".html"):
            try:
                source, filename, _ = env.loader.get_source(env, tn)
                code = env.compile(source, tn, filename, True, True)
                # uncomment to see python version of jinja template..
                #print code
                parse_tree_of_templates = ast.parse(code)
                self.__templates[tn] = parse_tree_of_templates
            except jinja2.exceptions.TemplateSyntaxError as e:
                print 'Could not compile "%s": %s : %s' % (tn, e.lineno, e)
                # After extensive research: if we hit this then we are not considering this template...
                # find a way to make it ignore missing tags / modules since this will come up a lot
                continue
            except UnicodeDecodeError, e:
                print "Unicode problems with %s" % tn
                continue

        print "Processing %d py files and %d / %d templates..." % (len(self.__fn_to_cb.keys()), len(self.__templates.keys()), len(list(env.list_templates(".html"))))

        # Scan/visit the py for  t_1 = environment.filters['safe']
        for tn, tree in self.__templates.items():
            for node in ast.walk(tree):

                #print astpp.dump(node)

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
        # TODO this should obviously not be just 1 and 2 cases, it should handle any depth of nested filters
        for (tn, safe_func_alias_name) in unsafe_tn_fn_pairs:
            for node in ast.walk(self.__templates[tn]):
                if isinstance(node, ast.Call):
                    if hasattr(node.func, 'id'):
                        if node.func.id == safe_func_alias_name:
                            # This is the one filter case, ex: {{foo | safe}}
                            if hasattr(node, 'args') and hasattr(node.args[0], 'id'):
                                v = str(node.args[0].id)
                                if v == "l__":
                                    continue
                                unsafe_tn_vn_pairs.append( (tn, v))
                                """
                                Call(func=Name(id='t_2', ctx=Load()), args=[
                                    Name(id='l_error', ctx=Load()),
                                  ], keywords=[], starargs=None, kwargs=None)
                                """

                            # This is the two filter case, ex: {{ foo | tojson | safe }}
                            if hasattr(node, 'args') and hasattr(node.args[0], 'func'):
                                sub_func = node.args[0]
                                if hasattr(sub_func, 'args') and hasattr(sub_func.args[0], 'id'):
                                    v = str(sub_func.args[0].id)
                                    # total hack, if a variable is named _ that means its doing translations and that can never be user-controlled
                                    if v == "l__":
                                        continue
                                    unsafe_tn_vn_pairs.append( (tn, v))
                                    """
                                    Call(func=Name(id='t_1', ctx=Load()), args=[
                                        Call(func=Name(id='t_2', ctx=Load()), args=[
                                            Name(id='l_join_data', ctx=Load()),
                                          ], keywords=[], starargs=None, kwargs=None),
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
                                if isinstance(node.value, ast.Call) and hasattr(node, 'value') and hasattr(node.value.func, 'value'):
                                    if node.value.func.value.id == "context" and node.value.func.attr == "resolve":
                                        if hasattr(node.value, 'args'):
                                            confirmed_dangerous_vn= str(node.value.args[0].s)
                                            #print "DEEP" + confirmed_dangerous_vn
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

        unsafe_template_names = [ tn for (tn, v) in final_unsafe_tn_vn_pairs] 
        unsafe_template_side_variable_names = [v[0] for (tn, v) in final_unsafe_tn_vn_pairs]


        # TODO: possible refactor to use a dict the whole time, feels more fitting datatype
        final_unsafe_tn_vn_pairs = dict(final_unsafe_tn_vn_pairs)


        # The ones we parse from the ast come in the form 'signup/foo.html'. Remove leading path info so they can potentially match
        template_string = os.sep + "templates" + os.sep
        really_final_unsafe_tn_vn_pairs = {}
        for tn,v in final_unsafe_tn_vn_pairs.items():
            if tn.startswith("/"):
                new_tn = tn[1:]
                really_final_unsafe_tn_vn_pairs[new_tn] = v
            else:
                really_final_unsafe_tn_vn_pairs[tn] = v
        final_unsafe_tn_vn_pairs = really_final_unsafe_tn_vn_pairs
 
        print "\ntemplates that use |safe:\n"
        for k,v in final_unsafe_tn_vn_pairs.items():
            print k, v


        # given listen of instances of |safe being used, get variable name and template file name (templates/signup_landing.html) and find all routable funcs that have a render_template() call using that template filename
        # for every render_template() parse the function body looking for the variable name being passed in to render_template
        # Check if that variable is user-controlled ($var = request.args['foo'])
        for path, cb in self.__fn_to_cb.items():
            for node in ast.walk(cb.tree):

                # Handle web-p2 @templated('foo.html') case
                if isinstance(node, ast.FunctionDef):
                    if hasattr(node, "decorator_list"):
                        if len(node.decorator_list) > 0:
                            for deco in node.decorator_list:
                                if isinstance(deco, ast.Call):
                                    if hasattr(deco.func, "id"):
                                        if deco.func.id == 'templated':
                                            if hasattr(deco, "args"):
                                                if len(deco.args) > 0:
                                                    # We now have every instance of the @templated deco, now check to see if any are in our unsafe list
                                                    template_filename_arg = deco.args[0].s
                                                    if template_filename_arg.startswith("/"):
                                                        template_filename_arg = template_filename_arg[1:]

                                                    if template_filename_arg in final_unsafe_tn_vn_pairs.keys():
                                                        try:
                                                            source = codegen.to_source(node)
                                                            source = ""
                                                            print "UNSAFE -> templatename: %s, unsafe var: %s\n" % (template_filename_arg, final_unsafe_tn_vn_pairs[template_filename_arg])
                                                        except:
                                                            print "UNSAFE -> templatename: %s, unsafe var: %s\n func name: %s\n" % (template_filename_arg, final_unsafe_tn_vn_pairs[template_filename_arg], node.name)

                # handles web-p2 render_template calls, should be combined with freecandy/login render_template handling code below...
                if isinstance(node, ast.Call) and hasattr(node.func, 'id'):
                    if node.func.id == 'render_template' and hasattr(node, "args") and hasattr(node, "keywords"):
                        if len(node.keywords) > 0 and hasattr(node.args[0], 's'):
                            template_filename_arg = node.args[0].s
                            if final_unsafe_tn_vn_pairs.has_key(template_filename_arg):
                                for k in node.keywords:
                                    if k.arg in final_unsafe_tn_vn_pairs[template_filename_arg]:
                                        try:
                                            source = codegen.to_source(node)
                                            source = ""
                                            print "UNSAFE -> templatename: %s, unsafe var: %s\n" % (template_filename_arg, final_unsafe_tn_vn_pairs[template_filename_arg])
                                        except:
                                            print "UNSAFE -> templatename: %s, unsafe var: %s\n func name: %s\n" % (template_filename_arg, final_unsafe_tn_vn_pairs[template_filename_arg], node.name)

 

                # Handle free-candys smart_template()
                """
                if isinstance(node, ast.Call) and hasattr(node.func, 'id'):
                    if node.func.id == 'smart_template':
                        print path
                        print astpp.dump(node.func)

                """
                # finish this later ^




                if isinstance(node, ast.Call) and hasattr(node.func, 'attr'):
                    # >1 means its render_template('foo.html', blah=blah_var) at least and not just render_template('foo.html')
                    #if node.func.attr == "render_template" and len(node.args) > 1:
                    if node.func.attr == "render_template" and len(node.args) > 0 and hasattr(node.args[0], 's'):
                        template_filename_arg = node.args[0].s

                        # TODO if a |safe is identified in a base.html its included into other things. We currently miss this. Fixable.
                        # TODO #2 - need to be more generic about paths, someone might do render_template('templates/foo.html') or render_template('foo.html') with the templates/ dir assumed
                        
                        # A render_template instance using a a template we know has an unsafe variable
                        print template_filename_arg
                        print repr(final_unsafe_tn_vn_pairs.keys())
                        if template_filename_arg in final_unsafe_tn_vn_pairs.keys():
                            """
                            This handles the following case
                            render_template('danger.html', var_foo=request.args.get('query'), var_bar="blah")
                            var_foo, var_bar are both keywords.
                            """
                            if len(node.keywords) > 0:
                                for k in node.keywords:
                                    # The dangerous render_template() call is filling a template-side variable we know is dangerous
                                    # if it is user-controlled on the python side then we have a vuln!
                                    if k.arg in final_unsafe_tn_vn_pairs[template_filename_arg]:
                                        v = k.value
                                        if isinstance(v, ast.Call):
                                            #print repr(dir(v))
                                            #assert hasattr(v.func.value.value, 'attr')
                                            #assert hasattr(v.func.value, 'attr')
                                            #assert hasattr(v.func, 'attr')
                                            #if isinstance(v.func.value.value.attr, ast.Name):
                                            #    print v.func.value.value.id

                                            # XXX LEFT OFF - whole goal here is to move beyond matching precisely flask.request.args.get(xxx) to request.args.get(xxx). A better way would be fuzzing matching where we get all parts of the call here and if there is EVER a fucking request with an args behind it consider that good enough and call it a dangerous sink. The precision here isn't totally helpful. 


                                            # request.args.get('foo')
                                            if hasattr(v.func.value.value, 'id'):
                                                if v.func.value.value.id == 'request' and v.func.value.attr == 'args' \
                                                        and v.func.attr == 'get' and isinstance(v.args[0], ast.Str):
                                                    print 'WINNER -> ' + repr(k.arg) + " in " + cb.path + " and " + template_filename_arg

                                            # flask.request.args.get('foo')
                                            if hasattr(v.func.value.value, "value"):
                                                if v.func.value.value.value.id == 'flask' and v.func.value.value.attr == 'request' \
                                                and v.func.value.attr == 'args' and v.func.attr == 'get' and isinstance(v.args[0], ast.Str):
                                                    print 'WINNER -> ' + repr(k.arg) + " in " + cb.path + " and " + template_filename_arg
                                                    #print repr(v.args[0].s)

                            """
                            At this point we have a few paths
                            1. We can match on the ast for very simple cases, ex:
                                return flask.render_template( 'collin_vulnerable.html', collin_error=flask.request.args.get('query'))
                                Handle flask.request.args.get(), flask.request.args['foo'], *.request.args.*
                            2. We can follow assignments naively, ex: 
                                blah = flask.request.args['foo'] 
                                return flask.render_template( 'collin_vulnerable.html', collin_error=blah)
                            3. We can do real dataflow analysis.

                            #3 is the best option but can't be done in one day so just do #1 right now to get end to end working.
                            """
 


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
    la.manual_mode = True
    la.verbose = False


    la.injest_dir(target_dir)
    la.determine_routability()
    #la.rule_no_csrf_protection()
    #la.get_all_routable_funcs()
    #la.rule_routable_but_no_service_auth()

    template_dir = la.find_template_dir()
    #la.rule_find_incredibly_simple_jinja_xss()
    la.find_tainted_flows(template_dir)


if __name__ == "__main__":
    main()



