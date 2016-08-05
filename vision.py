#!/usr/bin/env python

import sys
import os
import ast
import subprocess
import UserDict

import codegen
import astpp
import jinja2

import pprint








"""
TODO:
    * Make auditor mode that just shows areas of interest, lots of request. or whatnot
    * Run against taishan, login, free-candy
    * Make it gracefully handle api/, run against it, learn stuff, improve

    * DONE - Get tainted source from app.route() method
    * DONE - Break up giant jinja2 xss rule into a big sink rule that gets interesting variables from the jinja2 but is otherwise just like the eval() test
    * LOTS MORE TESTS
    * add def/use for variables that are tainted but then redefined and safe
    * taint prop through function calls... can be tricky to determine statically which function will be called but just approximate/best guess based off pythons duck typing rules (class first, then module, then global)
    * Handle taint prop through dicts....... dict creation specifically
    * Handle binOp cases where x = TAINTED; x = x + "some string"; eval(x)
    * Handle eval("foo bar baz %s" % x) case, x = tainted
    * Look through old bugs to find actual good sinks, json.dumps()? requests? urllib?


TODO:
    * Enhance jinja2 template parsing code to not only look at |safe but any variable that goes into a <script> block


README:
    focuson is a flow-insensitive, intra-procedural dataflow-based program analysis tool for python. Its aim is to find likely areas for security engineers to review for bugs. 
    In the future it will hopefully become inter-procedural and possibly flow-sensitive



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
    """ 
    An issue represents a potential security vulnerability

    This is a chain of function calls between code in a function somewhere that
    takes in user input and then later on passes that user input through
    other variables or functions to arrive at a dangerous sink.
    """
    def __init__(self, cf_of_matchpoint, call_chain):
        #self.sinkname = sinkname 
        self.cf = cf_of_matchpoint
        self.call_chain = call_chain

    def display(self):
        pass

    def __repr__(self):
        return "Issue through %s to %s" % (repr(self.call_chain), self.cf.name)


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


class sink:
    """
    Represenation of a function call which is a dangerous sink.

    A sink is a place to which if user input every flowed, could be a 
    security vulnerability. ex: a mysql_query() call in php causing sqli

    A sink is both the function call itself and the argument into it at a 
    specific offset that would be dangerous. 
    """
    def __init__(self, name, arg_offset):
        self.name = name

        # the argument to this function that, if tainted, would be a bug
        self.arg_offset = arg_offset

        # a keyword argument to this function that, if tainted, would be a bug
        self.keywords = None

        # (still in idea phase) a function that is run upon sink comparison to add custom logic
        self.kwarg_handler = None
        self.rule = None

        # Module = the module name
        self.module = None
    
    def __str__(self):
        return "%s(arg_%s)" % (self.name, self.arg_offset) 
    def __repr__(self):
        return "%s(arg_%s)" % (self.name, self.arg_offset) 


class functionTaintInfo:
    """
    This structure collects all the info we need to track tainting in/out/through a function

    This is the more specialized conceptual equal to a basic block. 
    """
    def __init__(self, name, ast=None):

        # Name is the full keyname, ex: views.vehicle_solutions.xchange::_get_xchange_status
        self.name = name

        self.ast = ast
        # Root node = main() or app.route() node, its the entry point for execution, nothing calls it, it dominates other nodes
        self.is_root_node = None

        # Functions I call in my function body
        # This is a list of keys that work in the big_map
        self.outgoing_calls = []

        # Functions that call me
        self.incoming_calls = []

        # Through-taint or trainsitively tainted.
        self.ttaint = False
        
        # a "primary" source or sink means that known dangerous sources or sinks exist in this function body
        # ex: request.args is a source, mysql_query() is a sink
        self.has_pri_sink = False
        self.has_pri_source = False

        self.pri_sinks = []
        self.pri_sources = []

        # v = Object("asdf") the varname would be "v"
        self.class_instance_varnames = []
        # v = petTurtle("asd") the classname would be "petTurtle"
        self.class_instance_classnames = []

        self.class_pairs = {}

        self.class_instances_lhs = []
        self.class_instances_rhs = []
        
        # Some funcs are inside a class
        self.class_name= None

        self.funcname = None
        self.module = None
        self.fn = None

    def __repr__(self):
        return "<function taint info> name: %s in: %s out: %s" % (self.name, repr(self.incoming_calls), repr(self.outgoing_calls))



class Engine:
    def __init__(self):
        self.__target_dir = None
        self.__fn_to_ast = {}
        self.__big_map = {}
        self.__template_dir = None
        self.perform_jinja_analysis = False

        self.verbose = False 
        self.__detective_mode = True

        self.METHOD_BLACKLIST = "format"

        self.issues_found = []

        self.uniq_modules = None 
        self.tside_unsafe_tn_to_vars = {}

        ehc_sink = sink("extend_home_context", 0)
        esc_sink = sink("extend_signup_context", 0)
        # make one for extend_signup_context
        # make one for templated() which is the same as extend_home_context...
        rt_sink = sink("render_template", 1)
        # TODO - a flask.render_template() sink and test
        eval_sink = sink("eval", 0)

        #rt_sink.kwarg_handler = self.rt_sink_kwarg_handler_func
        rt_sink.rule = self.webp2_render_template_sink_get_tainted_vars



        # TODO, could there be multiple rules attached to a sink? web-p2..login..api..etc? all need to handle render_template for instance...
        self.LIST_OF_SINKS = [
            ehc_sink,
            esc_sink,
            rt_sink,
            eval_sink,
            ]
 

    def handle_keyword_case(self, n):
        L = []
        danger_var_names = []
        template_filename = n.args[0].s
        if self.tside_unsafe_tn_to_vars.has_key(template_filename):
            danger_var_names = self.tside_unsafe_tn_to_vars[template_filename]

        for k in n.keywords:
            arg = k.arg
            val = k.value
            # handle this some day... it cant handle when the value is anything but 
            # an ast.Name right now, which is probably reasonable
            # ex: sink("asdf", foo=someFunc(asdf))
            if not isinstance(val, ast.Name):
                continue

            # veeeeeery small set
            if arg in danger_var_names:
                # a list of ast.Names
                if isinstance(k.value, ast.Name):
                    L.append(k.value.id)
        return L



    def webp2_render_template_sink_get_tainted_vars(self, n, arg_offset):
        """
        this function takes all we know about templates, return a list of python-side variable names
        that we know to be tainted. 

        TODO - grab good comment from webp2 other rule function...
        """

        # sinkvar = the "thing" being passed into a known dangerous sink at a 
        # known dangerous argument offset. ex: mysql_query() argument 0.
        # This can be a variable (Name), a list, a dict or a call. 
        print 'in rulee..........'
        
        # XXX RENAME AND recomment to make this varnames, because that is all it should be, bare strings not ast.Names or anything......
        tainted_vars = []

        # A sink needs to have at least 1 argument
        if not hasattr(n, "args"):
            return tainted_vars 
        if not len(n.args) > 0:
            return tainted_vars 


        sv_list = []
        # Handle the different forms a sinks arguments take
        # normal, keywords and kwargs

        # keyword arguments, sink(foo=var_1)
        if len(n.keywords) > 0:
            res = self.handle_keyword_case(n) 
            if len(res) > 0:
                sv_list.append(res)

        # kwargs form, sink(**template_vars)
        elif n.kwargs and isinstance(n.kwargs, ast.Name):
            sv_list = [n.kwargs.id]

        # Normal form, sink(var_1, var_2)
        else:
            # Its possible to call our sink()s without the number of args it takes for taint to propagate
            # ex: render_template('foo.html') instead of render_template('foo.html', some_var)
            if (arg_offset + 1) > len(n.args):
                sv_list = []
            else:
                # Its expected this is the most common case
                sinkvar = n.args[arg_offset]
                sv_list = [sinkvar]
        

        # We have collected some ast.Names instances, get their actual varname out and return it
        for sinkvar in sv_list:
            # The simple case. A normal variable name is the argument
            if isinstance(sinkvar, ast.Name):
                tvarname = sinkvar.id
                tainted_vars.append(tvarname)

            # The argument into the sink is a dict, explode it into 
            # assigns and mark the rhs varname as a tainted var
            if isinstance(sinkvar, ast.Dict):
                k = sinkvar.keys
                v = sinkvar.values
                for v in sinkvar.values:
                    if isinstance(v, ast.Name):
                        tainted_vars.append(v.id)
                        # TODO more work here, the value of a dict entry can be another dict, a list, and commonly a Call()...
                        # also account for True/False etc
                    else:
                        print 'it happened?????????????'
                        print astpp.dump(v)
        
            # This is complex to handle, punt for now
            if isinstance(sinkvar, ast.Call):
                continue
            if isinstance(sinkvar, ast.List):
                continue

        return tainted_vars

    def rt_sink_kwarg_handler_func(self, n):
        """
        This is code that is run every time a Call() instance for render_template() 
        happens where the arguments are kwargs ({a=b, c=d}, etc)
        
        This function uses all the jinja templateside info created to determine if
        a given instance of a render_template() call is actually vulnerable.

        its debatable if this logic should live IN the sink() class.


        n = a sink Call()s ast
     keywords=[
            keyword(arg='android_deep_link', value=Name(id='collin_final', ctx=Load())),
            keyword(arg='one', value=Name(id='foo_one', ctx=Load())),
            keyword(arg='two', value=Name(id='foo_two', ctx=Load())),
          ]
        """
        # also have to do work ahead of time for render_template (all the template |safe parsing...) to even know what the set of kwargs are that ARE dangerous....
        #danger_var_names = ['two', 'android_deep_link']
        danger_var_names = []
        
        template_filename = n.args[0].s
        print 'trying......', template_filename
        if self.tside_unsafe_tn_to_vars.has_key(template_filename):
            print '\n\n found one', template_filename
            danger_var_names = self.tside_unsafe_tn_to_vars[template_filename]
            print repr(danger_var_names)

        # XXX the realization is that this whole thing needs to be a rule run for eVERY case of render_template... not just the kwarg case....
        # in which case its basically a rule, like I made before. So expand this somewhat to account for that. Maybe do the same with the other sink() as well

        kw_list = n.keywords
        L = []

        for k in kw_list:
            arg = k.arg
            val = k.value
            # handle this some day... it cant handle when the value is anything but 
            # an ast.Name right now, which is probably reasonable
            # ex: sink("asdf", foo=someFunc(asdf))
            if not isinstance(val, ast.Name):
                continue

            if arg in danger_var_names:
                print 'here........'
                print repr(self.tside_unsafe_tn_to_vars)
                print astpp.dump(n)
                L.append(k.value)

        # return a list of ast.Names
        return L



    def ingest(self, rootdir):
        """
        Collect all the .py files to perform analysis upon
        """
        if not os.path.isdir(rootdir):
            raise Exception("directory %s passed in is not a dir" % rootdir)
        
        self.__target_dir = rootdir 

        # walk the dirs/files
        for root, subdir, files in os.walk(self.__target_dir):
            for f in files:
                if f.endswith(".py"):
                    fullpath = root + os.sep + f
                    contents = file(fullpath).read()
                    tree = ast.parse(contents)
                    self.__fn_to_ast[fullpath] = tree 

        # potentially analyze .html files for jinja templates
        if self.perform_jinja_analysis:
            self.__template_dir = self.get_template_dir()

    def derive_module(self, fn):
        # do something with the base processing dir... 
        # do more cleverness to figure out what portion of the filename is an importable
        # python module... maybe just venv try to import it?!
        # Since this is expensive maybe persist to disk/sqlite db
        
        # TODO this critical to get right and almost certainly wrong... just testing for now....
        # it works for tests but not partners... need more sophisticated work than lopping off the end foo.py file
        # and calling that the module....
        L = fn.split(os.sep)
        last = L[-1]
        if last.endswith('.py'):
            last = last[:-3]
        return last

    def process_funcs(self):
        """
        Take all the asts for each python file ingested and create a new dict, big_map, 
        keyed off the function name and whose values are a bundle of useful info for taint analysis
        """
        if not self.__fn_to_ast.keys() > 0:
            raise Exception("No asts parsed from filenames to analyze")
        
        processed_class_methods = []

        project_imports = {}

        # Round 0 - Determine what each file imports 
        #  One python file (f1) commonly imports another python file (f2) as a module 
        #  to call the functions inside it. To map which functions call which other
        #  functions we want to find all of these. 
        for (fn, fn_ast) in self.__fn_to_ast.items():
            # Note, if the same module is imported two different ways one entry
            # will be overwritten. This is rare in real code but be aware
            imports_for_fn = {}
            for n in ast.walk(fn_ast):
                if isinstance(n, ast.Import):
                    for x in n.names:
                        imports_for_fn[x.name] = None

                if isinstance(n, ast.ImportFrom):
                    names = [x.name for x in n.names]
                    imports_for_fn[n.module] = names
            project_imports[fn] = imports_for_fn

        # print import map
        #pp = pprint.PrettyPrinter(depth=6)
        #pp.pprint(project_imports)

        #fti.imports.keys() = "os urllib lib.lib_one.temporary_token"
        #fti.imports['lib.lib_one.temporary_token'] returns "TemporaryToken foo bar"

        # Round 1 - add all the class methods to the big map
        for (fn, fn_ast) in self.__fn_to_ast.items():
            for n in ast.walk(fn_ast):
                if isinstance(n, ast.ClassDef):
                    methods = [x for x in n.body if isinstance(x, ast.FunctionDef)]
                    for m in methods:
                        method_ast = m
                        class_name = n.name

                        modulename = self.gen_module_name(fn)
                        (name, funcname) = self.gen_unique_key(modulename, method_ast.name, class_name)
                        processed_class_methods.append(method_ast)

                        fti = functionTaintInfo(name)
                        fti.ast = method_ast
                        fti.fn = fn
                        fti.module = modulename
                        fti.funcname = funcname
                        fti.class_name = class_name
                        self.__big_map[name] = fti



        # Round 2 - add all the bare (not in a class) functions to the big map
        for (fn, fn_ast) in self.__fn_to_ast.items():
            for n in ast.walk(fn_ast):
                if isinstance(n, ast.FunctionDef):
                    # It is critical we look at all functionDefs as some are not
                    # part of a class but we already processed any of them inside
                    # a class so skip those same ones heres
                    if n in processed_class_methods:
                        continue

                    modulename = self.gen_module_name(fn)
                    (name,  funcname) = self.gen_unique_key(modulename, n.name)
                    #print 'funcdef case: ', name
                    #print astpp.dump(n)

                    # Process this function and collect all the useful info for later
                    fti = functionTaintInfo(name)
                    fti.ast = n
                    fti.fn = fn
                    fti.module = modulename
                    fti.funcname = funcname
                    self.__big_map[name] = fti



        # Round 2.5 - For each function record what modules it imports
        # this sets the stage for us determining which fundef calls another funcdef later
        for (name, fti) in self.__big_map.items():
            fn = fti.fn
            fti.imports = project_imports[fn]


        # Round 3 - Find every Call() made in each function in big map
        # For each Call(), resolve it to the right method in the big map
        for (name, fti) in self.__big_map.items():
            #print name, repr(fti)
            fti.outgoing_calls = self.get_outgoing_calls(fti)

        # Round 3 - for each function compute a list of all caller functions
        # This is why we should be using a graph, not a big dict... fast querying from either "side".
        who_called_me = {}
        for (name, fti) in self.__big_map.items():
            called = fti.outgoing_calls
            for fn in called:
                if who_called_me.has_key(fn):
                    who_called_me[fn].append(name)
                else:
                    who_called_me[fn] = [name]

                self.__big_map[fn].incoming_calls.append(name)

        # Useful for debugging
        #print '\n\nWho called who: '
        #pp = pprint.PrettyPrinter(depth=6)
        #pp.pprint(who_called_me)

        
        # Round 3 - foreach function see if its body contains any known
        # dangerous sources or sinks
        for (name, fti) in self.__big_map.items():
            fti.pri_sinks = self.get_pri_sinks(fti)
            fti.has_pri_sink = bool(len(fti.pri_sinks))

            fti.has_pri_source = self.get_sources(fti)


    def main_analysis(self):
        """
        Performs a path-insensitive, inter-functional dataflow analysis. 

        Roughly we:
        1. Find all the dangerous sinks in all files. 
        2. Look at every function with a dangerous sink
        3. For every sinky function, get all callers to it.
        4. For each caller determine if an argument passed into it is propagated from arg -> return, if so it transmits taint
        5. recursively look at every transitively tainted function

        This is performing "bottoms up" or sink-first analysis in contrast to top-down or source-first
        """

        #bottom-taint (sinks), top-taint (sources)
        initial_sink_tainted_funcs = [k for (k,v) in self.__big_map.items() if v.has_pri_sink == True]
        if self.__detective_mode:
            print '\n\n%d functions containing an initial sink' % len(initial_sink_tainted_funcs)


        if self.perform_jinja_analysis:
            self.tside_unsafe_tn_to_vars = self.get_unsafe_templateside_variables(self.__template_dir)
            # ex: tSIDE.......{'open-app.html': ['iphone_deep_link', 'iphone_fallback_link', 'android_deep_link', 'android_fallback_link']}
            # TODO need to actually *use* the templateside info, for each appropriate sink (render_template, templated, etc) we need to identify
            # which instances accept dangerous.html as the argument and then make those specifc sinks, or organize this a different way.....
            # maybe .....

        self.walkup(initial_sink_tainted_funcs, self.LIST_OF_SINKS)

        if self.__detective_mode:
            ttainted_funcs = [v.funcname for (k,v) in self.__big_map.items() if v.ttaint == True]
            not_ttainted_funcs = [v.funcname for (k,v) in self.__big_map.items() if v.ttaint == False]
            print "%d functions analyzed" % len(self.__big_map.keys())
            print "%d ttainted: %s " % (len(ttainted_funcs), repr(ttainted_funcs))
            #print "%d not ttainted: %s" % (len(not_ttainted_funcs), repr(not_ttainted_funcs))


    def parse_call(self, n):
        #print '\tparsing a call...'
        #print astpp.dump(n)

        func_name = None
        arg_offset_pairs = []

        # A some_lib.foo() type Call
        if isinstance(n.func, ast.Attribute):
            if hasattr(n.func.value, "id") and hasattr(n.func, "attr"):
                #print n.func.value.id
                #print s.module
                #print n.func.attr
                #print s.name
                #print astpp.dump(n.func)

                func_name = n.func.attr
                if len(n.args) > 0:
                    for a in n.args:
                        if isinstance(a, ast.Name):
                            i = n.args.index(a)
                            p = (a.id, i)
                            arg_offset_pairs.append(p)

        return func_name, arg_offset_pairs

    def collect_sinky_varnames(self, incoming_sinks, cf):
        """
        Return all the variable names from within this function (cf) 
        that are passed to a dangerous sink at a dangerous offset. 

        These variable names are later exploded to find the maximum set of
        variables like this possible via assignments.

        All this code does is:
        find the variable names that are passed into a sink, at a specific offset. 
        If we find such a variable name record it and return it for further processing

        This is made hard as arguments to a function can be bare variables, dicts, etc so most of 
        the effort here is parsing those variations to deliver one, or potentially a set, of bare variable names
        like ["foo", "blah"] that we are certain are function-local (bb-local) variables that make it into a dangerous sink in a dangerous
        "slot". The "slot" is represented by an arg_offset which is just the position of the argument. 
        ex:
         sink(a, b, c) and only an argument in c is vulnerable
         blah = "asdf"
         sink(42, "foo", blah) -> returns ("blah", 2)
        """

        # We return a dict where keys = sinky varnames and values are
        # the rules that triggered them (for later reporting)
        tainted_vars = {}
        for s in incoming_sinks:
            # Get the function-scoped variable name of the argument to our sink
            for n in ast.walk(cf.ast):
                if isinstance(n, ast.Call):
                    # First try parsing as some_lib.foo()
                    # TODO rename and possible remove this... see down below where we handle lots of cases
                    func_name, arg_offset_pairs = self.parse_call(n)


                    if func_name == s.name and len(arg_offset_pairs) > 0:
                        #tainted_vars.append(args_into_func[offset])
                        #print "\t\t", func_name + "()"
                        #print "\t\t so->", s.arg_offset
                        for (arg_into_func, arg_offset) in arg_offset_pairs:
                            #print "\t\t", arg_into_func
                            #print "\t\t", arg_offset
                            if arg_offset == s.arg_offset:
                                tainted_vars[arg_into_func] = s.name

                    elif func_name == None:
                        #func_name, arg_offset_pairs = self.parse_as_other_case()
                        pass
                        


                    if isinstance(n.func, ast.Name) and hasattr(n.func, "id") and n.func.id == s.name:

                        if not hasattr(n, "args"):
                            continue
                        if not len(n.args) > 0:
                            continue

                        try:
                            sinkvar = n.args[s.arg_offset]
                        except IndexError:
                            # Weird case, we have a sink and an offset and the
                            # case of that sink we found doesn't fit that
                            # argument pattern, just continue
                            # Seen this happen with render_template(var)
                            # where we instead expect render_template("blah/foo.html", var)
                            continue


                        if isinstance(sinkvar, ast.Name):
                            #tainted_vars.append(sinkvar.id)
                            tainted_vars[sinkvar.id] = s.name

                        elif isinstance(sinkvar, ast.Dict):
                            for k in sinkvar.keys:
                                i = sinkvar.keys.index(k)
                                v = sinkvar.values[i]
                                if isinstance(v, ast.Name):
                                    # We can comprehend this, its a varname as a value in a dict, taint it
                                    tainted_vars[v.id] = s.name
        return tainted_vars


    def get_functions_args(self, cf):
        """
        Collect the argument names to this function
        """
        args = [arg.id for arg in cf.ast.args.args]

        # if this method is in a class its first argument will be "self"
        if args.count("self") > 0:
            i = args.index("self")
            del args[i]
        return args



    def far_taint_analysis(self, cf_key, incoming_sinks):
        """ 
        cf = current function
        incoming_sinks = a set of tainted sinks to check against

        Determine if:
         1. Any of cf's sources flow to any of these sinks. If so, bug.
         2. Any of cf's arguments flow to any of these sinks. If so, Im tainted.
            In this case I BECOME a sink for the next round. 


        We do this in stages 
        1. Find args to incoming_sinks 
        2. Find assignments to those args
        3. Find any args to cf itself that flow to those assignments

        Some of this may look unintuitive because this is bottoms-up analysis

        We would expect the contents of incoming_sinks to be things like
        extend_home_contract()/mysql_query()/etc AND randomFunc2() that is 
        transitively tainted from previous rounds.

        """
        # A few stages here
        # 1. Find all matching sinks + args to those sinks, the name of one of those is sinkvar
        # 2. Given that variable look through assigns to propagate taint upwards from sinkvar
        # 3. With the full set of tainted variables in this function, see if the functions 
        #   arguments itself flow ultimately to that tainted sink. If they do, mark function transitively tainted!


        cf = self.__big_map[cf_key]
        if self.verbose:
            print '\n\ncf: ', cf_key
            print '\tcf.callers: ', cf.incoming_calls
        
        if not cf:
            return

        assert isinstance(cf.ast, ast.FunctionDef)

        #print astpp.dump(cf.ast)
        #print '\tcf incoming tainted sinks: %s' % repr(incoming_sinks)


        # The set of sinks to investigate in the next round. If we are 
        # transitively tainted this will include us. 
        outgoing_sinks = []

        tainted_vars = []
        tainted_vars_to_sinks = self.collect_sinky_varnames(incoming_sinks, cf)
        tainted_vars = tainted_vars_to_sinks.keys()



        # At this stage tainted_vars are all ast.Names or ast.Dicts etc so extract the actual variable names

        #print '\n'
        #print '..... tghe tainted vars inside.......'
        #for x in tainted_vars:
        #    print '-' * 80
        #    if isinstance(x, str):
        #        print x


        # Look at all assigns to determine if an argument to this function flows to the sinks arguments
        if tainted_vars:
            assigns = []
            if self.verbose:
                print '\t [1]tainted vars inside cf: ', repr(tainted_vars)

            # Collect list of assigns
            for n in ast.walk(cf.ast):
                if isinstance(n, ast.Assign):
                    if not hasattr(n.targets[0], "id") or not hasattr(n.value, "id"):
                        continue
                    (lhs, rhs) = (n.targets[0].id, n.value.id)
                    assigns.append((lhs, rhs))
     
            #print '\t cf assigns..........', repr(assigns)

            # if we have 8 assigns we need to do 8*8 rounds through loop to 
            # ensure the assignment taint correctly propagated.
            # This looks unintuitive because we propagate taint bottom up
            for x in range(len(assigns)):
                for (lhs, rhs) in assigns:
                    if lhs in tainted_vars:
                        tainted_vars.append(rhs)

            # The full unique set of tainted vars
            tainted_vars = list(set(tainted_vars))
            
            if self.verbose: 
                print '\t [2]tainted vars inside cf: ', repr(tainted_vars)
            #print "===========> %s sinks: %s tainted vars: %s" % (cf.name, repr(incoming_sinks), repr(tainted_vars))

            # If there are any sources in this function, we have a bug!
            matches = []
            matches = self.find_tainted_sources(cf, tainted_vars)
            # matches are the varnames in tainted vars that are also 
            # the lhs on a source assignment
            if matches:
                self.file_bug(cf, matches, tainted_vars_to_sinks)

            # Mark ourselves as a dangerous sink if we propagate taint from our args to a sink
            # We now have the full set of tainted vars inside this function that flow to the sink
            # compare these to the functions arguments to know what calls into *this* function 
            args = self.get_functions_args(cf)
            overlap = set(tainted_vars).intersection(set(args))
            if overlap:
                #print '\tcf args of mine that flow to tainted sinks:', repr(overlap)
                for targ in list(overlap):
                    targ_offset = args.index(targ)
                    s = sink(cf.ast.name, targ_offset)

                    #print '\t ginning a new sink........', repr(s)

                    outgoing_sinks.append(s)
                    # We know cf propagates taint, mark that
                    self.__big_map[cf_key].ttaint = True
            else:
                self.__big_map[cf_key].ttaint = False


        # We can conclude I, cf, am trainsitively tainted so return my callers
        # to be recursively investigated as I was
        if self.__big_map[cf_key].ttaint:
            return cf.incoming_calls, outgoing_sinks
        else:
            return [], outgoing_sinks






    def find_tainted_sources(self, cf, sink_tainted_vars):
        matches = []
        source_tainted_vars = []
        for n in ast.walk(cf.ast):
            # Look at all the assigns to find any cases of foo = request.*
            if isinstance(n, ast.Assign):
                if not hasattr(n.targets[0], "id"):
                    continue
                (lhs, rhs) = (n.targets[0].id, n.value)
                #print 'lhs: %s' % repr(lhs)
                #print 'rhs: %s' % repr(rhs)
                if self.dangerous_source_assignment(rhs):
                    source_tainted_vars.append(lhs)

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
                                            source_tainted_vars.append(arg.id)
 
        #print "\t sink tainted: %s" % repr(sink_tainted_vars)
        #print "\t source tainted: %s" % repr(source_tainted_vars)
        for v in source_tainted_vars:
            if v in sink_tainted_vars:
                matches.append(v)

        return matches

    def file_bug(self, cf, matches, tainted_vars_to_sinks):
        #print '\n\n!!!!A bug!!!!'


        #source = codegen.to_source(fti.ast)
        #self.issues_found.append()
        varname_into_sink = matches[0]
        #print astpp.dump(self.__big_map[cf]

        call_chain = [cf.funcname]
        bug_str = "%s() var $%s in " % (cf.funcname, matches[0])
        L = [cf]
        while len(L) > 0:
            cf = L.pop()
            bug_str += " -> %s()" % cf.name
            callers = cf.outgoing_calls
            callers_fti = []
            for c in callers:
                callers_fti.append(self.__big_map[c])
            tainted_callers = [x for x in callers_fti if x.ttaint]
            for tc in tainted_callers:
                L.append(tc)
                call_chain.append(tc.funcname)
        
        sinkname = "eval" #tainted_vars_to_sinks[start_of_chain_varname]
        cf_of_matchpoint = cf

        #source = codegen.to_source(cf.ast)
        #print repr(source)
        issue = Issue(cf_of_matchpoint, call_chain)
        self.issues_found.append(issue)
        #print bug_str


    def dangerous_source_assignment(self, n):
        """
        Look at an the right hand side of an assignment to determine if dangerous.
        Right now this only means flask request object represented in a few ways. 
        """

        # xx = True/False/None, skip em
        if isinstance(n, ast.Name):
            return False

        if isinstance(n, ast.Subscript):
            # xx = request.args['foo']
            if hasattr(n, "value") and hasattr(n.value, "value"):
                if n.value.value.id == "request":
                    return True

            # xx = dictname[some_var_as_key]
            if hasattr(n, "value") and not hasattr(n.value, "value"):
                # Lots of work could be done here but it is hard.. punting. 
                # Need to do more inside-func analysis like with assigns but for dict keys
                return False
            else:
                # Could be rhs here is an object, ex:
                # trips_required = fuel_cards_config.trips_required[g.user.flow_type_name.lower()]
                return False
                #print '\n\n'
                #print astpp.dump(n)
                #raise Exception("some wonky case nammed in source assignment")

        # xx = request.args.get('foo') is an ast.Call()
        if isinstance(n, ast.Call):
            if hasattr(n.func, "value") and hasattr(n.func.value, "value") \
                    and hasattr(n.func.value.value, 'id'):
                if n.func.value.value.id == 'request':
                    return True

            #  xxx = flask.request.headers.get('Host')
            if hasattr(n.func, "value") and hasattr(n.func.value, "value") \
                    and hasattr(n.func.value.value, "value") \
                    and hasattr(n.func.value.value.value, 'id') \
                    and hasattr(n.func.value.value, 'attr'):
                if n.func.value.value.value.id == 'flask' and n.func.value.value.attr == 'request':
                    return True
        return False



    def walkup(self, func_list, sink_list):
        """
        Recursively analyize functions to determine of they propagate taint.

        Each iteration of walkup() collects more sinks and functions to check out

        func_list is a set of functions that call into or contain tainted sinks
        sink_list could be primary sinks (mysql_query) or transitive (function blah(arg1, arg2) which we know passes arg1 into mysql_query()
        """

        while len(func_list) > 0:

            # The current function to work
            cf_key = func_list.pop()
            cf = self.__big_map[cf_key]

            if self.verbose:
                print "\n Incoming f: %s sinks: %s" % (cf.name, repr(sink_list))


            funcs_to_check_out, sinks_to_consider = self.far_taint_analysis(cf_key, sink_list)
            #print "\toutgoing f: %s sinks: %s" % (repr(funcs_to_check_out), repr(sinks_to_consider))
            self.walkup(funcs_to_check_out, sinks_to_consider)



    def intra_taint_analysis(self, fti):
        """ Given a function determine
        """
        pass

        # TODO other big chunk of work is doing the assingment analysis inside the function body
        """
         I think we basically want to determine bottoms up here
         that means if a->b->c->d->e and we are c() and e() has dangerous_sink our goal is to
         figure out if:
         1. we have a danger source that feeds into our Call of d() which feeds into its Call of e() which feeds into e()s dangerous_sink() call
         2. If not #1, we want to figure out all our callers and walk up the chain (which is handled by walkup() above)

         We want to determine if any of our inputs as a func (arguments) make it to OUR dangerous sink which isn't a REAL PRIMARY dangerous sink like mysql_query() but instead
         the function call to d() or e() which themselves have been checked for trainsitive or primary taintedness.
        """
        
                
    def get_pri_sinks(self, fti):
        """ 
        Return any dangerous sinks in the body of a function.
        pri = primary aka originate from here instead of transitive.
        """
        L = []
        for n in ast.walk(fti.ast):
            if isinstance(n, ast.Call):
                if hasattr(n.func, "id"):
                    for s in self.LIST_OF_SINKS:
                        if n.func.id == s.name:
                            L.append(s)
        return L


    def get_sources(self, fti):
        # TODO parse the body of a given ast funcDef and determine if there are any request.* whatevers
        L = []
        return L
        
    
    def handle_outfile_calls(self, n, fti):
        """
        One python file (f1) commonly imports another python file (f2) as a module 
        to call the functions inside it. To map which functions call which other
        functions we want to find all of these. 

        Currently we do this by checking fuzzily checking the imports of f2 in f1
        to get a baseline set of functions in f2 that could be called from f1. 

        Then we identify and return any instances of Calls() to f2s funcs
        """
        # Determine the maximum set of functions that *could* be callable in F1 from F2
        # do this from a computed-once set of imports done per-file, maybe something like:
        # fti.modules_imported

        if n.func.value.id in self.uniq_modules:
            # we return it in the format used for keys in the big map. Hopefully change this format later
            # ex: '/some_lib.py::far_out': <function taint info> name: /some_lib.py::far_out in: [] out: [],
            s = "/" + n.func.value.id + ".py" + "::" + n.func.attr
            return s


    def wrangle_classname_from_call(self, n):

        #print 'wrangling.........'
        #print astpp.dump(n)
        if isinstance(n, ast.Name):
            return n.id
        if isinstance(n, ast.Attribute):
            return None
            # ugggghhh, no "correct" answer here. 
            # Need to spend time teasing out all the variations here but start with the above to progress for now
            #return n.value.id
            #Examples of one that breaks
            #<_ast.Call object at 0x10d819ed0>
            #wrangling.........
            #Attribute(value=Attribute(value=Name(id='request', ctx=Load()), attr='args', ctx=Load()), attr='get', ctx=Load())
        """
        Two examples
        Call(func=Attribute(value=Name(id='flask', ctx=Load()), attr='Flask', ctx=Load()), args=[
            Name(id='__name__', ctx=Load()),
          ], keywords=[], starargs=None, kwargs=None)

        Call(func=Name(id='TemporaryToken', ctx=Load()), args=[
            Name(id='user', ctx=Load()),
          ], keywords=[], starargs=None, kwargs=None)
        """

    def get_outgoing_calls(self, fti):
        """ 
        Given a function, f1 determine all the other functions f1 calls.
        Return all those functions to be used later for taint propagation

        Determining what code is being called in a situation is hard. 
        So we guess. The cases we expect to see are:
        1. foo() - easiest.calling the foo function inside the existing module
            made trickier becacuse it can happen anywhere like as part
            of an assign or a return or inside a dict etc

        2. dog.bark() - could be the dog class, could be the dog module
            
        3. (probably other cases)
        
        The outgoing_calls list is what to pay attention to, everything boils
        down to adding entries to it where each entry is a key in the big map.
        """

        assert type(fti.ast) == ast.FunctionDef
        #print 'Figuring out calls for ', fti.name

        #source = codegen.to_source(fti.ast)


        # Step 1 - collect all the places where we instantiate a class and assign it to a variable
        # This so later we can untangle what actual code a Call() points to
        instancenames_inside_func = []
        classes_instantiated_inside_func = []
        for n in ast.walk(fti.ast):
            if isinstance(n, ast.Assign):
                if isinstance(n.value, ast.Call):

                    lhs = n.targets[0]
                    if not isinstance(lhs, ast.Name):
                        continue
                        #raise("this is strange...")

                    instancename = lhs.id
                    # ex: token = TempToken(blah), append "token" so we 
                    # know that it is actually an instance of a class and
                    # not a "normal" variable.
                    instancenames_inside_func.append(instancename)

                    # Can be a name or an attr... decipher...
                    class_name = self.wrangle_classname_from_call(n.value.func)
                    classes_instantiated_inside_func.append(class_name)
                    fti.class_pairs[instancename] = class_name

        fti.class_instance_varnames = instancenames_inside_func 
        fti.class_instance_classnames = classes_instantiated_inside_func




        # Step 2 - analyze all the Call()s
        # Handle all the different forms, function call, a call to a method on a class, etc
        outgoing_calls = []
        for n in ast.walk(fti.ast):
            if isinstance(n, ast.Call):

                # Calls() are often Names or Attribute nodes and Names are
                # the easier of the cases.
                if isinstance(n.func, ast.Name):
                    funcname = n.func.id
                    #print 'Call(easy).......', repr(funcname)

                    # A big blacklist of functions that if there is a Call() instance to, we dont care
                    # This is for things we know are safe or happen often and are likely safe
                    # Currently this is mostly _ (translation function) and things prefaced with test_
                    if funcname == "_" or funcname.startswith("test_"):
                        continue

                    # This is *really* permissive, if anywhere in the project we find a function
                    # named the same as one we call, toss it in. 
                    for k,v in self.__big_map.items():
                        if funcname == v.funcname:
                            outgoing_calls.append(k)



                """ 
                The hard case
                Could be class.method(), could be module.func()
                could even be self.func()
                """
                if isinstance(n.func, ast.Attribute):
                    if hasattr(n.func.value, "id"):
                        #print 'Call(hard)........',repr(n.func.value.id)

                        # Technically this is a method or a func name and we
                        # are not yet sure which one. 
                        method_name = n.func.attr
                        #print method_name

                        """
                        The lefthand side of a call.
                        For the class.method() for ex:
                         l2 = someClass(); l2.someMethod()
                        For the module.func() case for ex:
                         somelib.far_out()
                        lhs = "l2" in the first and "somelib" in the second
                        """
                        lhs = n.func.value.id

                        # self.someFunc() case so  use the class within which this function lives
                        if lhs == "self":
                            key = self.get_key_from_info(method_name, fti.class_name)
                            if self.__big_map.has_key(key):
                                outgoing_calls.append(key)
                        
                        # Next check the class.method() scenario.
                        if lhs in fti.class_instance_varnames:
                            class_of_varname = fti.class_pairs[lhs]


                            if method_name in self.METHOD_BLACKLIST:
                                continue

                            if class_of_varname and method_name:
                                # make this a func that returns a key into the big map given some info about
                                # a function/class/method/etc
                                key = self.get_key_from_info(method_name, class_of_varname)

                                # TODO get this working instead of above, its more elegant......
                                #(key, _) = self.gen_unique_key(fti.fn, method_name, class_of_varname)
                                #print 'genned key......', key
                                if self.__big_map.has_key(key):
                                    outgoing_calls.append(key)

                        # Wasn't class.method() so assume module.func() case
                        else:
                            module_name = lhs
                            # Assuming its an imported module, ensure its in import list for this function 
                            if fti.imports.has_key(module_name):
                                (key, _) = self.gen_unique_key(module_name, method_name)
                                if self.__big_map.has_key(key):
                                    outgoing_calls.append(key)


        if len(outgoing_calls) > 0:
            #print 'I, %s call these funcs: %s' % (fti.name, repr(outgoing_calls))
            pass

        return outgoing_calls 

    def get_key_from_info(self, funcname, class_name=None):
        """ Given some info return a key into the Big Map
            This is its own func because it at least encapsulates the lameness of
            iterating through everything to get a key. This could/should be refactored into 
            gen_module_name() most likely...
        """
        for k,v in self.__big_map.items():
            if v.class_name == class_name and v.funcname == funcname:
                return k


    def get_fn_from_call(self, fti):
        L = []

        # Step 2 - analyze all the Call()s
        # Handle all the different forms, function call, a call to a method on a class, etc
        outgoing_calls = []
        for n in ast.walk(fti.ast):
            if isinstance(n, ast.Call):

                # Calls() are often Names or Attribute nodes
                # Names are generally the easier of the two
                if isinstance(n.func, ast.Name):
                    funcname = n.func.id
                    #print 'Call(easy).......', repr(funcname)

                    # A big blacklist of functions that if there is a Call() instance to, we dont care
                    # This is for things we know are safe or happen often and are likely safe
                    # Currently this is mostly _ (translation function) and things prefaced with test_
                    if funcname == "_" or funcname.startswith("test_"):
                        continue

                    # This is *really* permissive, if anywhere in the project we find a function
                    # named the same as one we call, toss it in. 
                    for k,v in self.__big_map.items():
                        if funcname == v.funcname:
                            outgoing_calls.append(k)



                # The trickiest case
                if isinstance(n.func, ast.Attribute):
                    if hasattr(n.func.value, "id"):
                        #print 'Call(hard)........',repr(n.func.value.id)

                        # l2 = someClass(); l2.someMethod()
                        # lhs_instance_vn = "l2"
                        lhs_instance_vn = n.func.value.id

                        # Case of "self.someFunc()" calls the lhs will be "self"
                        # so use the class within which this function lives
                        if lhs_instance_vn == "self":
                            method_name = n.func.attr
                            key = self.get_key_from_info(method_name, fti.class_name)
                            if self.__big_map.has_key(key):
                                outgoing_calls.append(key)

                        if lhs_instance_vn in fti.class_instance_varnames:
                            class_of_varname = fti.class_pairs[lhs_instance_vn]
                            # We now have the class whose method we are calling
                            # Look it up in the big map so we can link these

                            method_name = n.func.attr

                            if method_name in self.METHOD_BLACKLIST:
                                continue

                            if class_of_varname and method_name:
                                # make this a func that returns a key into the big map given some info about
                                # a function/class/method/etc
                                key = self.get_key_from_info(method_name, class_of_varname)

                                # TODO get this working instead of above, its more elegant......
                                #(key, _) = self.gen_unique_key(fti.fn, method_name, class_of_varname)
                                #print 'genned key......', key
                                if self.__big_map.has_key(key):
                                    outgoing_calls.append(key)



    def gen_module_name(self, python_filename):
        """ Given a filename return the module it constitutes
        """

        # Base dir is relevant because the directory structure determines the modulenames
        base_dir = self.__target_dir

        # Determine modulename based on file path and make it module-y
        subfn = python_filename[len(base_dir) :]
        subfn = subfn.replace(os.sep, ".")
        if subfn[0:1] == ".":
            subfn = subfn[1:]
        if subfn.endswith(".py"):
            subfn = subfn[:-3]
        module_name = subfn

        return module_name



    def gen_unique_key(self, module_name, funcname, class_name=None):
        """
        Generate a unique key to used for an fti in the big map
        Format is: module::(optional class)::function

        base_dir/lib/lib_one/token.py
            def foo():
        Becomes: lib.lib_one.token::foo
        
        base_dir/lib/lib_one/turtle.py
            class box:
                def chomp():
        Becomes: lib.lib_one.turtle::box::chomp

        """
        unique_name = None

        if class_name:
            unique_name = module_name + "::" + class_name + "::" + funcname
        elif not class_name:
            unique_name = module_name + "::" + funcname

        return (unique_name, funcname)


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

        if self.verbose:
            print "Processing %d / %d templates..." % (len(templatename_to_parse_tree.keys()), len(list(env.list_templates(".html"))))

        return templatename_to_parse_tree


    def get_unsafe_templateside_variables(self, template_dir = None):
        """
        Compile all templates into python. Parse that python to find spots that
        if there was a variable substituion with user controlled data, would be xss. 
        In jinja this generally means:
        1. {{foo | safe}}
        2. a {{foo}} inside a <script> block
        3. an html attribute={{foo}} case

        Collect all the templateside variable names for these to pass up
        into the sink() we create for render_template and templated and similar
        to lend accuracy to xss rules

        """
        # output is template name : list of unsafe variables that if filled with user-controlled input would be xss
        #ex: d = {'templates/foo.html' : ['a', 'variable_blah']}



        tn_to_ast = self.consume_dir_compile_templates(template_dir)
        tn_to_unsafe_vars = self.find_all_safe_filter(tn_to_ast)
        #tn_to_unsafe_vars.append(self.find_all_attribute_xss(tn_to_ast))
        #tn_to_unsafe_vars.append(self.find_all_script_block_xss(tn_to_ast))
        print 'here it is.......'
        print repr(tn_to_unsafe_vars)
        return tn_to_unsafe_vars


    def get_template_dir(self):
        """ return the directory containing jinja2 templates
            ex:  web-p2 is web-p2/partners/templates
        """
        template_dirs = set()
        for root, subdir, files in os.walk(self.__target_dir):
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



    def find_all_safe_filter(self, tn_to_ast):
        """ Make a few passes over the template asts, first to get the Call()s to |safe, then to get the variables 
        that |safe is applied to. We return a templatename and a list of unsafe variables that flow into the
        portion of the template marked "|safe".
        
        The pattern looks like t_1 = environgment.filters['safe']
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
                    3. python ast: value=Subscript(value=Attribute(
                        value=Name(id='environment', ctx=Load()), attr='filters', ctx=Load()), 
                        slice=Index(value=Str(s='safe')), ctx=Load()))
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
    import argparse
    parser = argparse.ArgumentParser(description="Security-focused program analysis for python.")
    parser.add_argument('dir', metavar='dir', help='the directory of code to scan')
    parser.add_argument("-f", "--full", action="store_true", default=False, help="return full (unconfirmed) results")
    parser.add_argument("-v", "--verbose", action="store_true", default=False, help="increase verbosity")
    parser.add_argument("-vv", "--veryverbose", action="store_true", default=False, help="really really verbose")
    parser.add_argument("-t", "--targets", action="store_true", default=False, help="target function name")
    args = parser.parse_args()

    target_dir = args.dir

    engine = Engine()
    engine.ingest(target_dir)
    engine.process_funcs()
    engine.main_analysis()
    for i in engine.issues_found:
        print i

if __name__ == "__main__":
    main()





"""
            rough notes from whiteboard + pacing
            main() -> three() -> four() -> five()
            five() contains mysql_query()
            near/far analysis, near = do I contain a request.whatever?
            far = do I:
                1. have people that call me
                2. take arguments
                3. have assignments/etc that allow any of my arguments to pass to my sink, which could actually just be a call to a function we know has throughtaint (ttaint)
                4. (future) not have any sanitization functions blocking these paths

"""

