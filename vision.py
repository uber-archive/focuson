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









"""
Rule families

1. Ast rules. Simple as they operate upon the AST
2. CFG rules. Don't know of any but they might exist, maybe around toctou or race conditions on files?
3. Dataflow rules. xss/sqli/etc
4. Human - blacklist of people who write bugs, interns, new people etc
5. Experimential - codebase analysis, person x commits to this area a bunch but this is their first commit to area y.

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
        # filename : code bundle
        # codebundle = { full path, list of functions, git history? } 
        self.__fn_to_cb = {}

    def injest_dir(self, rootdir):
        if not os.path.isdir(rootdir):
            raise Exception("directory %s passed in is not a dir" % rootdir)


        # walk the dirs/files
        for root, subdir, files in os.walk(rootdir):
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
    la.get_all_routable_funcs()



if __name__ == "__main__":
    main()



