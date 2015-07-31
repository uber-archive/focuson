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

class Funcdef(Node):
    element_type = "function definition"
    name = String(nullable=False)
    #routable = Null()

class funcPrinter(ast.NodeVisitor):
    def visit_FunctionDef(self, node):
        print node.name
        self.generic_visit(node)


class funk:
    def __init__(self, ast_tree=None):
        self.tree = ast_tree
        self.decos = {}

class loginAnalysis:
    def __init__(self, base_file_dir=None, existing_ast=None):
        self.__base_file_dir = base_file_dir
        self.__existing_ast = existing_ast
        self.__paths_to_ast = {}
        self.__routable = []

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
                    self.__paths_to_ast[fullpath] = tree

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
        assert self.__paths_to_ast.keys() > 0
        #print 'building graph.........'
        #config = Config(NEO4J_URI, "neo4j", "foofoofoo")
        #g = Graph(config)
        #g.add_proxy("funcs", Funcdef)

        for path, tree in self.__paths_to_ast.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if hasattr(node, "decorator_list"):
                        if len(node.decorator_list) > 0:
                            for deco in node.decorator_list:
                                if self.is_routable(deco):
                                    print node.name
                                    self.__routable.append(node)

    # I envision a bundle of decos so I can say give me all routable funcs that also have csrf.excempt and begin with create_
    def fill_out_decorators(self):
        assert self.__routable > 0


        for f in self.__routable:
            decos = {}
            for n in ast.walk(f):
                pass




        # for each file parse as ast
        # store in graph db... but how... each function?

        #module -> (all funcs)->body of func)
    

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



if __name__ == "__main__":
    main()



