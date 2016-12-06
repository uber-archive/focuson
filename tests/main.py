import sys
sys.path.append("..")

import os
import unittest

from focuson import Engine 

class TestInOneFileDataflow(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

    def tearDown(self):
        self.engine = None

    def test_simple_inline(self):
        """
        Worlds simplist vuln:
        eval(request.args.get("foo"))
        """
        target_dir = os.getcwd() + os.sep + "simple_inline"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 1)
        self.assertEqual(self.engine.issues_found[0].cf.name, "main::func_seven")

    def test_simple_inline_dict(self):
        """
        eval({"a" : request.args.get("foo")})
        """
        target_dir = os.getcwd() + os.sep + "simple_inline_dict"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 1)
        self.assertEqual(self.engine.issues_found[0].cf.name, "main::func_seven")

    def test_simpleEval(self):
        """
        Test a very simple case, 
        a = DANGEROUS_SOURCE
        copy_of_a = a
        dangerous_sink(copy_of_a)
        """
        target_dir = os.getcwd() + os.sep + "simple_eval"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 1)
        self.assertEqual(self.engine.issues_found[0].cf.name, "main::func_seven")

    def test_flowing_through_4_functions(self):
        #Issue through ['first_layer', 'second', 'third', 'fourth'] to mobile_app::fourth
        target_dir = os.getcwd() + os.sep + "simple_4_hop"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 1)
        self.assertEqual(self.engine.issues_found[0].cf.name, "mobile_app::fourth")
        self.assertEqual(self.engine.issues_found[0].call_chain, ['first_layer', 'second', 'third', 'fourth'])

    def test_kwargs(self):
        """
        The case where taint is propagated into a sink() via **kwargs
        """
        target_dir = os.getcwd() + os.sep + "simple_kwargs"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 1)
        self.assertEqual(self.engine.issues_found[0].cf.name, "kwargs::render_endorsement_landing")

    def test_kwargs_two(self):
        """
        The case where taint is propagated into a sink() via a=varname kwargs style
        """
        target_dir = os.getcwd() + os.sep + "kwargs_two"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 1)
        self.assertEqual(self.engine.issues_found[0].cf.name, "main::partner_app")



    def test_app_route_args(self):
        """
        In flask a decorator like app.route(...) can designate arguments. ex:

        @app.route('/open-app/<foo>/', methods=['GET'])
        def open_app(foo):
            print foo
 
        we need to consider these arguments equivalent to 
        foo = request.args.get("asdf") because they are. 
        """
        target_dir = os.getcwd() + os.sep + "app_route_tainting"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 1)
        self.assertEqual(self.engine.issues_found[0].cf.name, "main::open_app")

    
    def test_hasjob_keyword_arguments(self):
        """
         There should be two issues, one for
         the inline request.args: render_template(tmpl, order_by=request.args.get('order_by'),
         and one for all the user-controlled vars flowing into that same render_template()
         ex:
         
         limit = request.args.get('limit', 100)
         ...
         render_template(tmpl, order_by=request.args.get('order_by'), 
         posts=posts, start=start, limit=limit, count=count, min=min, max=max, sortarchive=sortarchive)
 
        """
        target_dir = os.getcwd() + os.sep + "hasjob1"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertEqual(self.engine.issues_found[0].cf.name, "hasjob::sortarchive")
        self.assertEqual(self.engine.issues_found[0].source_varnames, ['order_by'])
        self.assertEqual(self.engine.issues_found[1].source_varnames, ['posts', 'start', 'limit'])



    def test_double_render_template_evaluation(self):
        """
        Since we were comparing only rule/func_name both flask.render_template and 
        *.render_template were running giving us 2 bugs for each instance of render template.... 
        """
        target_dir = os.getcwd() + os.sep + "hasjob1"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 2)

    
    def test_various_sources_ensure_marked(self):
        """
        Test that the different variations of request.args all work
        """
        import ast
        one = "summary_days = request.args.get('summary_days', type=int)"
        one_tree = ast.parse(one)
        subtree = one_tree.body[0].value
        self.assertTrue(self.engine.dangerous_source_assignment(subtree))

        two = "request.args.get('summary_days')"
        two_tree = ast.parse(two)
        subtree = two_tree.body[0].value
        self.assertTrue(self.engine.dangerous_source_assignment(subtree))

        three = "foo = request.args['blah']"
        three_tree = ast.parse(three)
        subtree = three_tree.body[0].value
        self.assertTrue(self.engine.dangerous_source_assignment(subtree))


    def test_urlopen_sink(self):
        """
        test that sink of dangerous urllib.urlopen(XXX) construct works
        """
        target_dir = os.getcwd() + os.sep + "urlopen"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 1)
        self.assertEqual(self.engine.issues_found[0].cf.name, "foo::resend_activation_email")
        self.assertEqual(self.engine.issues_found[0].source_varnames, ["a"])
 

class TestAcrossFilesDataflow(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

    def tearDown(self):
        self.engine = None

    def test_2file(self):
        """
        Pretty simple taint test across 2 files, no classes/objects
        """
        target_dir = os.getcwd() + os.sep + "across_files_dflow1"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 1)
        self.assertEqual(self.engine.issues_found[0].cf.name, "some_lib::far_out")
        self.assertEqual(self.engine.issues_found[0].source_varnames, ["arg_vuln"])
        self.assertEqual(self.engine.issues_found[0].call_chain, ['main_alt_2', 'second', 'third', 'far_out'])
 
    def test3_file_and_classes(self):
        """
        A more complex test across 3 files and a few classes

        This is a pretty robust test, see code for full details.
        """
        target_dir = os.getcwd() + os.sep + "across_files_dflow2"
        self.engine.ingest(target_dir)
        self.engine.process_funcs()
        self.engine.main_analysis()
        self.assertTrue(len(self.engine.issues_found) == 1)

        self.assertEqual(self.engine.issues_found[0].cf.name, "lib.lib_two.l2_class_filename::Dog::bark_two")
        self.assertEqual(self.engine.issues_found[0].source_varnames, ['some_arg_vuln'])
        self.assertEqual(self.engine.issues_found[0].call_chain, ['main_alt_2', 'second', 'chomp', 'chomp_two', 'bark_one', 'bark_two'])

 



if __name__ == '__main__':
    unittest.main()
