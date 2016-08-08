import sys
sys.path.append("..")

import os
import unittest
#import mock

from vision import Engine 

class TestInOneFileDataflow(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()

    def tearDown(self):
        self.engine = None

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




class TestAAAStringMethods(unittest.TestCase):

    def test_upper(self):
        self.assertEqual('foo'.upper(), 'FOO')

    def test_isupper(self):
        self.assertTrue('FOO'.isupper())
        self.assertFalse('Foo'.isupper())

    def test_split(self):
        s = 'hello world'
        self.assertEqual(s.split(), ['hello', 'world'])
        # check that s.split fails when the separator is not a string
        with self.assertRaises(TypeError):
            s.split(2)


if __name__ == '__main__':
    unittest.main()
