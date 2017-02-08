
import os


class Dog(object):

    def __init__(self, driver):
        self._driver = driver

    def bark_one(self, user_arg, url_arg, arg_3):
        bark_one_now_tainted = arg_3
        print 'I am lib two, class two, printing hello!'
        self.bark_two(bark_one_now_tainted)
        
    def bark_two(self, arg_1):
        foo = arg_1
        bar = foo
        baz = bar
        quux = baz
        spaceman = "blah"
        bowie = spaceman
        #bark_two_now_tainted = arg_1
        bark_two_now_tainted = quux

        # eval is a known dangerous sink to trigger on
        eval(bark_two_now_tainted)

        return now_tainted



