from __future__ import absolute_import

from lib.lib_two.l2_class_filename import Dog


class Turtle(object):
    def __init__(self, turtlename):
        self.name = turtlename

    def chomp(self, user_arg, url_arg, arg_3):
        chomp_now_tainted = arg_3
        self.chomp_two(chomp_now_tainted)
        
    def chomp_two(self, arg_1):
        self._blah = "blah"
        twenty_two = arg1

        chomp_two_now_tainted = arg_1
        denny_dog = Dog("asdf")
        denny_dog.bark_one("a", "b", chomp_two_now_tainted)
        return now_tainted




