import sys

"""
def func_one():
    a = flask.request.args.get("foo")
    b = 42
    d = "some d val"
    e = "some e val"
    modified_a = a + "_some_string"
    f = "some f val"
    eval(modified_a)

def sub_function(arg_a):
    foo = arg_a + "ggggg"
    return foo

def meep():
    print 'hi'
    return 42

def func_four():
    a = request.args.get("foo")
    a2 = a
    a3 = a2
    eval(a3)


def func_five():
    a = request.args.get("foo")
    b = 42
    eval(b)

def func_six():
    a = request.args.get("foo")
    b = 42
    c = a
    d = {"rargh" : "rargh value!!", "c key" : c, "b key" : b, "foo key" : 'foo value'}
    eval(d['c key'])
"""

def func_seven():
    a = request.args.get("foo")
    b = 42
    copy_of_a = a
    eval(copy_of_a)







if __name__ == "__main__":
    print 'hey'
