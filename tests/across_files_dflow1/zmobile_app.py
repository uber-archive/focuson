import some_lib


def main_alt_2():
    arg_vuln = request.args.get('foo')
    arg_not_vuln = "asdf"
    second(arg_vuln, "ggg")

def second(arg1, arg2):
    now_tainted = arg1
    now_also_tainted = now_tainted

    third(now_also_tainted, "foo")

def third(arg1, arg2):
    now_tainted_3rd = arg1
    x = now_tainted_3rd
    var_y = x
    some_lib.far_out(var_y)
