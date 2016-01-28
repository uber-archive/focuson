

def someFunc(arg):
    a = arg + "something else"
    return a

def main():
    a = 2
    b = 4
    c = 42
    d = request.args('foo')
    e = someFunc(d)
    dangerousSink(e)


if __name__ == "__main__":
    main()
