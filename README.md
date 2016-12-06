


== Overview

Focuson is a tool to find security bugs in python web applications. 
Primarily flask + jinja web applications and primarily XSS. It was written
as an experiment in response to the Uber Product Security team manually finding
many XSS bugs in our codebase and wanting a way to scalably find them. 

It uses dataflow analysis to model security flaws like xss, sqli, ssrf
as instances of a source (user input) flowing to a sink (dangerous function).

Focuson is best thought of as a dataflow framework for python upon which
rules can be written. While you can run focuson directly you should expect
to write custom rules for your codebase to find the types of security
flaws you would expect to lurk within. 

Uber now uses focuson to automatically to surface probable security issues
to the security team or, given high confidence, back to the engineer that wrote
the issue. 



== Background

Focuson is a path-insensitive, inter-functional dataflow analysis.

Path-insensitive = ignores the control flow (if/then/else/etc)
inter-functional = "tracks" variables across functions, not just within
dataflow analysis = "follows" variables through assignments, function calls,etc

Focuson works by parsing the program into an abstract syntax tree, constructing
call and dataflow graphs then traversing them. This all ultimately rests on being
able to predict ahead of time how the program runs, which we know is
undecidable so focuson, and any program analysis tool, is best considered a
collection of approximations to mine insight into how the program will execute. 

The expectation is focuson will show you areas a security engineer should
investigate more deeply with a good signal to noise ration

Focuson runs quickly, in testing taking ~15 sec for 100kb of python.
== Installation
foo bar baz

== Usage
1. source venv/bin/activate
2. python focuson.py <dir containting source code>



== Examples

Worlds simpliest RCE in python:
eval(request.args.get("foo"))

More complex
foo = request.args.get("foo")
eval(foo)

More complex
foo = request.args.get("foo")
bar = foo
eval(bar)

Yet more complex:

def func1(arg1):
    eval(arg1)
foo = request.args.get("foo")
bar = foo
func1(bar)

For more examples like this see the test directory



== How to make focuson useful
Focuson is customized for Uber's codebase.

To make it useful you will need to identify relevant set of sources and sinks 
for your codebase. Some of these are globally true and already built-in, 
like eval() as a sink for RCE.

If you dont use flask you will need to determine how to model what 
user-controlled input looks like for your codebase and add it as a source

You will need to do the same for sinks. 

== Improvements
Lots of additional good work to be done. 
- Adding additional sources and sinks
- Refactoring sink() idea to generalized rule()
- Make output less cryptic
- Add support for web frameworks beyond flask

== Inspiration
* https://github.com/facebook/pfff
* http://www.mlsec.org/joern/
* https://github.com/openstack/bandit
* http://simpsons.wikia.com/wiki/Focusyn


===================

It differs from existing tools like Bandit in that it is higher signal and more
customizable - the real key is that it uses dataflow analysis to attempt to
"follow" variables through the code. 


It has been used at Uber to surface security flaws in our python applications.
It currently supports  python + flask web applications but rules can be written
to expand that scope. 


