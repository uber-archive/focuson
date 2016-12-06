


== Overview

Focusin is a tool to find security bugs in python web applications. 

You run it and it outputs a list of potential security flaws to investigate. 

It uses dataflow analysis to model security flaws like xss, sqli, ssrf
as instances of a source (user input) flowing to a sink (dangerous function).

It has been used at Uber to surface security flaws in our python applications.
It currently supports  python + flask web applications but rules can be written
to expand that scope. 

Focusin is best thought of as a dataflow framework for python upon which
rules can be written. While you can run focusin directly you should expect
to write custom rules for your codebase to find the types of security
flaws you would expect to lurk within. 



== Background

Focusin is a path-insensitive, inter-functional dataflow analysis.

Path-insensitive = ignores the control flow (if/then/else/etc)
inter-functional = "tracks" variables across functions, not just within
dataflow analysis = "follows" variables through assignments, function calls,etc

Focuson works by parsing the program into an abstract syntax tree, constructing
call and dataflow graphs then traversing them. This all ultimately rests on being
able to predict ahead of time how the program runs, which we know is
undecidable so focuson, and any program analysis tool, is best considered a
collection of approximations to mine insight into how the program will execute. 

The expectation is focusin will show you areas a security engineer should
investigate more deeply with a good signal to noise ration

Focusin runs quickly, in testing taking ~15 sec for 100kb of python.

== Installation

Usage
1. source venv/bin/activate
2. python focusin.py <dir containting source code>


Changes
Focusin is customized for uber, to make it useful you will need to identify
the set of relevant sinks for your codebase and add them in. This should be
around line xxx

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
