Focusin is a tool to find security bugs in python web applications. 

It uses dataflow analysis to model security flaws like xss, sqli, ssrf
as instances of a source (user input) flowing to a sink (dangerous function).

It has been used at Uber to surface security flaws in our python applications.
It is most useful for python + flask web applications but rules can be written
to expand that scope. 

Background
Focusin helps the uber product security team figure out what areas to focus on
in a massive codebase. Many security issues (xss, sqli, rce) can be modelled 
as data flowing from a source (user-controlled input) to a sink (the dangerous
function that accepting user input). 

Focusin has found multiple real security flaws with this methodology at Uber.

The expectation is focusin will show you areas a security engineer should
investigate more deeply with a good signal to noise ratio but will rarely
be able to say with 100% certainty there is a security flaw. 

Installation

Usage
1. source venv/bin/activate
2. python vision.py <dir containting source code>


Changes
Focusin is customized for uber, to make it useful you will need to identify
the set of relevant sinks for your codebase and add them in. This should be
around line xxx

Future work
Good future work would be adding additional sources and sinks, make the parsing
of the AST more precise and write additional tests. 

Inspiration
* https://github.com/facebook/pfff
* http://www.mlsec.org/joern/
* https://github.com/openstack/bandit
* http://simpsons.wikia.com/wiki/Focusyn
