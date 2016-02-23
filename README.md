Focusin - A python static analysis tool to help find security flaws

http://simpsons.wikia.com/wiki/Focusyn


Goal: Finding security flaws in software is hard work - the goal of focusin is to give you an educated selection of areas in a python codebase to start looking. For microservices or websites a security audit would naturally focus on a subset of areas:

```
1. All functions that can be hit from the internet. ex: have app.route() decorators 
2. All of those internet-routable functions that also have any user input. ex: have an assignment like ```foo = request.args.get("foo") ```
3. All of the set of functions that pass #1 and #2 that also have a call to a function that renders html. ex: ``` flask.render_template() ```

focusin lets you construct queries like the above to narrow down where you would want to look first.

Focusin takes inspiration from toosl like 
https://github.com/facebook/pfff
and
http://www.mlsec.org/joern/

Usage:
1. source venv/bin/activate
2. python vision.py ~/src/free-candy/freecandy

Supported targets
* Any python flask code
* Api code

Results:
A high confidence issue looks like: TAINTED var "iphone_fallback_link" to @templated in /Users/collin/src/web-p2/partners/views/mobile_app.py +358
An area to manually explore looks like:/Users/collin/src/web-p2/partners/views/dashboard.py +195 templated() vars: ['inputs', 'translations']
