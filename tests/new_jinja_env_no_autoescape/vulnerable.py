from jinja2 import Environment, PackageLoader


env = Environment(loader=PackageLoader('securityPlayground', 'templates'))
temp = env.get_template('simplexss.html')
temp.render(name='<h1>XSS</h1>')



# output: '<html>\n<body>\n<title>Hello from clay</title>\nblah\n<h1>Hello <h1>XSS</h1>!</h1>\n</body>\n</html>'
