






@app.route('/open-app/<foo>/', methods=['GET'])
def open_app(foo):
    # foo comes in via the app.route above
    copy_of_foo = foo
    eval(copy_of_foo)
