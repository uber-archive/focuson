
@app.route('/first-layer-open-app', methods=['GET'])
def first_layer():
    android_deep_link_collin = request.args.get('android_deep_link')
    second(android_deep_link_collin, "asdf")


