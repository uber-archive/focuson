def render_endorsement_landing(directed_referral_uuid):
    #collin_flawed_two = flask.request.args['foo']
    collin_one = request.args['foo']
    translations = "asd"
    bar = "baaaar"

    some_dict = {'foo' : collin_one,
            'bar' : bar
            }
    template_vars = {
        'join_data': collin_one,
        'translations': translations,
    }
    return render_template('endorsement.html', **template_vars)
