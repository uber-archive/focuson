@app.route('/endorsement/<directed_referral_uuid>', methods=['GET'])
def render_endorsement_landing(directed_referral_uuid):
    """Render endorsement form."""
    directed_referral_info = get_directed_referral_info(directed_referral_uuid)

    collin_foo = request.args.get("foo")
    template_vars = {
        'endorsement': None,
        'join_data': get_join_data('code'),
        'num_referral_inputs': 3,
        'show_recommendations': False,
        'show_endorsement_inline': False,
        'translations': translations,
        'iphone_deep_link' : collin_foo,
    }

    return render_template(
        'referrals/endorsement.html', **template_vars
    )
