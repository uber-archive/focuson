@app.route('/endorsement/<directed_referral_uuid>', methods=['GET'])
def render_endorsement_landing(directed_referral_uuid):
    """Render endorsement form."""

    #collin_flawed_two = flask.request.args['foo']
    collin_flawed = request.args['foo']
    collin_one = request.args.get('foo')

    directed_referral_info = get_directed_referral_info(directed_referral_uuid)

    if not directed_referral_info:
        return abort(404)

    translations = get_endorsement_translations(
        directed_referral_info.inviterFirstName,
        directed_referral_info.formattedReferralInviteeAmount,
        directed_referral_info.referralInviteeAmount,
        include_sms=True
    )

    template_vars = {
        'join_data': get_join_data(directed_referral_info.referralCode),
        'translations': translations,
        'endorsement_data': {
            'showEndorsementInline': False,
            'showRecommendations': False,
            'endorsement': None,
        }
    }
    template_vars['endorsement_data'].update(
        _get_common_endorsement_variables(directed_referral_uuid)
    )

    #render_template('endorsement.html', rt_arg_1)

    #return render_template('endorsement.html', **template_vars)
    return render_template('endorsement.html', directed_referral_uuid)
