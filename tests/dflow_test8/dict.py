
@app.route('/join/upgrade/', methods=['GET'])
@templated('join/upgrade.html')
def polymorphism_lite():
    """Handle polymorphism partner signup on join/upgrade/."""
    if not g.user:
        return redirect(url_for('signup_join', **request.args), 302)

    if g.user and g.user.role != 'client':
        return redirect(url_for('get_user_dashboard'), 302)

    # google analytics params tracking
    ga_utils.set_ga_params_in_session()

    signup_consent_key = signup_helper.get_signup_consent_key_from_request()
    verified_city_name = _get_city_name_from_request()
    join_data = signup_helper.get_join_template_data(
        user=g.user, city_name=verified_city_name
    )

    if request.args.get('invite_code'):
        stats.count('web-p2.join_upgrade.get.referral.url_parameter', 1)
        invite_code = request.args.get('invite_code')
    elif request.cookies.get('referral_code'):
        stats.count('web-p2.join_upgrade.get.referral.cookie', 1)
        invite_code = request.cookies.get('referral_code')
    else:
        invite_code = None

    flow_type = request.args.get('flow_type')
    country_code = get_country_code_from_request()
    if not flow_type and country_code == 'US':
        flow_type = driver_status_flow_type.P2P

    return extend_signup_context({
        'flow_type': flow_type,
        'signup_consent_key': signup_consent_key,
        'verified_city_name': verified_city_name,
        'invite_code': invite_code,
        'join_data': join_data,
        'is_mobile_device': util.is_mobile_device()
    })

