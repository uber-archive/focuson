@app.route('/instant_pay/gobank_activation_email/', methods=['POST'])
@role_required(DRIVER)
@stats.wrapper('web-p2.view.instant_pay.resend_activation_email')
def resend_activation_email():
    """Resend activation email for uber card."""
    try:
        _url = RESEND_ACTIVATION_EMAIL_URL.format(partner_uuid=g.user.uuid)
        _request = urllib2.Request(_url, headers={
            'X-AUTH-PARAMS-USER-UUID': g.user.uuid,
            'X-Uber-Source': application_identifier
        })
        _request.get_method = lambda: 'POST'
        return urllib2.urlopen(_request).read()
    except Exception as e:
        logger.warn('Resend email (partner "%s") error: %s' % (g.user.uuid, e))
        return jsonify({
            'status': 'error',
        }), httplib.BAD_REQUEST

