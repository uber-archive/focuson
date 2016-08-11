@app.route('/partner-app/', methods=['GET'])
def partner_app():
    """Route to enable partners to download apps without logging in."""
    a_var = request.args.get('aaa')
    links = config.get('partner-app-urls')
    if is_mobile_device():
        return render_template(
            'referrals/partner-app.html',
            urls=links
        )
    else:
        #return render_template( 'referrals/partner-app-desktop.html', translations=_get_partner_app_translations())
        return render_template( 'referrals/partner-app-desktop.html', translations=a_var)
