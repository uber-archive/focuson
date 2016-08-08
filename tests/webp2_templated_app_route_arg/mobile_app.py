













@app.route('/open-app/<foo>/', methods=['GET'])
@templated('mobile_app/open-app.html')
def open_app(foo):
    #android_deep_link_collin 



    android_fallback_link = request.args.get(
        'android_fallback_link',
        config.get('byod.download_link.android'),
    )
    iphone_deep_link = request.args.get(
        'iphone_deep_link',
        config.get('deep_link.iphone'),
    )
    iphone_fallback_link = request.args.get(
        'iphone_fallback_link',
        config.get('byod.download_link.iphone'),
    )



    collin2 = foo
    return {
        'os_family': util.formatted_os_family(),
        'android_deep_link': collin2,
        'android_fallback_link': not_real,
        'iphone_deep_link': not_real2,
        'iphone_fallback_link': iphone_fallback_link,
    }


