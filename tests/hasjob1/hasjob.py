@app.route('/archive')
def sortarchive(blah):
    current_order_by = request.args.get('order_by')
    reverse = request.args.get('reverse')

    order_by = {
        'date': JobPost.datetime,
        'headline': JobPost.headline,
        'company': JobPost.company_name,
        'location': JobPost.location,
        }.get(request.args.get('order_by'))
    reverse = request.args.get('reverse')
    start = request.args.get('start', 0)
    limit = request.args.get('limit', 100)
    if request.is_xhr:
        tmpl = 'archive_inner.html'
    else:
        tmpl = 'archive.html'
    return render_template(tmpl, order_by=request.args.get('order_by'), posts=posts, start=start, limit=limit, count=count, min=min, max=max, sortarchive=sortarchive)
