@app.route('/instant_pay/gobank_activation_email/')
def resend_activation_email():
    a = request.args.get("a")
    copy_of_a = a
    second_copy_of_a = copy_of_a
    return urllib.urlopen(second_copy_of_a)

