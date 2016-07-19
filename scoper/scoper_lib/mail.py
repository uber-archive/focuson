import datetime as dt

from sendgrid import Mail, SendGridClient
from sendgrid.exceptions import SendGridClientError

import config
from templates import render_template


def send_email(routes_to_report):
    """Send email using sendgrid."""
    number_of_routes = len(routes_to_report)
    if number_of_routes == 0:
        return False

    formatted_date = dt.datetime.utcnow().strftime("%A, %b %d")
    rich_email_body = render_template(
        "email.html",
        routes=routes_to_report,
        date=formatted_date
    )

    sg = SendGridClient(config.SG_USERNAME, config.SG_PASSWORD, raise_errors=True)

    formatted_time = dt.datetime.utcnow().strftime("%F %T")
    subject = '({}): {} routes'
    subject = subject.format(formatted_time, number_of_routes)

    try:
        message = Mail(
            to=config.TO_EMAIL,
            subject=subject,
            html=rich_email_body,
            from_email=config.FROM_EMAIL
        )

        status, msg = sg.send(message)
        return msg
    except SendGridClientError as e:
        print 'Failed to send email: ', e
        raise
