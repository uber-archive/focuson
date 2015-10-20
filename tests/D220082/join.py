"""Join view."""
from __future__ import absolute_import


from clay import app, config, stats
from flask import (
    g,
    redirect,
    request,
    url_for,
)

from partner_signup_service_client.service.ttypes import InvalidInputError, ServiceFailure
from tchannel.errors import DeclinedError
from upi.exceptions import UberAPIError
from voluptuous import MultipleInvalid

from partners.helpers import ga_utils
from partners.helpers import signup_helper
from partners.helpers.base import (
    extend_signup_context,
    templated,
)
from partners.lib.exception_logger import log_failed_signup
from partners.lib.genghis_helpers import gettext as _
from partners.lib.validate import util
from partners.lib.validate.util import (
    get_schema_and_values
)
from partners.models.city import City
from partners.models.user_tag import UserTag


NOT_APPLICABLE = 'n/a'

logger = config.get_logger('p2')


@app.route('/join/', methods=['GET'])
@templated('join/index.html')
def signup_join():
    """Handle partner signup on /join endpoint."""
    stats.count('web-p2.join.visit', 1)

    if g.user and g.user.role != 'client':
        return redirect(url_for('get_user_dashboard'), 302)

    # google analytics params tracking
    ga_utils.set_ga_params_in_session()

    invite_code = request.args.get('invite_code') or request.cookies.get('referral_code')
    referral_info = None
    referrals_template = False
    if invite_code:
        referral_info = signup_helper.get_referral_info_from_code(invite_code)
        if referral_info:
            referrals_template = True
            stats.count('web-p2.join.visit.referral', 1)

    join_data = signup_helper.get_join_template_data(
        user=g.user, referrals_template=referrals_template, invite_code=invite_code
    )

    return extend_signup_context({
        'flow_type': request.args.get('flow_type'),
        'invite_code': invite_code,
        'referral_info': referral_info,
        'signup_consent_key': signup_helper.get_signup_consent_key_from_request(),
        'verified_city_name': _get_city_name_from_request(),
        'referrals_template': referrals_template,
        'join_data': join_data,
    })

