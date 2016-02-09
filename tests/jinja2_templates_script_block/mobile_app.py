"""Endpoints for opening the mobile app."""
from __future__ import absolute_import

import os
import re
import urllib

from clay import app, config, stats
from clay_assets import AssetHelper
from clay_genghis.lib import utils as genghis_utils
from flask import jsonify, redirect, render_template, request
from requests.exceptions import RequestException
from upi.exceptions import NotFound, UberAPIError

from partners.helpers import geolocation, populous
from partners.helpers.base import templated
from partners.lib import caesar_lib, events, flipr_client, util
from partners.lib.flipr_client import FliprServiceError
from partners.lib.genghis_helpers import gettext as _
from partners.models.driver import Driver
from partners.models import user_tag

DRIVE_NOW_INSTRUCTIONS_LOCALES = [
    'en',
    'es',
    'fr',
    'zh',
    'zh_CN'
]

manifest_path = os.path.abspath(config.get('clay-assets.manifest_path'))
assets = AssetHelper(manifest_path)


@app.route('/app', methods=['GET'])
@app.route('/driver-app', methods=['GET'])
def redirect_to_drive_now():
    """Legacy endpoint.

    We're redirecting traffic to /drive-now
    """
    return redirect(
        '/drive-now',
        code=302
    )


@app.route('/drive-now', methods=['GET'])
def drive_now():
    """Open the partner app or show instructions on how to get it."""
    stats.count('web-p2.drive-now', 1)

    partner_uuid = request.args.get('uuid')
    if partner_uuid:
        try:
            driver = Driver.get(partner_uuid)
            events.track_funnel_event(driver, 'drive_now', 'viewed')
        except NotFound as e:
            logger = config.get_logger('p2.partners.views.mobile_app')
            logger.warning({
                'exception': e.__class__.__name__,
                'msg': 'Invalid partner or driver UUID provided as query parameter',
                'uuid': partner_uuid,
            }, exc_info=True)

    template_name, template_vars = get_drive_now_template_name_and_vars(partner_uuid=partner_uuid)

    template_vars.update(get_genghis_and_asset_template_vars())

    if not template_name:
        return redirect(
            template_vars['redirect_url'],
            code=302,
        )

    mailto_space_char = '%20'
    template_vars['email_subject'] = mailto_space_char.join(
        _('drive-now.instructions.email_subject').split(' ')
    )
    template_vars['email_body'] = mailto_space_char.join(
        _('drive-now.instructions.email_body').split(' ')
    )

    template_vars = {'template_vars': template_vars}

    return render_template(template_name, **template_vars)


def _build_app_download_url():
    """Build the download URL for iOS."""
    app_download_url = ""
    domain = ".uber"
    if request.args.get('gx') == '1':
        domain = ".geixahba"

    try:
        app_download_url = urllib.unquote(flipr_client.get_flipr_property(
            config.get('mobile_app.flipr_property_key')
        )).replace(".uber", domain)

    except FliprServiceError:
        stats.count('web-p2.drive-now.get-flipr-property-error', 1)
        app_download_url = config.get('mobile_app.initial_url_template').format(
            domain=domain,
            plist_version=config.get('mobile_app.default_plist_version'),
        )

    return app_download_url


def get_drive_now_template_name_and_vars(partner_uuid=None):
    """Return template_name and template vars for /drive-now."""
    template_name = 'mobile_app/_drive_now.html'

    if not util.is_mobile_device():
        if (request.args.get('instructions') == '1'):
            template_vars = {
                'instructions': True,
                'locale': get_country_code_from_request(),
                'steps': _get_instruction_array('9', _get_instruction_map()),
            }
        else:
            template_vars = {
                'instructions': False,
                'locale': get_country_code_from_request(),
            }

    else:
        if util.is_ios_9_or_above():
            if (
                partner_uuid and
                user_tag.get_user_tag(partner_uuid, 'nob_signin') and
                request.args.get('web') != '1'
            ):
                template_name = None
                template_vars = {
                    'redirect_url': '/open-app',
                }
            else:
                template_vars = {
                    'app_download_url': _build_app_download_url(),
                    'popup_app_download_url': request.args.get('dl') != '0',
                    'instructions': True,
                    'steps': _get_instruction_array('9', _get_instruction_map()),
                }
        elif util.is_ios_user_agent():
            template_name = None
            template_vars = {
                'redirect_url': '/open-app',
            }
        elif util.is_android_user_agent():
            template_name = None
            template_vars = {
                'redirect_url': config.get('byod.download_link.android'),
            }
        else:
            template_vars = {
                'instructions': False,
                'locale': get_country_code_from_request(),
            }

    template_vars['is_mobile'] = util.is_mobile_device()
    template_vars['partner_uuid'] = partner_uuid
    template_vars['os_version'] = util.formatted_os_version()
    template_vars['device_model'] = util.formatted_device_model()

    return (template_name, template_vars)


def get_country_code_from_request():
    """Get locale with 'en' default."""
    logger = config.get_logger('p2.partners.views.mobile_app')
    country_code = geolocation.get_country_code_from_request()
    logger.info({'country_code': country_code})

    return country_code or 'US'


def get_genghis_and_asset_template_vars():
    """Get all template vars relating to genghis strings and assets."""
    return {
        'assets': {
            'phones': assets.url_for_asset('images/mobile_app/phones@1x.png'),
            'left_logo': assets.url_for_asset('images/mobile_app/left_logo@1x.png'),
            'middle_logo': assets.url_for_asset('images/mobile_app/middle_logo@1x.png'),
            'right_logo': assets.url_for_asset('images/mobile_app/right_logo@1x.png'),
        },
        'genghis_strings': {
            'header': _('drive-now.header'),
            'open_app': _('drive-now.open_app'),
            'get_link': _('drive-now.get_link'),
            'modal_button_text': _('partner-app.modal_button_text'),
            'app_availability': _('drive-now.app_availability'),
            'quick_tips': _('drive-now.quick_tips'),
            'first_tip': _('drive-now.first_tip'),
            'second_tip': _('drive-now.second_tip'),
            'third_tip': _('drive-now.third_tip'),
            'contact_support': _('drive-now.contact_support'),
            'mobile_number': _('drive-now.mobile_number'),
            'questions_contact_after_href': _('drive-now.questions_contact_after_href'),
            'questions_contact_before_href': _('drive-now.questions_contact_before_href'),
            'instructions': {
                'alert': {
                    'important': _('drive-now.instructions.alert.important'),
                    'text': _('drive-now.instructions.alert.text'),
                },
                'install': _('drive-now.instructions.install'),
                'install_subtext': _('drive-now.instructions.install.subtext'),
                'help': _('drive-now.instructions.help'),
                'email': _('drive-now.instructions.email'),
            },
        },
    }


def _get_instruction_map():
    """Get the instruction map."""
    step_images = _drive_now_images_steps(genghis_utils.get_locale())
    return {
        '9': [
            {
                'number': 2,
                'text': _('drive-now.instructions.settings'),
                'highlight': _('drive-now.instructions.settings.highlight'),
                'img_src': step_images.get('settings'),
            },
            {
                'number': 3,
                'text': _('drive-now.instructions.general'),
                'highlight': _('drive-now.instructions.general.highlight'),
                'img_src': step_images.get('general'),
            },
            {
                'number': 4,
                'text': _('drive-now.instructions.profile'),
                'highlight': _('drive-now.instructions.profile.highlight'),
                'img_src': step_images.get('profile'),
            },
            {
                'number': 5,
                'text': _('drive-now.instructions.uber'),
                'highlight': _('drive-now.instructions.uber.highlight'),
                'img_src': step_images.get('uber'),
            },
            {
                'number': 6,
                'text': _('drive-now.instructions.trust'),
                'highlight': _('drive-now.instructions.trust.highlight'),
                'img_src': step_images.get('trust'),
            },
            {
                'number': 7,
                'text': _('drive-now.instructions.steps.details.8'),
                'highlight': '',
                'img_src': step_images.get('open'),
            },
        ],
    }


def _get_instruction_array(correct_version, instruction_map, level=0):
    """Recursively maps an iOS version to an array of steps using a 2-depth dict tree."""
    correct_versions = correct_version.split('.')

    if level >= len(correct_versions):
        return instruction_map

    target_sub_version = int(correct_versions[level])

    versions = [int(version) for version in instruction_map.keys()]

    for version in versions:
        if version == target_sub_version:
            return _get_instruction_array(
                correct_version,
                level=level + 1,
                instruction_map=instruction_map[str(version)],
            )

    return []


@app.route('/open-app', methods=['GET'])
@templated('mobile_app/open-app.html')
def open_app():
    """Open the partner app if installed or fallback to store otherwise."""
    android_deep_link = request.args.get(
        'android_deep_link',
        config.get('deep_link.android'),
    )
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
    return {
        'os_family': util.formatted_os_family(),
        'android_deep_link': android_deep_link,
        'android_fallback_link': android_fallback_link,
        'iphone_deep_link': iphone_deep_link,
        'iphone_fallback_link': iphone_fallback_link,
    }


@app.route('/drive-now', methods=['POST'])
def drive_now_post():
    """Send sms with driver app link."""
    logger = config.get_logger('p2.partners.views.mobile_app')
    response = {
        'status': '',
        'message': '',
        'errors': {},
        'prompt': _('signup.dashboard.finished.byod.resend.short'),
    }

    def _strip_non_digit(string):
        return re.sub('\D', '', string)

    country_code = _strip_non_digit(request.form.get('country_code', ''))
    mobile = _strip_non_digit(request.form.get('mobile', ''))
    user = populous._get_user_by_mobile_and_country_code(mobile, country_code)
    if not user:
        response['errors']['NotFound'] = 'User not found for mobile number %s' % (
            request.form.get('country_code', '') + request.form.get('mobile', '')
        )
        response['status'] = 'Error'
        logger.exception({
            'msg': 'User not found',
            'country_code': country_code,
            'mobile': mobile,
        })
        return jsonify(response), 404

    text = '%s: %s?uuid=%s' % (_('partner_app_message_text'), request.url, user.uuid)
    status = 400

    try:
        logger.info({
            'mobile': mobile,
            'message': text,
        })

        sms_resp = caesar_lib.get_caesar_client().send_sms(
            text,
            to_user_uuid=user.uuid,
            priority='transactional'
        )

        response['message'] = 'Success'
        response['status'] = 'OK'
        status = sms_resp.status_code

        if status != 200:
            response['message'] = sms_resp.reason
            response['status'] = 'Error'
    except RequestException:
        response['errors']['Request Exception'] = 'Error occurred while completing your request'
        response['status'] = 'Error'
        logger.exception({
            'msg': 'Request exception while sending sms',
            'to_number': mobile
        })

    if status == 200:
        try:
            driver = Driver.get(user.uuid)
            events.track_funnel_event(driver, 'drive_now', 'completed')
        except NotFound as e:
            logger.warning({
                'exception': e.__class__.__name__,
                'msg': 'SMS number maps to valid user but they are not a driver or partner',
                'uuid': user.uuid,
            }, exc_info=True)

    return jsonify(response), status


def _update_user_attribute(partner, key, value):
    user_attributes = {key: value}
    try:
        partner.update(user_attributes)
    except UberAPIError as e:
        logger = config.get_logger('p2.partners.lib.exceptions')
        logger.error(
            'Error updating byod_app_downloaded user attribute : %s' % e
        )


def _drive_now_images_steps(browser_locale):
    """Return images paths for the right locale."""
    locale_for_images = browser_locale if browser_locale in DRIVE_NOW_INSTRUCTIONS_LOCALES else 'en'

    step_images = {
        'settings': 'images/mobile_app/drive_now/%s/settings@2x.png' % locale_for_images,
        'general': 'images/mobile_app/drive_now/%s/general@2x.png' % locale_for_images,
        'profile': 'images/mobile_app/drive_now/%s/profile@2x.png' % locale_for_images,
        'uber': 'images/mobile_app/drive_now/%s/uber@2x.png' % locale_for_images,
        'trust': 'images/mobile_app/drive_now/%s/trust@2x.png' % locale_for_images,
        'open': 'images/mobile_app/drive_now/%s/open@2x.png' % locale_for_images,
    }

    step_images = {key: assets.url_for_asset(step_images[key]) for key in step_images.keys()}

    return step_images
