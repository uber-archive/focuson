#!/usr/bin/env python


STR_AUTH_MAP = {
    "token": "token_wall",
    "token_allow_banned": "token_wall_allow_banned",
    "admin": "admin_wall",
    "admin_not_restricted": "admin_not_restricted_wall",
    "super_admin": "super_admin_wall",
    "no_auth_required": "insecure_wall",
    "GAPING_SECURITY_HOLE": "insecure_wall",
    "admin_and_dispatch_tag": "admin_and_dispatch_tag_wall",
    "gift_card": "gift_card_wall",
    "twilio_wall": "twilio_wall",
    "trip_rate_wall": "trip_rate_wall",
}

BADNESS_ORDER = [
    'insecure_wall',
    'token_wall_allow_banned',
    'token_wall',
    'token_or_service',
    # This is less bad than token because
    # it tries to do AuthZ checks itself.
    'user_wall',
    'supply_growth_tag_wall',
    '_zendesk_user_wall',
    'admin_insecure_wall',
    'admin_and_dispatch_tag_wall',
    'service_wall',
    'admin_or_service',
    'admin_wall',
    'admin_not_restricted_or_service',
    'admin_not_restricted_wall',
    'super_admin_wall',
    'api_global_cert_issuer_wall',
]

# Access to routes with these auth types is restricted
SAFE_AUTH_TYPES = {
    'admin_and_dispatch_tag_wall',
    'service_wall',
    'admin_or_service',
    'admin_wall',
    'admin_not_restricted_or_service',
    'admin_not_restricted_wall',
    'super_admin_wall',
    'api_global_cert_issuer_wall',
    '_zendesk_user_wall',
    'admin_insecure_wall',
    'supply_growth_tag_wall',
}
