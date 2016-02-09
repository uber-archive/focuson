"""Inventory management views."""
from __future__ import absolute_import

from clay import app, stats
from flipr_python_uwsgi.flipr_python_uwsgi import get_flipr
from flask import g, jsonify, redirect, render_template, request, url_for

from inventory_management_client.errors import InadequateInventoryError

from partners.helpers import inventory as helper
from partners.helpers.base import extend_home_context
from clay_genghis.lib.utils import get_locale
from partners.helpers.inventory import (
    DriverNotFoundByEmailError,
    inventory_gatekeeper
)

from partners.lib.auth import roles
from partners.lib.auth.roles import (
    PARTNER,
    role_required
)
from partners.lib.genghis_helpers import gettext as _


@app.route('/inventory/', methods=['GET'])
@inventory_gatekeeper()
@stats.wrapper('web-p2.partners.inventory.main')
def get_inventory_management():  # TODO: We can remove this when we remove the V1 inventory UI
    """The main inventory management view."""
    message = request.args.get('message', '')
    context = extend_home_context({'message': message})
    return render_template('inventory/index.html', **context)


def _get_and_strip(form, key, default=''):
    return form.get(key, default).strip()


def _driver_not_found(e):
    message = _("inventory_management.invalid_email", email=e.email)
    return jsonify({"error": message}), 400
    # Semantically, a 404 would be nicer but it gets clobbered by the 404 handler


@app.route('/inventory/sku', methods=['GET'])
@inventory_gatekeeper()
@stats.wrapper('web-p2.partners.inventory.sku')
def get_skus():
    """Return all future SKUs."""
    skus = helper.get_future_skus()
    presented_skus = present_skus(skus)
    return jsonify(presented_skus)


def present_skus(skus):
    """Populate SKUs with tag data."""
    presented_skus = []

    for sku in skus:
        if sku.get('attributes'):
            sku_details = sku['attributes']['name']
        else:
            sku_details = sku['name']
        if sku.get('tags'):
            tag_string = ', '.join(sku['tags'])
            sku_details += ' (%s)' % tag_string
        elif sku.get('mealServiceUuid'):
            sku_details += ' (MS: %s)' % sku['mealServiceUuid'][:5]
        presented_skus.append({
            'sku_details': sku_details,
            'uuid': sku['uuid']
        })
    return {'skus': presented_skus}


@app.route('/inventory/move', methods=['POST'])
@inventory_gatekeeper()
@stats.wrapper('web-p2.partners.inventory.move')
def inventory_move():  # TODO: We can remove this when we remove the V1 inventory UI
    """Move inventory from one id to another."""
    request_form = request.form.to_dict()

    # Validate they are skus (and/or the right type of IDs?)
    product_uuid = _get_and_strip(request_form, 'product_uuid')
    from_driver_email = _get_and_strip(request_form, 'from_driver_email')
    to_driver_email = _get_and_strip(request_form, 'to_driver_email')

    try:
        quantity = int(request_form.get('quantity', '0').strip())
    except ValueError:
        message = _("inventory_management.invalid_quantity")
        return redirect(url_for('get_inventory_management', message=message))

    # Send request to rtapi
    try:
        # If we have a from driver email, then move from one to another,
        #   otherwise, move from the creator
        if from_driver_email:
            response = helper.inventory_move(
                product_uuid,
                from_driver_email,
                to_driver_email,
                quantity)
        else:
            response = helper.inventory_create(
                product_uuid,
                to_driver_email,
                quantity)

    except DriverNotFoundByEmailError as e:
        message = _("inventory_management.invalid_email", email=e.email)
        return redirect(url_for('get_inventory_management', message=message))
    except InadequateInventoryError:
        message = _("inventory_management.not_enough_items")
        return redirect(url_for('get_inventory_management', message=message))

    if 'error' in response:
        message = _("inventory_management.default_error")
        if response['error_code'] == 'NOT_ENOUGH_ITEMS':
            message = _("inventory_management.not_enough_items")
        elif response['error'] == 'INVALID_ITEM_ID':
            message = _("inventory_management.invalid_item_id")
        return redirect(url_for('get_inventory_management', message=message))

    parameters = {
        'product_uuid': product_uuid,
        'from_driver_email': from_driver_email,
        'to_driver_email': to_driver_email,
        'quantity': quantity
    }

    context = extend_home_context({
        'parameters': parameters,
        'response': response
    })
    return render_template('inventory/move.html', **context)


@app.route('/inventory/move_v2', methods=['POST'])
@inventory_gatekeeper()
@stats.wrapper('web-p2.partners.inventory.move-v2')
def inventory_move_v2():
    """Move inventory items from one driver to another."""
    from_driver_email = request.json['from_email']
    to_driver_email = request.json['to_email']
    inventory_uuids = request.json['inventory_uuids']

    try:
        helper.inventory_move_items(from_driver_email, to_driver_email, inventory_uuids)
    except DriverNotFoundByEmailError as e:
        return _driver_not_found(e)
    except InadequateInventoryError:
        return jsonify({
            "error": _("inventory_management.not_enough_items")
        })

    inventories = {
        from_driver_email: helper.inventory_query(from_driver_email),
        to_driver_email: helper.inventory_query(to_driver_email)
    }
    return jsonify(inventories)


@app.route('/inventory/query', methods=['GET'])
@role_required(PARTNER)
@stats.wrapper('web-p2.partners.inventory.query')
def inventory_query():
    """Return a partner's inventory."""
    email = request.args['email']

    if not roles.user_can_update_inventory(g.user) and not email == g.user.email:
        return jsonify({
            "error": _("inventory_management.query_other_users_inventory_forbidden")}
        ), 403
    try:
        return jsonify({email: helper.inventory_query(email)})
    except DriverNotFoundByEmailError as e:
        return _driver_not_found(e)


@app.route('/inventory/create', methods=['POST'])
@inventory_gatekeeper()
@stats.wrapper('web-p2.partners.inventory.create')
def inventory_create():
    """Add items a driver's inventory."""
    email = request.json['email']
    inventory_items = request.json['inventory_items']
    try:
        helper.inventory_create_items(email, inventory_items)
    except DriverNotFoundByEmailError as e:
        return _driver_not_found(e)
    return jsonify({email: helper.inventory_query(email)}), 201


@app.route('/inventory/remove', methods=['POST'])
@inventory_gatekeeper()
@stats.wrapper('web-p2.partners.inventory.remove')
def inventory_remove():
    """Add items a driver's inventory."""
    email = request.json['email']
    inventory_uuids = request.json['inventory_uuids']
    try:
        helper.inventory_remove_items(email, inventory_uuids)
        return jsonify({email: helper.inventory_query(email)})
    except DriverNotFoundByEmailError as e:
        return _driver_not_found(e)


@app.route('/inventory/v2/', methods=['GET'])
@app.route('/inventory/v2/inventory', methods=['GET'])
@app.route('/inventory/v2/edit-inventory', methods=['GET'])
@app.route('/inventory/v2/handoff', methods=['GET'])
@role_required(PARTNER)
@stats.wrapper('web-p2.partners.inventory.ui-v2.main')
def get_inventory_v2():
    """The inventory handoff view."""
    context = extend_home_context({})
    user_email = g.user.email
    can_edit = roles.user_can_update_inventory(g.user)
    locale = get_locale()
    return render_template(
        'inventory-v2/index.html',
        user_email=user_email,
        can_edit=can_edit,
        locale=locale,
        language=helper.get_genghis(),
        polling_interval=get_flipr().get('partners.inventory_polling_interval') or 10000,
        update_limit=get_flipr().get('partners.inventory_update_limit') or 600,
        **context
    )
