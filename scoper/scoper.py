#!/usr/bin/env python
from __future__ import print_function

import argparse
import datetime as dt
import sys
import os
import os.path

from scoper_lib.auth_types import SAFE_AUTH_TYPES
from scoper_lib.check_changes import check_routes_for_changes
from scoper_lib.es_tools import (
    request_recent_origins,
    requests_with_users,
    route_has_requests,
)
from scoper_lib.mail import send_email
from scoper_lib.parsing import (
    get_all_routes,
    get_routes_by_auth_type,
)
from scoper_lib.task_template import TASK_TEMPLATE


def print_routes(routes):
    for auth_type, auth_type_routes in routes.items():
        print("\n\nAuth Type: %s\n---------" % auth_type)
        for route in auth_type_routes:
            print(" - ".join((route.route, route.match, route.route_name)))


def usage():
    args = argparse.ArgumentParser(
        description="Scans a cloned API repository for security-relevant routes"
    )
    args.add_argument("api_root", help="Location of the API repo")
    args.add_argument("--route", help="Generate an issue template for a route", default=None)
    args.add_argument("--show-safe", help="Include 'safe' auth types", default=False, action="store_true")
    args.add_argument("--only-stale", help="Only show views that haven't been requested recently",
                      default=False, action="store_true")

    parsed = args.parse_args()

    target_dir = parsed.api_root
    template_dir = os.path.join(target_dir, "Uber", "uber", "templates")
    if not os.path.isdir(target_dir) or not os.path.isdir(template_dir):
        print("%s needs to be a directory under which "
              "there will be a Uber/uber/templates/ directory" % target_dir,
              file=sys.stderr)
        sys.exit(1)
    return parsed


def main():
    parsed_args = usage()
    target_dir = parsed_args.api_root
    route_name = parsed_args.route

    target_dir = os.path.abspath(target_dir)
    all_routes = list(get_all_routes(target_dir))
    print("%d routes." % len(all_routes), file=sys.stderr)

    if route_name:
        route = filter(lambda x: x.route == route_name, all_routes)[0]
        date = dt.datetime.fromtimestamp(route.route_commit.committed_date)
        origins = request_recent_origins(route.route_name)
        request_users = requests_with_users(route.route_name)
        origins_str = ""
        for name, num in origins.iteritems():
            origins_str += "* %s: %s\n" % (name, num)
        view_name = route.route.split(".")[-1]
        task_rendered = TASK_TEMPLATE.format(
            route=route,
            commit=route.route_commit,
            request_origins=origins_str or "* None!\n",
            date=date,
            rel_path=os.path.relpath(route.path, target_dir),
            view_name=view_name,
            **request_users
        )
        print(task_rendered)
    else:
        routes_by_auth_type = get_routes_by_auth_type(all_routes)
        routes_to_check = {}
        for auth_type, routes in routes_by_auth_type.items():
            if not parsed_args.show_safe and auth_type in SAFE_AUTH_TYPES:
                continue
            if parsed_args.only_stale:
                routes = filter(lambda x: not route_has_requests(x.route_name), routes)
            if not routes:
                continue

            routes_to_check[auth_type] = routes

        print_routes(routes_to_check)
        routes_to_report = check_routes_for_changes(routes_to_check, target_dir)
        send_email(routes_to_report)


if __name__ == "__main__":
    main()
