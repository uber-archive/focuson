from collections import namedtuple

import git

from blame import (
    get_diff_from_commit,
    get_line_blame,
)
from db.db import db_session
from db.helpers import (
    find_route_by_route_name,
    save_new_route,
)
from parsing import (
    cmp_auth_types,
    RouteResult,
)


# via https://docs.python.org/3/library/collections.html#collections.namedtuple
ExtendedRouteResult = namedtuple(
    'ExtendedRouteResult',
    RouteResult._fields + ('diff', 'new', 'old_auth_type')
)


def check_routes_for_changes(routes_to_check, target_dir):
    routes_to_report = []

    repo = git.Repo(target_dir)
    for auth_type, routes in routes_to_check.items():
        for route in routes:
            # attempt to locate route in db
            db_route = find_route_by_route_name(route.route_name)

            # new routes
            if not db_route:
                db_route = save_new_route(auth_type, route.route, route.match, route.route_name)

                auth_commit = get_line_blame(repo, route.path, route.auth_lineno)
                diff = get_diff_from_commit(auth_commit)

                e_route = ExtendedRouteResult(
                    *route,
                    diff=diff,
                    new=True,
                    old_auth_type=None
                )
                routes_to_report.append(e_route)

            # changed routes
            elif auth_type != db_route.auth_type:
                # only alert if it's a more-bad route
                if cmp_auth_types(auth_type, db_route.auth_type) < 0:
                    auth_commit = get_line_blame(repo, route.path, route.auth_lineno)
                    diff = get_diff_from_commit(auth_commit)

                    e_route = ExtendedRouteResult(
                        *route,
                        diff=diff,
                        new=False,
                        old_auth_type=db_route.auth_type
                    )

                    routes_to_report.append(e_route)

                # update the route
                with db_session() as session:
                    db_route.auth_type = auth_type
                    session.add(db_route)

    return routes_to_report
