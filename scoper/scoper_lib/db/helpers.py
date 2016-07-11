from db import with_session
from models import Route


@with_session
def save_new_route(session, auth_type, route_view_method, route, route_name):
    new_route = Route(
        auth_type=auth_type,
        route_view_method=route_view_method,
        route=route,
        route_name=route_name,
    )
    session.add(new_route)


@with_session
def find_route_by_route_name(session, route_name):
    return session.query(Route).filter_by(route_name=route_name).first()
