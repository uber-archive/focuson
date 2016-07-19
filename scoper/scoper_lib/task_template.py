TASK_TEMPLATE = """
[API] Incorrect AuthZ in {route.match}

Route details
-------------

* Route Name: {route.route_name}
* View: {rel_path}:{view_name}
* URL Pattern: {route.match}
* Auth Type: {route.auth_type}
* Created By: {commit.author}
* Created On: {date}

Summary
-------

**SUMMARY HERE**

Remediation
-------

**REMEDIATION HERE**

Example request
---------------

```
**EXAMPLE REQUEST HERE**
```

This route's request origins in the last 30 days
------------------------------------------------

{request_origins}
Note that some of the "public" requests may be me testing.

How many requests included tokens?
----------------------------------

* With a token: {with_user}
* Without a token: {without_user}

If any legitimate requests included tokens it is //not// safe
to switch to service auth, even if they sent a valid `X-Uber-Source`.
Including a valid token will always cause service auth to fail.
"""
