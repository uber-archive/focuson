import collections
import datetime as dt
import os

import requests


def request_recent_origins(route_name):

    cookies = {
        'auth-openid': os.environ["SEARCH_OPENID"],
    }

    headers = {
        'Host': 'search.uberinternal.com',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:44.0) Gecko/20100101 Firefox/44.0',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=utf-8',
    }

    PAYLOAD={
        "facets": {
            "terms": {
                "facet_filter": {
                    "fquery": {
                        "query": {
                            "filtered": {
                                "filter": {
                                    "bool": {
                                        "must": [
                                            {
                                                "range": {
                                                    "@timestamp": {
                                                        "to": "now",
                                                        "from": "now-30d"
                                                    }
                                                }
                                            },
                                            {
                                                "terms": {
                                                    "tag": [
                                                        "api_request"
                                                    ]
                                                }
                                            },
                                            {
                                                "terms": {
                                                    "msg_.route_name": [
                                                        route_name
                                                    ]
                                                }
                                            }
                                        ]
                                    }
                                },
                                "query": {
                                    "bool": {
                                        "should": [
                                            {
                                                "query_string": {
                                                    "query": "*"
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    }
                },
                "terms": {
                    "exclude": [],
                    "field": "msg_.req_headers.X-Uber-Source",
                    "order": "count",
                    "size": 100
                }
            }
        },
        "size": 0
    }

    counted = collections.Counter()

    # With some fudge
    start_day = dt.datetime.utcnow() - dt.timedelta(hours=1)
    # API logs are sharded by day, make sure we get as many as we can
    for i in xrange(30):
        datestamp = (start_day - dt.timedelta(days=i)).strftime("%Y.%m.%d")
        resp = requests.get('https://search.uberinternal.com/elasticsearch/api-sjc1-%s/_search' % datestamp,
                            headers=headers,
                            cookies=cookies,
                            json=PAYLOAD)
        # Guess we don't actually have 30 days worth of logs to look at?
        if resp.status_code == 404:
            break
        res = resp.json()["facets"]["terms"]["terms"]

        counted.update(dict((x["term"], x["count"]) for x in res))

    return collections.OrderedDict(counted.most_common(100))
