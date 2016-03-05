import collections
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
    resp = requests.get('https://search.uberinternal.com/elasticsearch/api-sjc1-2016.03.04/_search',
                        headers=headers,
                        cookies=cookies,
                        json=PAYLOAD)
    res = resp.json()["facets"]["terms"]["terms"]

    return collections.OrderedDict((
        (x["term"], x["count"]) for x in res
    ))
