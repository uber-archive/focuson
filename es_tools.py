import collections
import datetime as dt
import os

import requests


def get_base_terms_request(route_name):
    return {
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
                                }
                            }
                        }
                    }
                },
            }
        },
        "size": 0
    }


def get_base_agg_request(route_name):
    return {
      "query": {
        "filtered": {
          "query": {
            "bool": {
              "should": [
                {
                  "query_string": {
                    "query": "*",
                    "lowercase_expanded_terms": False
                  }
                }
              ]
            }
          },
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
          }
        }
      },
      "size": 0
    }


def fetch_across_indexes(payload, search_type=None):
    cookies = {
        'auth-openid': os.environ["SEARCH_OPENID"],
    }

    headers = {
        'Host': 'search.uberinternal.com',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:44.0) Gecko/20100101 Firefox/44.0',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=utf-8',
    }

    # With some fudge
    start_day = dt.datetime.utcnow() - dt.timedelta(hours=1)
    # API logs are indexed by day, make sure we get as many as we can
    for i in xrange(30):
        datestamp = (start_day - dt.timedelta(days=i)).strftime("%Y.%m.%d")
        url = 'https://search.uberinternal.com/elasticsearch/api-sjc1-%s/_search' % datestamp
        if search_type:
            url += "?search_type=%s" % search_type
        resp = requests.get(
                url,
                headers=headers,
                cookies=cookies,
                json=payload
        )
        # Guess we don't actually have 30 days worth of logs to look at?
        if resp.status_code == 404:
            if i == 0:
                raise Exception("No indexes exist?")
            break

        yield resp.json()


def request_recent_origins(route_name):

    services_payload = get_base_terms_request(route_name)
    services_payload["facets"]["terms"]["terms"] = {
        "exclude": [],
        "field": "msg_.req_headers.X-Uber-Source",
        "order": "count",
        "size": 100
    }

    counted = collections.Counter()
    for resp in fetch_across_indexes(services_payload):
        terms = resp["facets"]["terms"]["terms"]
        counted.update(dict((x["term"], x["count"]) for x in terms))

    return collections.OrderedDict(counted.most_common(100))


def requests_with_users(route_name):

    token_auth_payload = get_base_agg_request(route_name)
    token_auth_payload["aggs"] = {
        "with_user": {
            "filter": {
                "exists": {
                    "field": "msg_.remote_user_uuid"
                }
            }
        },
        "without_user": {
            "missing": {
                "field": "msg_.remote_user_uuid"
            }
        }
    }

    counter = collections.Counter()
    for resp in fetch_across_indexes(token_auth_payload, "count"):
        for k, v in resp["aggregations"].items():
            counter[k] += v["doc_count"]

    return counter
