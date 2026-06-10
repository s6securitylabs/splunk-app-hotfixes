# encoding = utf-8

import os
import sys
import time
import datetime
import json
import traceback

# Maximum number of response body characters written to the log per request
MAX_LOGGED_BODY = 10000

def validate_input(helper, definition):
    pass

def _redact_headers(headers):
    # Show which auth header is being sent without leaking the key itself
    return {k: ("****" if k.lower() in ("x-apikey", "userapikey") else v) for k, v in headers.items()}

def _send_logged_request(helper, tag, url, payload, headers, verify_ssl):
    helper.log_info("{} API request: method=POST url={} payload={} headers={} verify={}".format(
        tag, url, json.dumps(payload), json.dumps(_redact_headers(headers)), verify_ssl))
    response = helper.send_http_request(
        url,
        method="POST",
        parameters=None,
        payload=payload,
        headers=headers,
        cookies=None,
        verify=verify_ssl,
        cert=None,
        timeout=None,
        use_proxy=True
    )
    body = response.text if response.text is not None else ""
    helper.log_info("{} API response: status={} bytes={} body={}{}".format(
        tag, response.status_code, len(body), body[:MAX_LOGGED_BODY],
        " ...[truncated]" if len(body) > MAX_LOGGED_BODY else ""))
    return response

def collect_events(helper, ew):

    opt_airlock_server_url = helper.get_global_setting('airlock_server_url')
    opt_airlock_rest_api_port = helper.get_global_setting('airlock_rest_api_port')
    opt_airlock_rest_api_key = helper.get_global_setting('airlock_rest_api_key')
    opt_airlock_tenant_id = helper.get_global_setting('airlock_tenant_id')
    opt_airlock_directory_id = helper.get_global_setting('airlock_directory_id')

    # Get SSL verification settings
    opt_disable_ssl = helper.get_global_setting('airlock_disable_ssl_verification')
    opt_ca_cert_path = helper.get_global_setting('airlock_custom_ca_cert_path')

    # Check disable SSL first, then path, else Default (True)
    verify_ssl = True
    if opt_disable_ssl and str(opt_disable_ssl).lower() in ('true', '1', 'yes', 'on'):
        verify_ssl = False
    elif opt_ca_cert_path and str(opt_ca_cert_path).strip():
        verify_ssl = str(opt_ca_cert_path).strip()

    local_airlock_directory_id = helper.get_arg("local_airlock_cloud_directoryid")
    local_airlock_tenantid = helper.get_arg("local_airlock_cloud_tenantid")

    helper.get_input_stanza()
    proxy_settings = helper.get_proxy()

    # Sanitize the URL
    if opt_airlock_server_url.startswith("https://"):
        opt_airlock_server_url = opt_airlock_server_url[len("https://"):]
    opt_airlock_server_url = opt_airlock_server_url.split("/")[0]

    # Set up the initial URL and handle specific domain conditions
    if "appenforcement.com" in opt_airlock_server_url:
        if opt_airlock_server_url.startswith("portal."):
            opt_airlock_server_url = opt_airlock_server_url[len("portal."):]
        endpoint = "/willard/v1/group"
        headers = {
                "UserApiKey": opt_airlock_rest_api_key,
                "directoryid": (local_airlock_directory_id if local_airlock_directory_id else opt_airlock_directory_id),
                "tenantID": (local_airlock_tenantid if local_airlock_tenantid else opt_airlock_tenant_id)
            }
    else:
        #On-prem/hosted
        endpoint = "/v1/group"
        headers = {
                "X-ApiKey": opt_airlock_rest_api_key
            }
    url = "https://" + opt_airlock_server_url + (":" + opt_airlock_rest_api_port if opt_airlock_rest_api_port else "") + endpoint

    try:
        response = _send_logged_request(helper, "airlock_policies", url, None, headers, verify_ssl)
        # check the response status before parsing, if the status is not successful, raise requests.HTTPError
        response.raise_for_status()
        r_json = response.json()
    except Exception:
        helper.log_error("airlock_policies: group list request to Airlock failed. Traceback: {}".format(traceback.format_exc()))
        exit()

    if 'response' not in r_json or 'groups' not in r_json['response']:
        helper.log_error("airlock_policies: expected response.groups not found in API reply. Keys were: {}".format(list(r_json.keys())))
        exit()

    helper.log_info("airlock_policies: {} groups returned".format(len(r_json['response']['groups'])))

    # Loop through each group ID and fetch policies
    written = 0
    for i in r_json['response']['groups']:
        groupid = i['groupid']

        # Define the policy URL based on whether it’s appenforcement.com
        if "appenforcement.com" in opt_airlock_server_url:
            endpoint = "/willard/v1/group/policies"
        else:
            endpoint = "/v1/group/policies"

        url = "https://" + opt_airlock_server_url + (":" + opt_airlock_rest_api_port if opt_airlock_rest_api_port else "") + endpoint

        try:
            response = _send_logged_request(helper, "airlock_policies", url, {"groupid": groupid}, headers, verify_ssl)
            response.raise_for_status()
            policy = response.json()
        except Exception:
            helper.log_error("airlock_policies: policy request for groupid={} failed. Traceback: {}".format(groupid, traceback.format_exc()))
            continue

        event = helper.new_event(
            source=helper.get_input_stanza_names(),
            index=helper.get_output_index(),
            sourcetype="airlock:policies",
            data=json.dumps(policy),
            unbroken=True,
            time=time.time()
        )
        ew.write_event(event)
        written += 1
    helper.log_info("airlock_policies: wrote {} policy events".format(written))
