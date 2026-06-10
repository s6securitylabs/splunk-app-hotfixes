
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

    # Determine verify_ssl: disable > path > default(True)
    verify_ssl = True
    if opt_disable_ssl and str(opt_disable_ssl).lower() in ('true', '1', 'yes', 'on'):
        verify_ssl = False
    elif opt_ca_cert_path and str(opt_ca_cert_path).strip():
        verify_ssl = str(opt_ca_cert_path).strip()

    opt_delete_existing_checkpoint = helper.get_arg('delete_existing_checkpoint')

    local_airlock_directory_id = helper.get_arg("local_airlock_cloud_directoryid")
    local_airlock_tenantid = helper.get_arg("local_airlock_cloud_tenantid")

    if opt_delete_existing_checkpoint is True:
        helper.delete_check_point("svrcheckpoint")
        helper.log_debug("Existing checkpoint deleted, now exiting. Disable the Delete Existing Checkpoint option to index logs")
        exit()

    helper.get_input_stanza()
    proxy_settings = helper.get_proxy()

    # get checkpoint
    svrcheckpoint = helper.get_check_point("svrcheckpoint")

    # Sanitize the URL
    if opt_airlock_server_url.startswith("https://"):
        opt_airlock_server_url = opt_airlock_server_url[len("https://"):]
    opt_airlock_server_url = opt_airlock_server_url.split("/")[0]

    # Check if the FQDN contains "appenforcement.com" and modify the URL if needed
    if "appenforcement.com" in opt_airlock_server_url:
        if opt_airlock_server_url.startswith("portal."):
            opt_airlock_server_url = opt_airlock_server_url[len("portal."):]
        # NOTE: doubled trailing 's' is carried over from the vendor 6.0.0 release.
        # The request URL is logged below - if cloud pulls return 404, this path is the prime suspect.
        endpoint = "/willard/v1/logging/svractivitiess"
        headers = {
                "UserApiKey": opt_airlock_rest_api_key,
                "directoryid": (local_airlock_directory_id if local_airlock_directory_id else opt_airlock_directory_id),
                "tenantID": (local_airlock_tenantid if local_airlock_tenantid else opt_airlock_tenant_id)
            }
    else:
        #On-prem/hosted
        endpoint = "/v1/logging/svractivities"
        headers = {
                "X-ApiKey": opt_airlock_rest_api_key
            }

    url = "https://" + opt_airlock_server_url + (":" + opt_airlock_rest_api_port if opt_airlock_rest_api_port else "") + endpoint

    helper.log_info("airlock_server_activities: checkpoint value in Splunk is: {}".format(svrcheckpoint))

    if svrcheckpoint is None:
        helper.log_info("airlock_server_activities: no historical checkpoint found, obtaining restart checkpoint from Airlock")

        try:
            response = _send_logged_request(helper, "airlock_server_activities", url, None, headers, verify_ssl)
            response.raise_for_status()
            r_json = response.json()
        except Exception:
            helper.log_error("airlock_server_activities: initial checkpoint request failed. Traceback: {}".format(traceback.format_exc()))
            exit()

        if 'response' not in r_json or 'svractivities' not in r_json['response'] or len(r_json['response']['svractivities']) == 0: #If there are no results we don't need to write anything or do much
            helper.log_error("airlock_server_activities: something went wrong sending the request to the Airlock Server, please check connectivity. Unable to get initial checkpoint.")
            exit() #Stop here because we can't continue

        else:
            svrcheckpoint = r_json['response']['svractivities'][-1]['checkpoint']
            # Initial pull only establishes the checkpoint baseline; events are indexed from the next interval onwards
            helper.log_info("airlock_server_activities: saving initial checkpoint to Splunk: {} (events will be indexed from the next interval)".format(svrcheckpoint))
            helper.save_check_point("svrcheckpoint", svrcheckpoint)

    else:
        helper.log_info("airlock_server_activities: historical checkpoint found: {}".format(svrcheckpoint))
        try:
            response = _send_logged_request(helper, "airlock_server_activities", url, {"checkpoint":svrcheckpoint}, headers, verify_ssl)
            response.raise_for_status()
            r_json = response.json()
        except Exception:
            helper.log_error("airlock_server_activities: request failed, please check connectivity and that the supplied REST API key is valid. If Access Forbidden is seen, the API key is invalid. Traceback: {}".format(traceback.format_exc()))
            exit() #If the request is unable to be sent we should quit here

        if 'response' not in r_json or 'svractivities' not in r_json['response'] or len(r_json['response']['svractivities']) == 0: #If there are no results we don't need to write anything or do much
            helper.log_info("airlock_server_activities: no results, nothing to do")
        else:
            helper.log_debug("there are results to parse")
            helper.log_debug(r_json)
            #Write the events to the specified index
            written = 0
            for i in r_json['response']['svractivities']:
                event = helper.new_event(source=helper.get_input_stanza_names(), sourcetype="airlock:svractivities", index=helper.get_output_index(), data=json.dumps(i))
                ew.write_event(event)
                written += 1
            helper.log_info("airlock_server_activities: wrote {} events to index {}".format(written, helper.get_output_index()))

            #Set latest checkpoint
            svrcheckpoint = r_json['response']['svractivities'][-1]['checkpoint']
            # save checkpoint
            helper.log_info("airlock_server_activities: saving checkpoint to Splunk: {}".format(svrcheckpoint))
            helper.save_check_point("svrcheckpoint", svrcheckpoint)
