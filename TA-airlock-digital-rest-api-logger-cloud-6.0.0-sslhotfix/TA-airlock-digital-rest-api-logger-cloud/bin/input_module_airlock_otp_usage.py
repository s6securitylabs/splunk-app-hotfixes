# encoding = utf-8

import os
import sys
import time
import datetime
import json
import hashlib
import traceback

'''
Custom input - Airlock OTP Usage
Pulls OTP usage records from the Airlock REST API (POST /v1/otp/usage) so that
the OTP reason/purpose entered by the end user is indexed in Splunk.

OTP usage records are mutable (status transitions Awaiting -> Active ->
Enforced/Revoked), so this input cannot use the checkpoint pattern the other
inputs use. Instead it keeps a per-otpid hash of the last indexed version of
each record and only writes records that are new or have changed.

All API requests and responses are logged at INFO level so they are visible in:
  index=_internal sourcetype="taairlockdigitalrestapiloggercloud:log" otp_usage
'''

# Maximum number of response body characters written to the log per request
MAX_LOGGED_BODY = 10000


def validate_input(helper, definition):
    pass


def _redact_headers(headers):
    # Show which auth header is being sent without leaking the key itself
    return {k: ("****" if k.lower() in ("x-apikey", "userapikey") else v) for k, v in headers.items()}


def _send_logged_request(helper, url, payload, headers, verify_ssl):
    helper.log_info("otp_usage API request: method=POST url={} payload={} headers={} verify={}".format(
        url, json.dumps(payload), json.dumps(_redact_headers(headers)), verify_ssl))
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
    helper.log_info("otp_usage API response: status={} bytes={} body={}{}".format(
        response.status_code, len(body), body[:MAX_LOGGED_BODY],
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

    local_airlock_directory_id = helper.get_arg("local_airlock_cloud_directoryid")
    local_airlock_tenantid = helper.get_arg("local_airlock_cloud_tenantid")

    opt_delete_existing_checkpoint = helper.get_arg('delete_existing_checkpoint')
    if opt_delete_existing_checkpoint is True:
        helper.delete_check_point("otp_usage_state")
        helper.log_info("otp_usage: existing state checkpoint deleted, now exiting. Disable the Delete Existing Checkpoint option to index logs")
        exit()

    helper.get_input_stanza()
    proxy_settings = helper.get_proxy()

    # Sanitize the URL
    if opt_airlock_server_url.startswith("https://"):
        opt_airlock_server_url = opt_airlock_server_url[len("https://"):]
    opt_airlock_server_url = opt_airlock_server_url.split("/")[0]

    # Check if the FQDN contains "appenforcement.com" and modify the URL if needed
    if "appenforcement.com" in opt_airlock_server_url:
        if opt_airlock_server_url.startswith("portal."):
            opt_airlock_server_url = opt_airlock_server_url[len("portal."):]
        endpoint = "/willard/v1/otp/usage"
        headers = {
                "UserApiKey": opt_airlock_rest_api_key,
                "directoryid": (local_airlock_directory_id if local_airlock_directory_id else opt_airlock_directory_id),
                "tenantID": (local_airlock_tenantid if local_airlock_tenantid else opt_airlock_tenant_id)
            }
    else:
        #On-prem/hosted
        endpoint = "/v1/otp/usage"
        headers = {
                "X-ApiKey": opt_airlock_rest_api_key
            }

    url = "https://" + opt_airlock_server_url + (":" + opt_airlock_rest_api_port if opt_airlock_rest_api_port else "") + endpoint

    # Load previously indexed record hashes so we only index new/changed records
    seen = {}
    raw_state = helper.get_check_point("otp_usage_state")
    if raw_state:
        try:
            seen = json.loads(raw_state) if isinstance(raw_state, str) else dict(raw_state)
        except Exception:
            helper.log_error("otp_usage: could not parse state checkpoint, re-indexing all records. State was: {}".format(str(raw_state)[:1000]))
            seen = {}
    helper.log_info("otp_usage: loaded state for {} previously indexed otpids".format(len(seen)))

    try:
        response = _send_logged_request(helper, url, None, headers, verify_ssl)
        response.raise_for_status()
        r_json = response.json()
    except Exception:
        helper.log_error("otp_usage: request to Airlock failed. Traceback: {}".format(traceback.format_exc()))
        exit()

    if 'response' not in r_json:
        helper.log_error("otp_usage: no 'response' key in API reply. Top-level keys were: {}. Check API key and connectivity.".format(list(r_json.keys())))
        exit()

    # The vendor response key for this endpoint is 'otpusage'; tolerate variants
    records = None
    for key in ('otpusage', 'otpusages', 'otps'):
        if key in r_json['response']:
            records = r_json['response'][key]
            helper.log_info("otp_usage: found {} records under response.{}".format(len(records), key))
            break
    if records is None:
        helper.log_error("otp_usage: could not find OTP usage records in reply. response keys were: {}".format(list(r_json['response'].keys())))
        exit()

    written = 0
    for record in records:
        otpid = str(record.get('otpid', ''))
        record_hash = hashlib.md5(json.dumps(record, sort_keys=True).encode('utf-8')).hexdigest()
        if not otpid:
            helper.log_info("otp_usage: record has no otpid field, indexing unconditionally: {}".format(json.dumps(record)[:1000]))
        elif seen.get(otpid) == record_hash:
            continue  # unchanged since last poll
        event = helper.new_event(
            source=helper.get_input_stanza_names(),
            index=helper.get_output_index(),
            sourcetype="airlock:otpusage",
            data=json.dumps(record)
        )
        ew.write_event(event)
        written += 1
        if otpid:
            seen[otpid] = record_hash

    helper.log_info("otp_usage: wrote {} new/changed events out of {} records returned".format(written, len(records)))

    if written > 0:
        helper.save_check_point("otp_usage_state", json.dumps(seen))
        helper.log_info("otp_usage: saved state checkpoint for {} otpids".format(len(seen)))
