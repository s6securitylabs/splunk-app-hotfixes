# encoding = utf-8

import os
import sys
import time
import datetime
import json

def validate_input(helper, definition):
    pass

def collect_events(helper, ew):

    opt_airlock_server_url = helper.get_global_setting('airlock_server_url')
    opt_airlock_rest_api_port = helper.get_global_setting('airlock_rest_api_port')
    opt_airlock_rest_api_key = helper.get_global_setting('airlock_rest_api_key')
    opt_airlock_tenant_id = helper.get_global_setting('airlock_tenant_id')
    opt_airlock_tenant_id = helper.get_global_setting('airlock_tenant_id')
    opt_airlock_directory_id = helper.get_global_setting('airlock_directory_id')
    
    # Get SSL verification settings
    opt_disable_ssl = helper.get_global_setting('airlock_disable_ssl_verification')
    opt_ca_cert_path = helper.get_global_setting('airlock_custom_ca_cert_path')
    
    # Determine verify_ssl value based on settings
    # Default is True. If disable is checked, False. If path provided, use path.
    verify_ssl = True
    if opt_disable_ssl and str(opt_disable_ssl).lower() in ('true', '1', 'yes', 'on'):
        verify_ssl = False
    elif opt_ca_cert_path and str(opt_ca_cert_path).strip():
        verify_ssl = str(opt_ca_cert_path).strip()

    local_airlock_directory_id = helper.get_arg("local_airlock_cloud_directoryid")
    local_airlock_tenantid = helper.get_arg("local_airlock_cloud_tenantid")

    opt_execution_types_to_collect = helper.get_arg('execution_types_to_collect')
    opt_delete_existing_checkpoint = helper.get_arg('delete_existing_checkpoint')
    if opt_delete_existing_checkpoint is True:
        helper.delete_check_point("checkpoint")
        helper.log_debug("Existing checkpoint deleted, now exiting. Disable the Delete Existing Checkpoint option to index logs")
        exit()

    helper.get_input_stanza()
    proxy_settings = helper.get_proxy()

    # get checkpoint
    checkpoint = helper.get_check_point("checkpoint")

    # Sanitize the URL
    if opt_airlock_server_url.startswith("https://"):
        opt_airlock_server_url = opt_airlock_server_url[len("https://"):]
    opt_airlock_server_url = opt_airlock_server_url.split("/")[0]

    # Check if the FQDN contains "appenforcement.com" and modify the URL if needed
    if "appenforcement.com" in opt_airlock_server_url:
        if opt_airlock_server_url.startswith("portal."):
            opt_airlock_server_url = opt_airlock_server_url[len("portal."):]
        endpoint = "/willard/v1/logging/exechistories"
        headers = {
                "UserApiKey": opt_airlock_rest_api_key, 
                "directoryid": (local_airlock_directory_id if local_airlock_directory_id else opt_airlock_directory_id),
                "tenantID": (local_airlock_tenantid if local_airlock_tenantid else opt_airlock_tenant_id)
            }
    else:
        #On-prem/hosted
        endpoint = "/v1/logging/exechistories"
        headers = {
                "X-ApiKey": opt_airlock_rest_api_key
            }
        
    url = "https://" + opt_airlock_server_url + (":" + opt_airlock_rest_api_port if opt_airlock_rest_api_port else "") + endpoint

    try:
        helper.log_debug("Checkpoint value in Splunk is:" + checkpoint)
    except:
        helper.log_debug("Checkpoint appears to be empty")
    # The following examples send rest requests to some endpoint.
    if checkpoint is None:
        helper.log_debug("No historical checkpoint found, obtaining restart checkpoint from Airlock") 

    # Updated to use dynamic verify_ssl
        response = helper.send_http_request(
            url, 
            method="POST", 
            parameters=None,
            payload={"type":opt_execution_types_to_collect},
            headers=headers, 
            cookies=None, 
            verify=verify_ssl, 
            cert=None, 
            timeout=None, 
            use_proxy=True
        )

        response.raise_for_status()
        r_json = response.json()        
        if not 'response' in r_json or len(r_json['response']['exechistories']) == 0: #If there are no results we don't need to write anything or do much
            helper.log_info("Something went wrong sending the request to the Airlock Server, please check connectivity and your API key. Unable to get initial checkpoint.")
            exit() #Stop here because we can't continue
            
        else:
            r_json = response.json()
            helper.log_debug(r_json)
            checkpoint = r_json['response']['exechistories'][-1]['checkpoint']
            #Write the events to the specified index
            event = helper.new_event(source=helper.get_input_stanza_names(), sourcetype="airlock:exechistories", index=helper.get_output_index(), data=json.dumps(r_json['response']['exechistories']))
            # save checkpoint
            helper.log_debug("Saving checkpoint to Splunk:" + checkpoint)
            helper.save_check_point("checkpoint", checkpoint)

    else:
        helper.log_debug("Historical checkpoint found:" + checkpoint)
        try:
            # Updated to use dynamic verify_ssl
            response = helper.send_http_request(
                url, 
                method="POST", 
                parameters=None, 
                payload={"checkpoint":checkpoint,"type":opt_execution_types_to_collect},
                headers=headers, 
                cookies=None, 
                verify=verify_ssl, 
                cert=None,
                timeout=None, 
                use_proxy=True
            )

            response.raise_for_status()
            r_json = response.json()
        except:
            helper.log_info("Something went wrong sending the request to the Airlock Server, please check connectivity and your API key for validity.")
            exit() #If the request is unable to be sent we should quit here
            
        if not 'response' in r_json or len(r_json['response']['exechistories']) == 0: #If there are no results we don't need to write anything or do much
            helper.log_debug("no results, nothing to do")
        else:    
            helper.log_debug("there are results to parse")
            helper.log_debug(r_json)
            #Write the events to the specified index
            for i in r_json['response']['exechistories']:
                event = helper.new_event(source=helper.get_input_stanza_names(), sourcetype="airlock:exechistories", index=helper.get_output_index(), data=json.dumps(i))
                ew.write_event(event)
            index=helper.get_output_index()
            helper.log_debug("index is" + index)
            #Set latest checkpoint
            checkpoint = r_json['response']['exechistories'][-1]['checkpoint']
            # save checkpoint
            helper.log_info("Saving checkpoint to Splunk:" + checkpoint)
            helper.save_check_point("checkpoint", checkpoint)
