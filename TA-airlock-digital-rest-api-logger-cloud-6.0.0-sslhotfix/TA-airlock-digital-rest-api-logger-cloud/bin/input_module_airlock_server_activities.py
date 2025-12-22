
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

    try:
        helper.log_debug("Checkpoint value in Splunk is:" + svrcheckpoint)
    except:
        helper.log_debug("Checkpoint appears to be empty")
    # The following examples send rest requests to some endpoint.
    if svrcheckpoint is None:
        helper.log_debug("No historical checkpoint found, obtaining restart checkpoint from Airlock") 

    # Updated to use dynamic verify_ssl
        response = helper.send_http_request(
            url, 
            method="POST", 
            parameters=None, 
            payload=None,
            headers=headers, 
            cookies=None, 
            verify=verify_ssl, 
            cert=None, 
            timeout=None, 
            use_proxy=True
        )
        
        response.raise_for_status()
        r_json = response.json()        
        if not 'response' in r_json or len(r_json['response']['svractivities']) == 0: #If there are no results we don't need to write anything or do much
            helper.log_debug("Something went wrong sending the request to the Airlock Server, please check connectivity. Unable to get initial checkpoint.")
            exit() #Stop here because we can't continue
            
        else:
            r_json = response.json()
            helper.log_debug(r_json)
            svrcheckpoint = r_json['response']['svractivities'][-1]['checkpoint']
            #Write the events to the specified index
            event = helper.new_event(source=helper.get_input_stanza_names(), sourcetype="airlock:svractivities", index=helper.get_output_index(), data=json.dumps(r_json['response']['svractivities']))
            # save checkpoint
            helper.log_debug("Saving checkpoint to Splunk:" + svrcheckpoint)
            helper.save_check_point("svrcheckpoint", svrcheckpoint)

    else:
        helper.log_debug("Historical checkpoint found:" + svrcheckpoint)
        try:
            # Updated to use dynamic verify_ssl
            response = helper.send_http_request(
                url, 
                method="POST", 
                parameters=None, 
                payload={"checkpoint":svrcheckpoint},
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
            helper.log_info("Something went wrong sending the request to the Airlock Server, please check connectivity and that the supplied REST API key is valid. Please enable debug logging to see more information. If Access Forbidden is seen on debug level logging, the API key is invalid.")
            r_json = response.json()
            helper.log_debug(r_json)
            exit() #If the request is unable to be sent we should quit here
            
        if not 'response' in r_json or len(r_json['response']['svractivities']) == 0: #If there are no results we don't need to write anything or do much
            helper.log_debug("no results, nothing to do")
        else:    
            helper.log_debug("there are results to parse")
            helper.log_debug(r_json)
            #Write the events to the specified index
            for i in r_json['response']['svractivities']:
                event = helper.new_event(source=helper.get_input_stanza_names(), sourcetype="airlock:svractivities", index=helper.get_output_index(), data=json.dumps(i))
                ew.write_event(event)

            #Set latest checkpoint
            svrcheckpoint = r_json['response']['svractivities'][-1]['checkpoint']
            # save checkpoint
            helper.log_info("Saving checkpoint to Splunk:" + svrcheckpoint)
            helper.save_check_point("svrcheckpoint", svrcheckpoint)
