import ta_airlock_digital_rest_api_logger_cloud_declare

import os
import sys
import time
import datetime
import json

import modinput_wrapper.base_modinput
from splunklib import modularinput as smi



import input_module_airlock_otp_usage as input_module

bin_dir = os.path.basename(__file__)

'''
    Custom modular input added to pull OTP usage (including the OTP reason)
    from the Airlock REST API. Modelled on airlock_server_activities.py.
    Add your modular input logic to file input_module_airlock_otp_usage.py
'''
class ModInputairlock_otp_usage(modinput_wrapper.base_modinput.BaseModInput):

    def __init__(self):
        if 'use_single_instance_mode' in dir(input_module):
            use_single_instance = input_module.use_single_instance_mode()
        else:
            use_single_instance = False
        super(ModInputairlock_otp_usage, self).__init__("ta_airlock_digital_rest_api_logger_cloud", "airlock_otp_usage", use_single_instance)
        self.global_checkbox_fields = None

    def get_scheme(self):
        """overloaded splunklib modularinput method"""
        scheme = super(ModInputairlock_otp_usage, self).get_scheme()
        scheme.title = ("Airlock OTP Usage")
        scheme.description = ("Pulls OTP usage records (including the OTP reason/purpose) from the Airlock REST API.")
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True

        scheme.add_argument(smi.Argument("name", title="Name",
                                         description="",
                                         required_on_create=True))

        """
        For customized inputs, hard code the arguments here to hide argument detail from users.
        For other input types, arguments should be get from input_module. Defining new input types could be easier.
        """
        scheme.add_argument(smi.Argument("delete_existing_checkpoint", title="Delete Existing Checkpoint",
                                         description="When checked will delete the existing checkpoint stored in Splunk and exit. This used for troubleshooting purposes only and the utility will not index events while this option is selected.",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("local_airlock_cloud_directoryid", title="Airlock Cloud DirectoryID",
                                         description="[Optional] Will override the addon configuration page. Used for multi-tenancy cloud instances.",
                                         required_on_create=False,
                                         required_on_edit=False))
        scheme.add_argument(smi.Argument("local_airlock_cloud_tenantid", title="Airlock Cloud TenantID",
                                         description="[Optional] Will override the addon configuration page. Used for multi-tenancy cloud instances.",
                                         required_on_create=False,
                                         required_on_edit=False))
        return scheme

    def get_app_name(self):
        return "TA-airlock-digital-rest-api-logger-cloud"

    def validate_input(self, definition):
        """validate the input stanza"""
        input_module.validate_input(self, definition)

    def collect_events(self, ew):
        """write out the events"""
        input_module.collect_events(self, ew)

    def get_account_fields(self):
        account_fields = []
        return account_fields

    def get_checkbox_fields(self):
        checkbox_fields = []
        checkbox_fields.append("delete_existing_checkpoint")
        return checkbox_fields

    def get_global_checkbox_fields(self):
        if self.global_checkbox_fields is None:
            checkbox_name_file = os.path.join(bin_dir, 'global_checkbox_param.json')
            try:
                if os.path.isfile(checkbox_name_file):
                    with open(checkbox_name_file, 'r') as fp:
                        self.global_checkbox_fields = json.load(fp)
                else:
                    self.global_checkbox_fields = []
            except Exception as e:
                self.log_error('Get exception when loading global checkbox parameter names. ' + str(e))
                self.global_checkbox_fields = []
        return self.global_checkbox_fields

if __name__ == "__main__":
    exitcode = ModInputairlock_otp_usage().run(sys.argv)
    sys.exit(exitcode)
