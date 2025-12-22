
import ta_airlock_digital_rest_api_logger_cloud_declare

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    DataInputModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunk_aoblib.rest_migration import ConfigMigrationHandler

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        'interval',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.Pattern(
            regex=r"""^\-[1-9]\d*$|^\d*$""", 
        )
    ), 
    field.RestField(
        'index',
        required=True,
        encrypted=False,
        default='default',
        validator=validator.String(
            min_len=1, 
            max_len=80, 
        )
    ), 
    field.RestField(
        'execution_types_to_collect',
        required=True,
        encrypted=False,
        default='0~10~2~3~4~5~6~7~8~9~1~11~12~13~14~15~16~17~18',
        validator=None
    ), 
    field.RestField(
        'delete_existing_checkpoint',
        required=False,
        encrypted=False,
        default=None,
        validator=None
    ), 
    field.RestField(
        'local_airlock_cloud_directoryid',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=0, 
            max_len=8192, 
        )
    ), 
    field.RestField(
        'local_airlock_cloud_tenantid',
        required=False,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=0, 
            max_len=8192, 
        )
    ), 

    field.RestField(
        'disabled',
        required=False,
        validator=None
    )

]
model = RestModel(fields, name=None)



endpoint = DataInputModel(
    'airlock_execution_history',
    model,
)


if __name__ == '__main__':
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
