# TA-airlock-digital-hec-routing-fix

## Overview
This hotfix addresses a configuration issue in `props.conf` for the Airlock Digital Splunk Add-on (HEC).

## Changes
- **File**: `local/props.conf`
- **Change**: Renamed `TRANSFORMS-routing` to `TRANSFORMS-sourcetype` for the `[airlock:hec]` stanza.

## Rationale
The referenced transforms (`airlock_hec_routing_*`) are designed to modify the `MetaData:Sourcetype`. 
In Splunk's pipeline, `TRANSFORMS-routing` is processed *before* `TRANSFORMS-sourcetype`. 

If `TRANSFORMS-routing` is used, valid `TRANSFORMS-sourcetype` configurations in upstream apps or the system default could potentially overwrite the sourcetype assignment made by this app. By moving these to `TRANSFORMS-sourcetype`, we ensure they are processed at the correct stage and take precedence as intended for this sourcetype assignment.
