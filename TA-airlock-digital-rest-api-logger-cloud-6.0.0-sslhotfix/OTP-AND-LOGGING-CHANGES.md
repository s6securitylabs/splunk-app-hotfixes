# Airlock Add-on: OTP Usage Input + API Logging (v6.0.1, build 11)

Installable package: `TA-airlock-digital-rest-api-logger-cloud-6.0.1-otp-sslhotfix.tgz`
(version is aligned across app.conf, app.manifest, the .aob_meta and the filename).

## Why this change exists

The custom modification to pull the OTP reason into Splunk via an additional
API call was **never committed to this repository** — the only customisation
present here was the SSL verification hotfix (`changes.diff`). If the add-on
was ever reinstalled from the `.tgz` in this repo, any OTP code applied
directly on the Splunk server would have been wiped out. The OTP pull has now
been rebuilt from scratch as a proper modular input, and verbose API logging
has been added to every input so failures are visible.

## New input: `airlock_otp_usage`

* Calls `POST /v1/otp/usage` (on-prem/hosted, `X-ApiKey` header) or
  `POST /willard/v1/otp/usage` (Airlock Cloud / appenforcement.com,
  `UserApiKey`/`tenantID`/`directoryid` headers) — same server/port/SSL
  settings as the other inputs.
* Records are parsed from `response.otpusage` (falls back to
  `response.otpusages` / `response.otps` and logs the actual keys if the
  expected key is missing, so a schema mismatch is visible instead of silent).
* Indexed with sourcetype `airlock:otpusage` (KV_MODE=json). The OTP
  reason/purpose entered by the end user is a field on each record.
* OTP usage records are **mutable** (status moves Awaiting → Active →
  Enforced/Revoked), so the checkpoint pattern used by the other inputs does
  not apply. Instead the input stores an md5 hash per `otpid` and only
  re-indexes records that are new or have changed. In Splunk, use
  `| dedup otpid sortby -_time` (or a `latest()` stats) to get current state.
* Runs every 300s by default (`default/inputs.conf`), enabled by default,
  manageable from the add-on's Inputs UI page.
* The "Delete Existing Checkpoint" option clears the stored state
  (`otp_usage_state`) and forces a full re-index on the next run.

New files / wiring:

* `bin/input_module_airlock_otp_usage.py` — collection logic
* `bin/airlock_otp_usage.py` — modular input wrapper
* `bin/TA_airlock_digital_rest_api_logger_cloud_rh_airlock_otp_usage.py` — REST handler
* `default/inputs.conf`, `default/restmap.conf`, `default/props.conf`,
  `README/inputs.conf.spec`, `appserver/static/js/build/globalConfig.json`

## API call logging (all inputs)

Every input now logs, at INFO level (the add-on's default log level):

* the request: method, full URL, JSON payload, headers (API key redacted),
  and the SSL `verify` value in effect
* the response: HTTP status, byte count, and the body (truncated to 10,000
  characters)
* the number of events written per run, and checkpoint save/load values

To see the calls:

```
index=_internal sourcetype="taairlockdigitalrestapiloggercloud:log" "API request" OR "API response"
```

## Logic errors found during review

1. **`response.json()` called before `raise_for_status()`** (agent, policies):
   an HTTP error with a non-JSON body (e.g. an HTML 403 page) raised a JSON
   decode error that masked the real HTTP status. Order swapped; failures now
   log the status and body first.
2. **`NameError` inside the error handler** (server activities): the `except`
   block called `response.json()`, but if the request itself threw, `response`
   was never assigned — the input crashed while trying to report the error.
   Handlers now log `traceback.format_exc()` instead.
3. **Bare `except:` blocks swallowed the real error** (execution history,
   server activities): the actual exception was discarded and replaced with a
   generic "check connectivity" message. Tracebacks are now logged.
4. **Duplicated `airlock_tenant_id` lookup** in all four modules (harmless,
   removed).
5. **`KeyError` risk on malformed replies**: `r_json['response']['exechistories']`
   etc. were accessed without checking the inner key. Now guarded, with the
   actual keys logged when the expected one is absent.
6. **Per-group policy fetch had no error handling** (policies): one failing
   group aborted the whole run. Failures are now logged and the remaining
   groups still indexed.
7. **Dead code on first run** (execution history, server activities): the
   initial-checkpoint branch built an event with `helper.new_event(...)` but
   never called `ew.write_event(...)`, so it was never indexed. The intent is
   to only establish a checkpoint baseline on first run; the dead event was
   removed and a log line states that indexing starts on the next interval.
8. **Suspect cloud endpoint** (server activities): the willard path is
   `/willard/v1/logging/svractivitiess` — note the doubled trailing "s",
   unlike `/willard/v1/logging/exechistories`. Carried over unchanged from
   the vendor 6.0.0 release, but if cloud server-activity pulls 404, this is
   the prime suspect — the logged request URL will now show it.
