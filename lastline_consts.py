# --
# File: lastline_consts.py
# Copyright (c) 2015-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# --
RESULT_REPORT_KEY = "report"
TASK_ID_KEY = 'id'
TARGET_KEY = 'target'
RESULTS_URL_KEY = 'result_url'
ANALYSIS_TYPE_FILE = 'file'
ANALYSIS_TYPE_URL = 'url'
SUMMARY_TYPE_KEY = 'type'
ANALYSIS_KEY = 'analysis'
URL_ANALYSIS_ENDED_KEY = 'analysis_ended'
FILE_ANALYSIS_END_KEY = 'analysis_end'
ANALYSIS_SUBJECT_KEY = 'analysis_subjects'

VAULT_ERR_INVALID_VAULT_ID = "Invalid Vault ID"
VAULT_ERR_FILE_NOT_FOUND = "Vault file could not be found with supplied Vault ID"

PHANTOM_ERR_CODE_UNAVAILABLE = "Error code unavailable"
PHANTOM_ERR_MSG_UNAVAILABLE = "Unknown error occurred. Please check the asset configuration and|or action parameters"

LASTLINE_GENERATED_RANDOM_HASH = "Generated Random hash '{gen_hash}' to query"
LASTLINE_SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
LASTLINE_ERR_CONNECTIVITY_TEST = "Test Connectivity Failed"
LASTLINE_ERR_CONNECT = "Error occurred, response: {response}"
LASTLINE_ERR_GETTING_REPORT = "Error getting report"
LASTLINE_ERR_SUBMIT_URL = "Error submitting URL"
LASTLINE_ERR_TASK_ID_NOT_FOUND = "Task ID not found"
LASTLINE_ERR_NO_FILES = "No runnable files found"

LASTLINE_SLEEP_SECS = 10
LASTLINE_JSON_POLL_TIMEOUT_SECS = "timeout"
LASTLINE_MAX_TIMEOUT_DEF_SECS = 5 * 60
LASTLINE_POLL_TIMEOUT = "Polled for the maximum number of times"
LASTLINE_POLL_TIMEOUT += " Report not yet ready. Please try 'get report' action with id: {0} later"
