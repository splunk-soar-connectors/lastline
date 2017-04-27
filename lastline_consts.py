# --
# File: lastline_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
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

LASTLINE_GENERATED_RANDOM_HASH = "Generated Random hash '{gen_hash}' to query"
LASTLINE_SUCC_CONNECTIVITY_TEST = "Connectivity test succeeded"
LASTLINE_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
LASTLINE_ERR_CONNECT = "Error occured, response: {response}"
LASTLINE_ERR_GETTING_REPORT = "Error getting report"
LASTLINE_ERR_SUBMIT_URL = "Error submutting URL"
LASTLINE_ERR_TASK_ID_NOT_FOUND = "Task ID not found"
LASTLINE_ERR_NO_FILES = "No runnable files found."

LASTLINE_SLEEP_SECS = 10
LASTLINE_JSON_POLL_TIMEOUT_SECS = "timeout"
LASTLINE_MAX_TIMEOUT_DEF_SECS = 5 * 60
LASTLINE_POLL_TIMEOUT = "Polled for the maximum number of times."
LASTLINE_POLL_TIMEOUT += " Report not yet ready. Please try 'get report' action with id: {0} later"
