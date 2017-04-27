# --
# File: lastline_view.py
#
# Copyright (c) Phantom Cyber Corporation, 2016
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# import json

# from lastline_consts import *


def parse_report(report):
    # pre-process the report here if required

    ana_subjects = report.get('analysis_subjects')

    if (not ana_subjects):
        return

    for subject in ana_subjects:
        file_name = None
        try:
            file_name = subject['overview']['process']['executable']['static_pe_information']['original_filename']
        except:
            pass

        if (not file_name):
            try:
                file_name = subject['overview']['process']['executable']['abs_path']
                file_name = file_name.split('\\')[-1]
            except:
                pass

        if (not file_name):
            try:
                file_name = subject['overview']['process']['executable']['filename']
                file_name = file_name.split('\\')[-1]
            except:
                pass

        if (not file_name):
            file_name = "no_name"

        pid = None

        try:
            pid = subject['overview']['process']['process_id']
        except:
            pid = "Unknown"
            pass

        subject['process_display'] = "{0} (PID: {1})".format(file_name, pid)

    return report


def get_ctx_result(result):

    ctx_result = {}

    ctx_result['summary'] = result.get_summary()
    ctx_result['param'] = result.get_param()
    ctx_result['status'] = result.get_status()

    if (not ctx_result['status']):
        ctx_result['message'] = result.get_message()

    data = result.get_data()

    if (not data):
        return ctx_result

    data = data[0]

    report = data.get('report')

    if (not report):
        return ctx_result

    ctx_result['report'] = report
    parse_report(report)

    return ctx_result


def display_report(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if (not ctx_result):
                continue
            results.append(ctx_result)
    # print context
    return 'll_display_report.html'
