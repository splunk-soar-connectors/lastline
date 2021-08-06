# --
# File: lastline_view.py
# Copyright (c) 2015-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


def parse_report(report):
    # pre-process the report here if required

    ana_subjects = report.get('analysis_subjects')

    if not ana_subjects:
        return

    for subject in ana_subjects:
        file_name = None
        try:
            file_name = subject['overview']['process']['executable']['static_pe_information']['original_filename']
        except:
            pass

        if not file_name:
            try:
                file_name = subject['overview']['process']['executable']['abs_path']
                file_name = file_name.split('\\')[-1]
            except:
                pass

        if not file_name:
            try:
                file_name = subject['overview']['process']['executable']['filename']
                file_name = file_name.split('\\')[-1]
            except:
                pass

        if not file_name:
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

    ctx_result = {'summary': result.get_summary(), 'param': result.get_param(), 'status': result.get_status()}

    if not ctx_result['status']:
        ctx_result['message'] = result.get_message()

    data = result.get_data()

    if not data:
        return ctx_result

    data = data[0]

    report = data.get('report')

    if not report:
        return ctx_result

    ctx_result['report'] = report
    parse_report(report)

    return ctx_result


def display_report(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)
    # print context
    return 'll_display_report.html'
