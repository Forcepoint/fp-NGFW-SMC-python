#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import logging
import sys
import time

sys.path.append('../../')  # smc-python
from smc import session  # noqa
from smc.api.common import SMCRequest  # noqa
from smc.administration.reports import MiniReport   # noqa

logging.getLogger()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - '
                                               '%(name)s - [%(levelname)s] : %(message)s')

MINI_REPORT_NAME = "Top Network Latencies by Application"
CUSTOM_MINI_REPORTS_LIST = [MINI_REPORT_NAME]


def related_link(links, rel_name):
    """ Find URL of the related object. """
    for link in links:
        if link['rel'] == rel_name:
            return link['href']
    return ''


def get_launch_time():
    date = time.strftime("%m/%d/%y %H:%M:%S")
    launch_time = str(int(time.mktime(time.strptime(date, "%m/%d/%y %H:%M:%S")) * 1000))
    return launch_time


def get_duration_in_seconds(duration):
    """
    Convert duration in seconds
    :param duration: duration in format 1d, 1h, 1m, 1s
    :return: duration in seconds
    """
    if duration[-1] == "d":
        return int(duration[:-1]) * 86400
    elif duration[-1] == "h":
        return int(duration[:-1]) * 3600
    elif duration[-1] == "m":
        return int(duration[:-1]) * 60
    else:
        logging.error("Only days, hours, minutes and seconds format are supported")
        raise NameError


def generate_and_follow_mini_report(report_name, launch_time, overriding_duration, senders=None):
    """
    Generate mini report
    :param report_name: Name of the report
    :param launch_time: Launch time of the report
    :param overriding_duration: Duration of the report
    :param senders: List of senders to use for the report
    :return: Mini report json content
    """
    mini_report = MiniReport(report_name)
    res = mini_report.generate(launch_time=launch_time, overriding_duration=overriding_duration,
                               senders=senders)
    generate_mini_report_follower_link = res["follower"]
    in_progress = res["in_progress"]
    generate_follower = ""
    while in_progress is True:
        time.sleep(1)
        generate_follower = SMCRequest(href=generate_mini_report_follower_link).read()
        generate_follower = generate_follower.json
        try:
            in_progress = generate_follower["in_progress"]
        except TypeError:
            logging.error(
                f"Error happened during generate mini report for [{report_name}]"
            )
            return None

    if not res["success"]:
        raise Exception(res["last_message"])

    result_mini_report_link = related_link(generate_follower["link"], "result")
    json_content = SMCRequest(href=result_mini_report_link).read()
    return json_content.json


def main():
    return_code = 0
    try:
        arguments = parse_command_line_arguments()
        session.login(url=arguments.api_url, api_key=arguments.api_key,
                      login=arguments.smc_user, pwd=arguments.smc_pwd,
                      api_version=arguments.api_version)
        arguments.launch_time = get_launch_time()
        arguments.duration = get_duration_in_seconds("1d")

        for report_name in CUSTOM_MINI_REPORTS_LIST:
            logging.info(f"Mini report {report_name} will be generated")
            launch_time = arguments.launch_time
            overriding_duration = arguments.duration
            senders = []
            res = generate_and_follow_mini_report(report_name,
                                                  launch_time,
                                                  overriding_duration,
                                                  senders)
            logging.info(f"Mini report {report_name} content:")
            logging.info(res)

    except BaseException as e:
        logging.error(f"Exception:{e}")
        return_code = 1

    finally:
        session.logout()
    return return_code


def parse_command_line_arguments():
    """ Parse command line arguments. """

    parser = argparse.ArgumentParser(
        description='Example script for mini report usage in SMC',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False)
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='show this help message and exit')
    parser.add_argument(
        '--api-url',
        type=str,
        help='SMC API url like https://192.168.1.1:8082')
    parser.add_argument(
        '--api-version',
        type=str,
        help='The API version to use for run the script'
    )
    parser.add_argument(
        '--smc-user',
        type=str,
        help='SMC API user')
    parser.add_argument(
        '--smc-pwd',
        type=str,
        help='SMC API password')
    parser.add_argument(
        '--api-key',
        type=str, default=None,
        help='SMC API api key (Default: None)')
    arguments = parser.parse_args()

    if arguments.help:
        parser.print_help()
        sys.exit(1)
    if arguments.api_url is None:
        parser.print_help()
        sys.exit(1)

    return arguments


if __name__ == '__main__':
    sys.exit(main())
