import pytest
import argparse
from wavs import WebScanner

########################
# argument parsing     #
########################
arg_parser = argparse.ArgumentParser()
subparsers = arg_parser.add_subparsers(dest='subcommand')

scan_parser = subparsers.add_parser("scan", help='Options to control a vulnerability scan')
tgen_parser = subparsers.add_parser("generate", help='Options to generate text payloads')
report_parser = subparsers.add_parser("report", help='Options to generate reports')
db_parser = subparsers.add_parser("database", help='Options to control databases')

###########################################
# command line arguments for scan command #
###########################################
scan_parser.add_argument(
    'host',
    help='The url of the web application to be scanned, including protocol')

scan_parser.add_argument(
    '-b',
    '--base_dir',
    default='',
    help='The base directory of the application to be scanned'
)

scan_parser.add_argument(
    '-p',
    '--port',
    type=int,
    default=0,
    help='The port the web application is running on')

scan_parser.add_argument(
    '-c',
    '--cookies',
    help='Cookies to include in requests, <cookie_name>=<cookie_value>,[...]')

scan_parser.add_argument(
    '-r',
    '--restrict_paths',
    default='',
    help='Paths which should not be visited, /restrict/path/')

scan_parser.add_argument(
    '-t',
    '--type',
    default='default',
    help='Determines which modules run and in what order. From config')

scan_parser.add_argument(
    '-m',
    '--manual_crawl',
    default=False,
    action='store_true',
    help='Use a proxy to manually crawl the target')

scan_parser.add_argument(
    '--no_report',
    default=False,
    action='store_true',
    help='Do not create a report for this scan'
)

scan_parser.add_argument(
    '--add_success_codes',
    nargs='+',
    type=int,
    help='Add HTTP codes for a found resources. Space delimited list')

scan_parser.add_argument(
    '--remove_success_codes',
    nargs='+',
    type=int,
    help='Remove HTTP codes for found resources. Space delimited list')

scan_parser.add_argument(
    '--save_ext',
    type=str,
    default='html',
    choices=['html', 'txt', 'pdf'],
    help='Set the extension to save the report as'
)

scan_parser.add_argument(
    '-o',
    '--outfile',
    default=False,
    action='store_true',
    help='The path to save the report to'
)

################################################
# command line arguments for generator command #
################################################
tgen_parser.add_argument(
    '-g',
    '--generator',
    default=False,
    action='store_true',
    help='Runs the attack string text generator')

#############################################
# command line arguments for report command #
#############################################
report_parser.add_argument(
    '-o',
    '--outfile',
    help='The full path of the report file to be created, including extension'
)

###############################################
# command line arguments for database command #
###############################################
db_parser.add_argument(
    '--reset',
    action='store_true',
    help='Reset both wordlist and scans database. Deletes all data from scans, resets wordlist count'
)

db_parser.add_argument(
    '--reset_wordlist',
    action='store_true',
    help='Reset the count of the wordlist database'
)

db_parser.add_argument(
    '--reset_scans',
    action='store_true',
    help='Delete all previous scan data'
)

args = arg_parser.parse_args()

# --------------- tests ----------------------------


@pytest.fixture
def scan_widget_default():
    test_args = arg_parser.parse_args(['scan', 'http://localhost'])
    w = WebScanner(test_args)
    w._parse_cmd_line_args()
    return w


@pytest.fixture
def scan_widget_basedir():
    test_args = arg_parser.parse_args(['scan', '-b', 'dvwa/', 'http://localhost'])
    w = WebScanner(test_args)
    w._parse_cmd_line_args()
    return w


def test_get_host_url_base_default(scan_widget_default):
    assert scan_widget_default.get_host_url_base() == 'http://localhost:80'
    assert scan_widget_default.get_host_url_base(False) == 'http://localhost:80'


def test_get_host_url_base_with_basedir(scan_widget_basedir):
    assert scan_widget_basedir.get_host_url_base() == 'http://localhost:80/dvwa/'
    assert scan_widget_basedir.get_host_url_base(False) == 'http://localhost:80'
