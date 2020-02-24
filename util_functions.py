#/usr/bin/python3

# author:       Ryan Ritchie
# student no:   17019225
# email:        ryan2.ritchie@live.uwe.ac.uk
# file:         utils.py

import importlib
import inspect
import requests
import requests.exceptions
import unittest

from os import path

# aesthetics imports
try:
    import colorama
except:
    print('Required modules not installed. use pip install -r requirements.txt')
    exit(1)

from colorama import Fore, Back
colorama.init(autoreset=True)

def load_module(package_name, class_name):
    try:
        module = importlib.import_module(f'{package_name}.{class_name}')

        for _class in dir(module):
            obj = getattr(module, _class)

            try:
                if obj.__wavs_mod__:
                    return obj

            except AttributeError:
                pass

    except ImportError:
        return None

###############################################################################
#                                                                             #
#                            HTTP UTIL FUNCTIONS                              #
#                                                                             #
###############################################################################

def http_get_request(url, cookies):
    """

        @param url (str) -              the URL to make the request to
        @param cookies (dict) -         the cookies to send with the request
    """
    try:
        r = requests.get(url, cookies=cookies)

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        warning(f'Server at {url} is not responding')
        return 1

    return r

def http_post_request(url, post_params, cookies):
    """

        @param url (str) -              the URL to make the request to
        @param post_params (dict) -     the post parameters to include in the request
        @param cookies (dict) -         the cookies to send with the request
    """
    try:
        post_data = {}
        r = requests.post(url, data=post_params, cookies=cookies)

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        warning(f'Server at {url} is not responding')
        return 1

    return r

def cookie_parse(cookie_string):
    if not cookie_string:
        return {}

    cookies = cookie_string.split(',')

    cookie_dict = {}
    for c in cookies:
        k, v = c.split('=')
        cookie_dict[k] = v

    return cookie_dict

###############################################################################
#                                                                             #
#                           PRINT UTIL FUNCTIONS                              #
#                                                                             #
###############################################################################

def banner_colour(banner):
    print(Fore.CYAN + banner)

def _print_status(message, type, prepend):
    assert(type in ['success', 'warning', 'info'])

    # TODO: load in verbosity option from config file
    # 0 - quiet mode (default): dont print anything
    # 1 - print mode: print messages to stdout
    # 2 - log mode: print to stdout and log file
    VERBOSITY = 1

    if type == 'success':
        colour = Fore.GREEN
        status_code = '+'
    elif type == 'warning':
        colour = Fore.RED
        status_code = '-'
    elif type == 'info':
        colour = Fore.YELLOW
        status_code = '*'

    # TODO: sort this out ->
    if VERBOSITY or type == 'warning':
        print(colour + f'{prepend}[{status_code}] {message}\n', end='')

def success(message, prepend=''):
    _print_status(message, 'success', prepend)

def warning(message, prepend=''):
    _print_status(message, 'warning', prepend)

def info(message, prepend=''):
    _print_status(message, 'info', prepend)


class Test(unittest.TestCase):
    def test_cookie_parse(self):
        c_string = 'testcookie=1,PHPSESSID=ff7p62chjhlfi69o71nqk5vqd4'
        cookies = cookie_parse(c_string)
        self.assertEqual(cookies['testcookie'], '1')
        self.assertEqual(cookies['PHPSESSID'], 'ff7p62chjhlfi69o71nqk5vqd4')

    def test_save_new_scan(self):
        class FakeScanObject:
            def __init__(self):
                self.host = '127.0.0.1'
                self.port = 80

        fake_scan_object = FakeScanObject()
        #id = save_new_scan(fake_scan_object)
        #self.assertIsInstance(id, int)

    def test_save_scan_results(self):
        save_scan_results(1, 'test', 'method, action, params', [('GET', 'index.php', 'username, password, submit'), ('POST', 'contact.php', 'name', 'email')])
        pass

    def test_load_scan_results(self):
        print(load_scan_results(1, 'directories_found', 'directories_found'))


    def test_db_table_exists(self):
        self.assertTrue(db_table_exists("directories_found"))


if __name__ == '__main__':
    unittest.main()
