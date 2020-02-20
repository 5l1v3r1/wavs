#/usr/bin/python3

# author:       Ryan Ritchie
# student no:   17019225
# email:        ryan2.ritchie@live.uwe.ac.uk
# file:         utils.py

import sqlite3
import importlib
import inspect
import requests
import requests.exceptions
import unittest
import pickle

from sqlite3 import Error
from datetime import datetime
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


###############################################################################
#                                                                             #
#                       DATABASE UTIL FUNCTIONS                               #
#                                                                             #
###############################################################################

DB_FILE = 'database/main.db'
DB_SCAN_RESULTS = 'database/scans.db'

def db_get_connection(database_file):
    """ create the database connection to the sqlite database

        :param database_file:   the path to the database file
        :return:                sqlite3 database connection
    """

    connection = None
    try:
        connection = sqlite3.connect(database_file)
    except Error as e:
        print(e)

    return connection


def db_create_table(sql_statement):
    connection = db_get_connection(DB_SCAN_RESULTS)
    db_execute_statement(connection, sql_statement)


def db_execute_statement(connection, sql_statement):
    """ execute a sql statement on the database represented by the connection
        object

        :param connection:      a sqlite3 database connection
        :param sql_statement:   the sql statement to be executed on the database
        :return:
    """

    try:
        cursor = connection.cursor()
        cursor.execute(sql_statement)
        connection.commit()
    except Error as e:
        print('sql error')
        print(e)


def _db_get_data(connection, sql_select_statement):
    try:
        cursor = connection.cursor()
        cursor.execute(sql_select_statement)

        return cursor.fetchall()
    except Error as e:
        print(e)


def db_table_exists(table_name):
    connection = db_get_connection(DB_SCAN_RESULTS)

    try:
        cursor = connection.cursor()
        sql_check_tbl_exists = f'SELECT name FROM sqlite_master WHERE type="table" and name="{table_name}"'
        cursor.execute(sql_check_tbl_exists)
        if len(cursor.fetchall()) > 0:
            return True

        return False
    except Error as e:
        print(e)

def db_get_wordlist(wordlist_name, group_name):
    """ load a wordlist from the database

        :param wordlist_name:   the name of the wordlist, also the table name
        :param group_name:      the name of a group of words to be selected
        :return (list):
    """
    c = db_get_connection(DB_FILE)

    sql_get_wordlist = "SELECT word FROM '{}' WHERE type = '{}'".format(wordlist_name, group_name)

    result = _db_get_data(c, sql_get_wordlist)
    wordlist = [row[0] for row in result]

    return wordlist

def db_get_wordlist_generic(table_name, column_names, filter=None):
    """

        @param column_names -   a string list, separated by commas
        @param filter -         a tuple (column_name, criteria)
    """
    c = db_get_connection(DB_FILE)

    if not filter:
        sql_get_wordlist = f"SELECT {column_names} FROM '{table_name}'"
    else:
        sql_get_wordlist = f"SELECT {column_names} FROM '{table_name}' WHERE {filter[0]} = '{filter[1]}'"

    result = _db_get_data(c, sql_get_wordlist)

    return result


def db_wordlist_add_words(wordfile, table_name, words, group='general'):
    """ insert words into a wordlist table

        :param wordlist:    the wordlist to add the words to
        :param words:       the words to add to the wordlist
        :param group:       the group name of the words being added
        :return:
    """

    # create a connection to the database
    c = db_get_connection(DB_FILE)

    words = []
    with open(wordfile, 'r') as f:
        for line in f:
            words.append(line)

    for word in words:
        sql_add_words = f"INSERT INTO {table_name}(injection_string, type) VALUES('{word}', '{group}');"
        db_execute_statement(c, sql_add_words)

    c.close()


def __load_wordlist(wordlist_file):
    with open(wordlist_file, 'r') as f:
        wordlist = f.read()
        wordlist = wordlist.split('\n')
        wordlist = [word for word in wordlist if word]

    db_wordlist_add_words('directory', wordlist)


def save_new_scan(scan_object):
    conn = db_get_connection(DB_SCAN_RESULTS)

    scan_start = str(datetime.now())
    sql_new_scan = (f"INSERT INTO scans(timestamp, host, port)"
                    f" VALUES('{scan_start}',"
                           f"'{scan_object.host}',"
                           f"'{scan_object.port}')")

    db_execute_statement(conn, sql_new_scan)

    sql_get_id = f"SELECT id FROM scans ORDER BY id DESC LIMIT 0, 1"
    result = _db_get_data(conn, sql_get_id)

    # result is a list containing a tuple
    return result[0][0]


def save_scan_results(scan_id, table_name, table_columns, results):
    conn = db_get_connection(DB_SCAN_RESULTS)

    for row in results:
        # give each string in row quotation marks
        if isinstance(row, (list, tuple)):
            val_list = [f'"{r}"' for r in row]

            # construct a value string, comma delimited
            val_string = ','.join(val_list)
        else:
            val_string = f'"{row}"'

        # construct the sql statement
        sql_save_results = f'INSERT OR IGNORE INTO {table_name} (scan_id,{table_columns}) VALUES ({scan_id},{val_string})'
        db_execute_statement(conn, sql_save_results)

    conn.close()


def load_scan_results(scan_id, column_names, table_name):
    ''' load scan results from previous modules, from the database.

        @param:     scan_id (int)           - the scan id to be loaded
        @param:     column_names (string)   - the column names to load. multiple
                                              columns delimited with commas
        @param:     scan_name (string)      - the name of the scan module

        @return:    (list) the scan results
    '''
    conn = db_get_connection(DB_SCAN_RESULTS)

    # the SQL query to get the scan results
    sql_load_scan = f'SELECT {column_names} FROM {table_name} WHERE scan_id={scan_id}'

    # execute the query and get results
    result = _db_get_data(conn, sql_load_scan)

    # convert the returned tuple to a list
    #results = [r[0] for r in result]
    conn.close()

    return result


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
