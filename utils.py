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

from sqlite3 import Error

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
        module = importlib.import_module('{}.mod_{}'.format(package_name, class_name))

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

def http_get_request(url):
    try:
        r = requests.get(url)

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        warning(f'Server at {url} is not responding')
        return 1

    return r


###############################################################################
#                                                                             #
#                           PRINT UTIL FUNCTIONS                              #
#                                                                             #
###############################################################################

def _print_status(message, type):
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
        colour = Fore.BLUE
        status_code = '*'

    # TODO: sort this out ->
    if VERBOSITY or type == 'warning':
        print(colour + '[{}] {}'.format(status_code, message))

def success(message):
    _print_status(message, 'success')

def warning(message):
    _print_status(message, 'warning')

def info(message):
    _print_status(message, 'info')


###############################################################################
#                                                                             #
#                       DATABASE UTIL FUNCTIONS                               #
#                                                                             #
###############################################################################

DB_FILE = 'database/main.db'

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
        print(e)


def _db_get_data(connection, sql_select_statement):
    try:
        cursor = connection.cursor()
        cursor.execute(sql_select_statement)

        return cursor.fetchall()
    except Error as e:
        print(e)


def db_create_tables():
    """ create the necessary database tables needed for the web scanner to work

        :return:
    """

    # create a connection to the database
    c = db_get_connection(DB_FILE)

    # sql statement to create wordlist table
    sql_create_table_wordlist = """ CREATE TABLE IF NOT EXISTS directory (
                                        id integer PRIMARY KEY AUTOINCREMENT,
                                        word text NOT NULL,
                                        type text NOT NULL
                                    ); """

    # execute table creation statements
    db_execute_statement(c, sql_create_table_wordlist)

    # close the database connection
    c.close()


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


def db_wordlist_add_words(wordlist, words, group='general'):
    """ insert words into a wordlist table

        :param wordlist:    the wordlist to add the words to
        :param words:       the words to add to the wordlist
        :param group:       the group name of the words being added
        :return:
    """

    # create a connection to the database
    c = db_get_connection(DB_FILE)

    for word in words:
        sql_add_words = "INSERT INTO {}(word, type) VALUES('{}', '{}');".format(wordlist, word, group)
        print(sql_add_words)
        db_execute_statement(c, sql_add_words)

    c.close()


def __load_wordlist(wordlist_file):
    with open(wordlist_file, 'r') as f:
        wordlist = f.read()
        wordlist = wordlist.split('\n')
        wordlist = [word for word in wordlist if word]

    db_wordlist_add_words('directory', wordlist)
