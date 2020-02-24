import sqlite3
from sqlite3 import Error
from datetime import datetime

class DBManager:
    def __init__(self):
        self.db_paths = {}
        self.db_paths['attack_strings'] = 'database/main.db'
        self.db_paths['scan_results'] = 'database/scans.db'


    def db_get_connection(self, database_file):
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


    def db_create_table(self, sql_statement):
        connection = self.db_get_connection(self.db_paths['scan_results'])
        self.db_execute_statement(connection, sql_statement)


    def db_execute_statement(self, connection, sql_statement):
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


    def _db_get_data(self, connection, sql_select_statement):
        try:
            cursor = connection.cursor()
            cursor.execute(sql_select_statement)

            return cursor.fetchall()
        except Error as e:
            print(e)


    def db_table_exists(self, table_name):
        connection = self.db_get_connection(self.db_paths['scan_results'])

        try:
            cursor = connection.cursor()
            sql_check_tbl_exists = f'SELECT name FROM sqlite_master WHERE type="table" and name="{table_name}"'
            cursor.execute(sql_check_tbl_exists)
            if len(cursor.fetchall()) > 0:
                return True

            return False
        except Error as e:
            print(e)

    def db_get_wordlist(self, wordlist_name, group_name):
        """ load a wordlist from the database

            :param wordlist_name:   the name of the wordlist, also the table name
            :param group_name:      the name of a group of words to be selected
            :return (list):
        """
        c = self.db_get_connection(self.db_paths['attack_strings'])

        sql_get_wordlist = "SELECT word FROM '{}' WHERE type = '{}'".format(wordlist_name, group_name)

        result = self._db_get_data(c, sql_get_wordlist)
        wordlist = [row[0] for row in result]

        return wordlist

    def db_get_wordlist_generic(self, table_name, column_names, filter=None):
        """

            @param column_names -   a string list, separated by commas
            @param filter -         a tuple (column_name, criteria)
        """
        c = self.db_get_connection(self.db_paths['attack_strings'])

        if not filter:
            sql_get_wordlist = f"SELECT {column_names} FROM '{table_name}'"
        else:
            sql_get_wordlist = f"SELECT {column_names} FROM '{table_name}' WHERE {filter[0]} = '{filter[1]}'"

        result = self._db_get_data(c, sql_get_wordlist)

        return result


    def db_wordlist_add_words(self, wordfile, table_name, words, group='general'):
        """ insert words into a wordlist table

            :param wordlist:    the wordlist to add the words to
            :param words:       the words to add to the wordlist
            :param group:       the group name of the words being added
            :return:
        """

        # create a connection to the database
        c = self.db_get_connection(self.db_paths['attack_strings'])

        words = []
        with open(wordfile, 'r') as f:
            for line in f:
                words.append(line)

        for word in words:
            sql_add_words = f"INSERT INTO {table_name}(injection_string, type) VALUES('{word}', '{group}');"
            self.db_execute_statement(c, sql_add_words)

        c.close()


    def save_new_scan(self, scan_object):
        conn = self.db_get_connection(self.db_paths['scan_results'])

        scan_start = str(datetime.now())
        sql_new_scan = (f"INSERT INTO scans(timestamp, host, port)"
                        f" VALUES('{scan_start}',"
                               f"'{scan_object.host}',"
                               f"'{scan_object.port}')")

        self.db_execute_statement(conn, sql_new_scan)

        sql_get_id = f"SELECT id FROM scans ORDER BY id DESC LIMIT 0, 1"
        result = self._db_get_data(conn, sql_get_id)

        # result is a list containing a tuple
        return result[0][0]


    def save_scan_results(self, scan_id, table_name, table_columns, results):
        conn = self.db_get_connection(self.db_paths['scan_results'])

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
            self.db_execute_statement(conn, sql_save_results)

        conn.close()


    def load_scan_results(self, scan_id, column_names, table_name):
        ''' load scan results from previous modules, from the database.

            @param:     scan_id (int)           - the scan id to be loaded
            @param:     column_names (string)   - the column names to load. multiple
                                                  columns delimited with commas
            @param:     scan_name (string)      - the name of the scan module

            @return:    (list) the scan results
        '''
        conn = self.db_get_connection(self.db_paths['scan_results'])

        # the SQL query to get the scan results
        sql_load_scan = f'SELECT {column_names} FROM {table_name} WHERE scan_id={scan_id}'

        # execute the query and get results
        result = self._db_get_data(conn, sql_load_scan)

        # convert the returned tuple to a list
        #results = [r[0] for r in result]
        conn.close()

        return result
