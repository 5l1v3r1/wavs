import sqlite3
import os.path
from sqlite3 import Error
from datetime import datetime
from util_functions import warning, success
from tinydb import TinyDB, Query
# TODO: use prepared statements for SQL


class DBManager:
    """ manages all database operations carried out by the program, and
        provides some utility functions
    """

    def __init__(self):
        self.db_paths = {}

        # test db
        self.db_paths['wordlist'] = 'database/wordlists_test.db'

        # production db
        # self.db_paths['wordlist'] = 'database/wordlists_prod.db'

        # the database to hold scan results
        self.db_paths['scan_results'] = 'database/scans.db'

        # the 'wordlist' database is required for the program to function
        # so if it cant be found the program should warn and exit
        if not os.path.exists(self.db_paths['wordlist']):
            warning(f'Could not find wordlist database at: '
                    f'{self.db_paths["wordlist"]}')
            exit()

        # if the scans database doesn't exist then create it
        # self.scan_db = TinyDB(self.db_paths['scan_results'])

    def get_scan_db(self):
        return TinyDB(self.db_paths['scan_results'])

    def scan_exists(self, scan_id):
        scan_table = self.get_scan_db().table('scans')
        return scan_table.contains(doc_ids=[scan_id])

    def save_new_scan(self, scan_object):
        """ called each time a new scan is run, saves details about the scan
            and returns a unique scan id to identify the scan
            @param:     scan_object         - a WebScanner instance
        """

        # get the current time
        scan_start = str(datetime.now())

        # insert initial scan data into db, insert returns document id
        scans_table = self.get_scan_db().table('scans')
        id = scans_table.insert({
            'timestamp': scan_start,
            'host': scan_object.host,
            'port': scan_object.port
        })

        return id

    def reset_scans(self):
        scans = self.get_scan_db()
        scans.purge_tables()

        success('scans database has been reset successfully', prepend='  ')

    def reset_wordlist(self):
        conn = self.get_connection(self.db_paths['wordlist'])

        sql_statement = 'UPDATE wordlist SET count = 0 WHERE count > 0'
        self.execute_statement(conn, sql_statement)

        success('wordlist database has been reset successfully', prepend='  ')

    def get_connection(self, database_file):
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

    def execute_statement(self, connection, sql_statement):
        """ execute a sql statement on the database represented by the
            connection object

            :param connection:      a sqlite3 database connection
            :param sql_statement:   sql to be executed on the database
            :return:
        """

        try:
            cursor = connection.cursor()
            cursor.execute(sql_statement)
            connection.commit()
        except Error as e:
            print('sql error')
            print(e)

    def create_table(self, sql_statement):
        """ creates a table in the scan results database using a supplied sql
            statement

            @param:     sql_statement       - a SQL statement that creates a
                                              table
            @return:    None
        """
        connection = self.get_connection(self.db_paths['scan_results'])
        self.execute_statement(connection, sql_statement)

    def table_exists(self, table_name):
        """ checks if a table named [table_name] exists within the scan_results
            database

            @param:     table_name      - a table name to be checked
            @return:    True            - if table exists
                        False           - if table does not exist
        """
        connection = self.get_connection(self.db_paths['scan_results'])

        try:
            cursor = connection.cursor()

            # a SQL query which checks if the table exists
            sql_check_tbl_exists = ('SELECT name '
                                    'FROM sqlite_master '
                                    'WHERE type="table" '
                                    'and name=?;')
            cursor.execute(sql_check_tbl_exists, (table_name))

            # if fetched rows is more than 0 the table exists
            if len(cursor.fetchall()) > 0:
                return True

            return False
        except Error:
            return False

    def get_data(self, connection, sql_select_statement):
        """ retrieves data from a database connection and returns it

            @param:     connection              - a sqlite3 database connection
            @param:     sql_select_statement    - sql select statement

        """
        try:
            cursor = connection.cursor()
            cursor.execute(sql_select_statement)

            return cursor.fetchall()
        except Error as e:
            print(e)

    def get_wordlist(self, type):
        """ load a wordlist from the database

            :param wordlist_name:   the name of the wordlist, and table name
            :param group_name:      the name of a group of words to be selected
            :return (list):
        """
        c = self.get_connection(self.db_paths['wordlist'])

        wordlist = []

        # add any generated text to the retrieved wordlist
        cursor = c.cursor()
        if self.table_exists('generated_text'):
            cursor.execute('SELECT payload FROM generated_text WHERE type=?',
                           type)

            data = cursor.fetchall()

            # db returns data as a list of tuples, this 'flattens' the list
            wordlist = [row[0] for row in data if row]

        # select the wordlist of a specific type from the database
        sql_get_wordlist = ('SELECT payload '
                            'FROM "wordlist" '
                            f'WHERE type = "{type}" '
                            'ORDER BY "count" DESC;')

        # retrieve the wordlist data
        result = self.get_data(c, sql_get_wordlist)

        # flatten the retrieved data into a list and add it to any generated
        # text that was retrived in previous operation
        wordlist.extend([row[0] for row in result])

        return wordlist

    def get_detect_wordlist(self, type):
        """ retrieves wordlists from the 'detect' table, which contains
            wordlists used to detect positive outcomes of some scans such as
            SQL injections. The program will search for these 'detection'
            strings in the text of retrieved webpages.

            @param:     type        - the type of wordlist to retrieve
        """
        c = self.get_connection(self.db_paths['wordlist'])

        # sql query to retrieve a wordlist of a specific type
        sql_get_wordlist = (f'SELECT detect_string '
                            f'FROM "detect" '
                            f'WHERE type = "{type}"')

        # retrieving the data from the database using sql query
        result = self.get_data(c, sql_get_wordlist)

        # flatten the returned list
        wordlist = [row[0] for row in result]

        return wordlist

    def save_generated_text(self, generated_text, type):
        """ saves wordlists generated by the TextGenerator class into a
            new table called 'generated_text'

            @param:     generated_text      - a list of words generated by
                                              TextGenerator class
            @param:     type                - the type of wordlist generated
        """
        conn = self.get_connection(self.db_paths['wordlist'])
        cursor = conn.cursor()

        # loop through each word in the generated list
        for text in generated_text:
            # insert the word into the table
            cursor.execute('INSERT INTO generated_text(text, type) '
                           'VALUES(?, ?);', (text, type))

        # save changes to the database
        conn.commit()
        conn.close()

    def add_if_not_exist(self, cursor, payload, type):
        """ adds a payload to the wordlist table if the payload does not exist

            @param:     cursor          - a sqlite3 cursor connected to
                                          wordlist db
            @param:     payload         - the word to add to wordlist
            @param:     type            - the wordlist type

            @return:    True            - if payload was added to table
                        False           - if payload was not added to table

        """
        # sql to check if the payload exists in the wordlist table
        cursor.execute('SELECT id '
                       'FROM wordlist '
                       'WHERE type = ? '
                       'AND payload = ?;', (type, payload))
        check = cursor.fetchone()

        # if the payload does not exist, add it to the wordlist
        # check will be None if it doesn't exist in table
        if not check:
            cursor.execute('INSERT INTO wordlist(payload, type, count)'
                           'VALUES(?, ?, ?)', (payload, type, 1))
            return True
        else:
            return False

    def update_count(self, payloads, type):
        """ updates the count of words in the wordlist when they successfully
            find something

            @param:     payloads        - a list of words that were successful
            @param:     type            - the type of wordlist the payloads
                                          belong to
        """
        try:
            conn = self.get_connection(self.db_paths['wordlist'])
            cursor = conn.cursor()

            # TODO: add ability to set a custom wordlist

            # loop through each payload
            for payload in payloads:

                # add_if_not_exist will return True if payload was added to
                # the table, so we dont want to update the count then
                if not self.add_if_not_exist(cursor, payload, type):
                    cursor.execute('UPDATE wordlist '
                                   'SET count = count + 1 '
                                   'WHERE type = ? '
                                   'AND payload = ?;', (type, payload))

            conn.commit()
            conn.close()
        except Error as e:
            print('SQL Error')
            print(e)

    def remove_generated_text(self):
        """ once generated text has been used in a scan it should be removed,
            any text successful in finding something in a scan will already
            be stored in wordlist table
        """
        if self.table_exists('generated_text'):
            conn = self.get_connection(self.db_paths['wordlist'])
            cursor = conn.cursor()

            cursor.execute('DROP TABLE generated_text;')
            conn.commit()
            conn.close()
