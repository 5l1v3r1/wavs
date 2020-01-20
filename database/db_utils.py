import sqlite3
from sqlite3 import Error


def create_database_connection(database_file):
    """ create the database connection to the sqlite database
    """

    connection = None
    try:
        connection = sqlite3.connect(database_file)
    except Error as e:
        print(e)
    finally:
        if connection:
            connection.close()
