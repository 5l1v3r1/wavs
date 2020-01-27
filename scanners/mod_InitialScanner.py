import requests
import requests.exceptions
import random
import string

from datetime import datetime
from multiprocessing import Pool
from functools import partial

from utils import success, warning, info
from utils import db_get_wordlist
from utils import http_get_request

class InitialScanner:
    __wavs_mod__ = True

    info = {
        "name": "Initial scanner",
        "desc": "Does some initial scans on the web application to determine \
                 if its available, if it returns normal status codes etc",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main

        # seed the random number generator
        random.seed(datetime.now())

        self.options = {
            # the number of threads the directory scanner should use
            "numberOfThreads": 1
        }


    def _is_server_up(self):
        ''' checks if the server us up

            :param:
            :return (int): 0 - server is up and responding
                           1 - server is not responding
        '''
        resp = http_get_request(f'http://{self.main.host}:{self.main.port}', self.main.cookies)

        if resp == 1:
            return 1
        else:
            return 0


    def _check_fuzzing(self):
        ''' checks if a random string returns a 200 success code.
            a 200 code would mean the web application is returning 200 for
            all requests.

            :param:
            :return:
        '''

        # construct a random string of length 10
        should_not_find = ''.join(random.choice(string.ascii_lowercase) for i in range(20))

        # make a get request with random string as a directory
        resp = requests.get('http://{}:{}/{}'.format(self.main.host, self.main.port, should_not_find), self.main.cookies)

        # check for success code
        if resp.status_code == 200:
            warning('/{} returned code 200. Should switch to fuzzing'.format(should_not_find))
            return 1

        # TODO: switch to fuzzing mode?
        return 0

    def _run_thread(self):
        pass

    def run_module(self):
        checks = 0

        if self._is_server_up():
            exit()

        checks += self._check_fuzzing()

        if checks:
            warning('Scanning cannot continue, check error messages')
            exit()
