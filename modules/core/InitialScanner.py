import requests
import requests.exceptions
import random
import string

from modules.core.BaseModule import BaseModule
from datetime import datetime
from util_functions import success, warning, info
from util_functions import http_get_request


class InitialScanner(BaseModule):
    info = {
        "name":         "Initial Scanner",
        "reportable":   False,
        "generate":     False,
        "desc":         "Does some initial scans on the web application to \
                         determine if its available, if it returns normal \
                         status codes etc",
        "author":        "@ryan_ritchie"
    }

    def __init__(self, main):
        BaseModule.__init__(self, main)

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
        resp = http_get_request(f'{self.main.get_host_url_base()}',
                                self.main.cookies)

        return resp is not None

    def _check_fuzzing(self):
        ''' checks if a random string returns a 200 success code.
            a 200 code would mean the web application is returning 200 for
            all requests.

            :param:
            :return:
        '''

        # construct a random string of length 10
        should_not_find = ''.join(
                                random.choice(string.ascii_lowercase)
                                for i in range(20))

        # make a get request with random string as a directory
        resp = requests.get(f'{self.main.get_host_url_base()}/'
                            f'{should_not_find}', self.main.cookies)

        # check for success code
        if resp.status_code == 200:
            warning(f'/{should_not_find} returned code 200. ')
            warning('Consider removing code 200 as success code')
            exit()

    def _parse_robots(self):
        # construct url for robots.txt
        url = f'{self.main.get_host_url_base()}/robots.txt'
        resp = http_get_request(url, self.main.cookies)

        dir_paths = []
        file_paths = []

        # checking is robots.txt exists
        if resp.status_code == 200:
            success('robots.txt found', prepend='  ')
            info('parsing robots.txt', prepend='  ')
            lines = resp.text.split('\n')

            # if there are no lines then theres nothing to do
            if not lines:
                return

            # loop through every line in robots.txt
            for line in lines:
                if line.startswith('Allow:') or line.startswith('Disallow:'):
                    path = line.split(': ')[1]
                    success(f'Found path: {path}', prepend='    ')

                    if not path:
                        continue

                    if path[:-1] == '/':
                        dir_paths.append(path)
                    else:
                        file_paths.append(path)

        if dir_paths:
            table = self.main.db.get_scan_db().table('directories_discovered')

            table.insert({
                "scan_id": self.main.id,
                "results": dir_paths
            })

        if file_paths:
            table = self.main.db.get_scan_db().table('files_discovered')

            table.insert({
                "scan_id": self.main.id,
                "results": file_paths
            })

    def run_module(self):
        info('Running initial scans...')

        if not self._is_server_up():
            exit()

        self._check_fuzzing()
        self._parse_robots()
