import concurrent.futures
from util_functions import info, warning, http_get_request, http_post_request, success
from multiprocessing import Pool
from modules.core.BaseModule import BaseModule


class SQLInjectionScanner_Blind(BaseModule):
    """ This module tests a web application for the SQL injection vulnerability
        it does this by injecting SQL 'attack' strings into parameters and
        checking the resulting webpage for SQL error messages.

        @depends on: HTMLParser
            - this module requires the HTMLParser module to be run before it
              so that it has a list of injectable parameters

        TODO: need to test for blind SQL attacks
    """

    info = {
        "name":             "SQL Injection Scanner - Blind",
        "desc":             "Scan the web application for blind SQL injections",
        "reportable":       True,
        "db_table_name":    "sql_blind_injection",
        "wordlist_name":    "",
        "author":           "@ryan_ritchie",
        "report": {
            "level":            "High",
            "vulnerability":    "SQL Injection - Blind",
            "description":
                "An SQL injection is when malicious SQL statements are "
                "inserted into input parameters in an application with the "
                "intention that the SQL is executed and perform some action "
                "on the applications database that the developer did not "
                "intend. SQL injections arise when user input is incorrectly "
                "filtered.",
            "mitigation": [
                "- Treat all user inputs as malicious",
                "- Use prepared statements if available for DBMS",
                "- Never concatenate user input into SQL queries",
                "- Escape all input received from users",
                "- Use a whitelist of allowed characters, reject all else",
                "- Use a low privilege database user if possible",
            ],
            "link": "https://cwe.mitre.org/data/definitions/89.html"
        }
    }

    def __init__(self, main):
        BaseModule.__init__(self, main)

    def _construct_get_url(self, page, params):
        url = f'{self.main.get_host_url_base()}/{page}?'

        # http://localhost:80/index.php?username=test&password=test&submit=submit

        for param in params:
            url += f'{param}=test&'

        # remove the last &
        url = url[:-1]

        return url

    def _construct_post_params(self, params):
        param_dict = {}
        for p in params:
            param_dict[p] = 'test'

        return param_dict

    def _run_thread(self, param):
        method = param['method']
        page = param['action']

        self.injections = []
        self.injectable_params = []
        inject_params = param['params']

        assert(hasattr(self, "attack_strings"))
        attack_strings = self.attack_strings

        if method == 'GET':
            url = self._construct_get_url(page, inject_params)

            for p in inject_params:
                for injection in attack_strings:
                    resp = http_get_request(url, self.main.cookies)
                    normal_time = resp.elapsed

                    final_url = url.replace(f'{p}=test', f'{p}={injection}')
                    resp = http_get_request(final_url, self.main.cookies)
                    test_time = resp.elapsed

                    check_time = test_time - normal_time
                    if check_time.total_seconds() >= 5.0:
                        if self.main.options['verbose']:
                            success(f'Vulnerable parameter: {page} - {param} ({injection})',
                                    prepend='  ')
                        # self.injectable_params.append((page, param, injection))
                        self.injectable_params.append({'method': method,
                                                       'page': page,
                                                       'parameter': param,
                                                       'payload': injection})

        elif method == 'POST':
            # construct the url to make the request to
            url = f'{self.main.get_host_url_base()}/{page}'

            for p in inject_params:
                params = self._construct_post_params(inject_params)

                for injection in attack_strings:
                    resp = http_post_request(url, params, self.main.cookies)
                    normal_time = resp.elapsed

                    params[p] = injection
                    resp = http_post_request(url, params, self.main.cookies)
                    test_time = resp.elapsed

                    check_time = test_time - normal_time
                    if check_time.total_seconds() >= 5.0:
                        if self.main.options['verbose']:
                            success(f'Vulnerable parameter: {page} - {param} ({injection})',
                                    prepend='  ')
                        # self.injectable_params.append((page, param, injection))
                        self.injectable_params.append({'method': method,
                                                       'page': page,
                                                       'parameter': param,
                                                       'payload': injection})

        return self.injectable_params

    def run_module(self):
        info('Searching for SQL blind injections...')

        # get the injectable params
        params = self._get_previous_results('HTMLParser')
        # self.attack_strings = self.main.db.get_wordlist(
        #    self.info['wordlist_name'])

        self.attack_strings = ["1' OR sleep(5)-- -", "test' OR sleep(5)-- -"]

        # pass them off to threads
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = list(executor.map(self._run_thread, params))

        final = []
        for r in results:
            final.extend(r)
        self._save_scan_results(final)
