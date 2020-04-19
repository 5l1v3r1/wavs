import concurrent.futures
from multiprocessing import Pool
from modules.core.BaseModule import BaseModule

from util_functions import success, warning, info


class CSRF(BaseModule):
    info = {
        "name": "Cross Site Request Forgery",
        "reportable": True,
        "generate": True,
        "db_table_name": "csrf_discovered",
        "wordlist_name": "csrf",
        "desc": "Searches for the lack of anti-csrf tokens in forms",
        "author": "@ryan_ritchie",
        "report": {
            "level":            "Low",
            "vulnerability":    "Absence of anti-CSRF tokens",
            "description":
                "No anti-CSRF tokens where found in a form. Anti-CSRF tokens "
                "protect against cross site request forgery (CSRF) attacks. CSRF "
                "is an attack which exploits a user's session by making the user "
                "send an HTTP request to the target application without their "
                "consent. The request will then perform whatever action the "
                "attacker wants, with the users privileges.",
            "mitigation": [
                    "- Generate a non-predictable token for each form, and verify the token is correct upon form submission.",
                    "- Make sure the application is not vulnerable to cross site scripting (XSS), as XSS can bypass anti-CSRF protections.",
                    "- Use an application framework which provides built-in anti-CSRF functionality."
                ],
            "link": "https://cwe.mitre.org/data/definitions/352.html"
        }
    }

    def __init__(self, main):
        BaseModule.__init__(self, main)

    def _run_thread(self, form):
        """ search through form parameters to find anti-csrf tokens
        """
        if len(form) != 3:
            warning('Internal error, not enough form elements in CSRF')
            exit()

        # give the form data human friendly names
        method = form['method']
        page = form['action']
        params = form['params']

        # were only concerned with POST requests for CSRF
        if method == 'POST':

            # check if param names contain any anti-csrf token params
            if not any(csrf_name in params for csrf_name in self.csrf_fields):
                success(f'No anti-csrf tokens for: {page}/{",".join(params)}',
                        prepend='  ')
                return {'method': method,
                        'page': page,
                        'parameter': params,
                        'payload': None}

    def run_module(self):
        """ method that loads in a file wordlist and uses thread to search for
            the files

            :return:
        """

        info('Searching for CSRF...')

        self.csrf_fields = self.main.db.\
            get_wordlist(self.info['wordlist_name'])

        forms_discovered = self._get_previous_results('HTMLParser')

        # create the threads
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = list(executor.map(self._run_thread, forms_discovered))

        # remove any empty results
        results = list(filter(None, results))
        self._save_scan_results(results, update_count=False)
