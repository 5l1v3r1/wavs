import concurrent.futures
from multiprocessing import Pool

from util_functions import info, warning, http_get_request, http_post_request
from modules.core.InjectionScannerBase import InjectionScannerBase


class CrossSiteScripting_Stored(InjectionScannerBase):
    """
    """

    info = {
        "name":             "Cross Site Scripting - Stored",
        "desc":             "Checks for cross site scripting vulnerabilities",
        "reportable":       True,
        "db_table_name":    "xss_discovered_stored",
        "wordlist_name":    "xss_injection",
        "author":           "@ryan_ritchie",
        "report": {
            "level":            "High",
            "vulnerability":    "Cross Site Scripting - Stored",
            "description":
                "Cross-site scripting (XSS) is when attacker supplied scripting "
                "code is injected into a user's browser. This can happen "
                "when user provided data is not sanitised. When an attackers "
                "code is executed the code could hijack a user's account "
                "by stealing cookies, the browser could be redirected to a "
                "different website or the content of the website could be "
                "changed.",
            "mitigation": [
                    "- To prevent XSS assume that all user input is malicious.",
                    "- Use a whitelist of acceptable inputs, reject anything that does not conform to the whitelist.",
                    "- Use a blacklist of known attack inputs to be alerted when the application is being attacked, and consider banning IPs that attacks originate from.",
                    "- Make sure that validation performed on the client side is also performed on the server side, as client side controls can be bypassed."
                ],
            "link": "https://cwe.mitre.org/data/definitions/79.html"
        }
    }

    def __init__(self, main):
        """
            @param main (WebScanner) - a webscanner object to share
                                        configuration between modules
        """
        InjectionScannerBase.__init__(self, main)

    def _run_thread(self, param):
        method = param['method'].upper()
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
                    final_url = url.replace(f'{p}=test', f'{p}={injection}')

                    # the first request sends the payload
                    first = http_get_request(final_url, self.main.cookies)

                    # the second request checks if the xss was stored
                    second = http_get_request(url, self.main.cookies)
                    if self._check_page_content(method, injection, p, page, second.text):
                        break

        elif method == 'POST':
            # construct the url to make the request to
            url = f'{self.main.get_host_url_base()}/{page}'

            for p in inject_params:
                params = self._construct_post_params(inject_params)

                for injection in attack_strings:
                    params[p] = injection

                    first = http_post_request(url, params, self.main.cookies)
                    second = http_post_request(url, {}, self.main.cookies)

                    if self._check_page_content(method, injection, p, page, second.text):
                        break

        return self.injectable_params

    def run_module(self):
        info("Searching for cross site scripting (stored)...")

        # load in a list of lfi attach strings
        #self.attack_strings = self.main.db.get_wordlist(
        #    self.info['wordlist_name'])

        self.attack_strings = ['<script>alert(1)</script>',
                               '<img srx="x" onerror="alert(1)>"']

        # the search strings will be the attack strings themselves
        # because python will not interpret any javascript
        self.re_search_strings = self.attack_strings

        injectable_params = self._get_previous_results('HTMLParser')

        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(self._run_thread, injectable_params)

        final = []
        for r in results:
            final.extend(r)

        # save the results
        self._save_scan_results(final)
