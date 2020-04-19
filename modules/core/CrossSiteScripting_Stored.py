import concurrent.futures
from multiprocessing import Pool

from util_functions import info, warning, http_get_request, http_post_request
from modules.core.InjectionScannerBase import InjectionScannerBase


class CrossSiteScripting_Stored(InjectionScannerBase):
    """ This module is used to scan for cross site scripting.

        Inserts payloads into parameters, then checks the webpage for patterns
        which show target is vulnerable.

        Args:
            main:   instance of WebScanner
    """

    info = {
        "name":             "Cross Site Scripting - Stored",
        "desc":             "Checks for cross site scripting vulnerabilities",
        "reportable":       True,
        "generate":         True,
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
        """ Checks for stored XSS by inserting a payload into parameter,
            checking the payload exists on the resulting webpage, then makes
            a request again to see if the payload still exists. If the payload
            is still on the webpage it is assumed to be vulnerable.

            Args:
                param:  the parameter to inject payloads into

            Returns:
                a dict containing details about a vulnerable parameter
        """
        # the HTTP method for the request
        method = param['method'].upper()

        # the webpage for the request
        page = param['action']

        self.injections = []
        self.injectable_params = []

        # the parameters to inject into
        inject_params = param['params']

        assert(hasattr(self, "attack_strings"))
        attack_strings = self.attack_strings

        if method == 'GET':
            url = self._construct_get_url(page, inject_params)

            # loop through each injectable parameter
            for p in inject_params:

                # loop through each payload
                for injection in attack_strings:
                    # inject the payload into the parameter
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

            # loop through each parameter
            for p in inject_params:
                params = self._construct_post_params(inject_params)

                # loop through each payload
                for injection in attack_strings:
                    # inject the payload into the parameter
                    params[p] = injection

                    # make the first request with the payload
                    first = http_post_request(url, params, self.main.cookies)

                    # make a normal request without payload
                    second = http_post_request(url, {}, self.main.cookies)

                    # check if the payload still exists after second request
                    if self._check_page_content(
                        method,
                        injection,
                        p,
                        page,
                        second.text):
                        break

        return self.injectable_params

    def run_module(self):
        """ Loads the attack strings from the database, and runs multiple
            processes

            Args:
                None

            Returns:
                None
        """
        info("Searching for cross site scripting (stored)...")

        # load in the payloads
        self.attack_strings = self.main.db.get_wordlist(
            self.info['wordlist_name'])

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
