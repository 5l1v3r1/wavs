import concurrent.futures
from multiprocessing import Pool

from util_functions import info, warning
from modules.core.InjectionScannerBase import InjectionScannerBase


class CrossSiteScripting_Reflected(InjectionScannerBase):
    """ This module is used to scan for cross site scripting.

        Inserts payloads into parameters, then checks the webpage for patterns
        which show target is vulnerable.

        Args:
            main:   instance of WebScanner
    """

    info = {
        "name":             "Cross Site Scripting - Reflected",
        "desc":             "Checks for cross site scripting vulnerabilities",
        "reportable":       True,
        "generate":         True,
        "db_table_name":    "xss_discovered_reflected",
        "wordlist_name":    "xss_injection",
        "author":           "@ryan_ritchie",
        "report": {
            "level":            "High",
            "vulnerability":    "Cross Site Scripting - Reflected",
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

    def run_module(self):
        """ Performs the actual scanning of the target application.

            Loads in the payloads, patterns and calls the _run_thread method
            to inject payloads into parameters.

            Args:
                None

            Returns:
                None
        """
        info("Searching for cross site scripting (reflected)...")

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
