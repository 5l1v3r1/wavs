import concurrent.futures
from multiprocessing import Pool

from util_functions import info, warning
from modules.core.InjectionScannerBase import InjectionScannerBase


class CrossSiteScripting(InjectionScannerBase):
    """ This module is used to scan for local file inclusions, it does this by
        inserting file paths in parameters and checking the resulting page to
        see if the file contents are on the page.
    """

    info = {
        "name":             "Cross Site Scripting",
        "desc":             "Checks for cross site scripting vulnerabilities",
        "reportable":       True,
        "db_table_name":    "xss_discovered",
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
            "mitigation":
                "- To prevent XSS assume that all user input is malicious.\n"
                "- Use a whitelist of acceptable inputs, reject anything "
                "  that does not conform to the whitelist.\n"
                "- Use a blacklist of known attack inputs to be alerted when "
                "  the application is being attacked, and consider banning "
                "  IPs that attacks originate from. \n"
                "- Make sure that validation performed on the client side is "
                "  also performed on the server side, as client side controls "
                "  can be bypassed.\n",
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
        info("Searching for cross site scripting...")

        # load in a list of lfi attach strings
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
