import concurrent.futures
from multiprocessing import Pool

from util_functions import info, warning
from modules.core.InjectionScannerBase import InjectionScannerBase


class LocalFileInclusion(InjectionScannerBase):
    """ This module is used to scan for local file inclusions, it does this by
        inserting file paths in parameters and checking the resulting page to
        see if the file contents are on the page.
    """

    info = {
        "name":             "Local File Inclusion",
        "desc":             "Checks for local file inclusion vulnerability",
        "reportable":       True,
        "db_table_name":    "lfi_discovered",
        "wordlist_name":    "lfi_injection",
        "author":           "@ryan_ritchie",
        "report": {
            "level":            "High",
            "vulnerability":    "Local File Inclusion",
            "description":
                "Most web programming languages allow the inclusion of files "
                "to extend the functionality of the file. If the application "
                "uses user input to determine the file that is included it "
                "could lead to unintentional information disclosure, and "
                "code execution if the attacker is able to upload files.",
            "mitigation": [
                    "- If the set of files that can be included is known, create a mapping between the files and numeric ids and reject all other inputs.",
                    "- If possible run the web application in a restricted 'sandbox' environment that restricts access to the underlying operating system.",
                    "- Use a whitelist of acceptable inputs and reject all other inputs.",
                    "- Reject directory seperator characters from input",
                    "- Do not rely exclusively on a filtering mechanism",
                    "- Use a web application firewall (WAP) which detects common attack strings and blocks them.",
                    "- Make sure you are using the latest versions of web frameworks and programming languages."
                ],
            "link": "http://cwe.mitre.org/data/definitions/98.html"
        }
    }

    def __init__(self, main):
        """
            @param main (WebScanner) - a webscanner object to share config
                                       between modules
        """
        InjectionScannerBase.__init__(self, main)

    def run_module(self):
        info("Searching for local file inclusions...")

        # load in a list of lfi attach strings
        self.attack_strings = self.main.db.get_wordlist(
            self.info['wordlist_name'])

        self.re_search_strings = self.main.db.\
            get_detect_wordlist('lfi')

        # load in params
        injectable_params = self._get_previous_results('HTMLParser')

        # create thread pool
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = list(executor.map(self._run_thread, injectable_params))

        final = []
        for r in results:
            final.extend(r)

        # save the results
        self._save_scan_results(final)
