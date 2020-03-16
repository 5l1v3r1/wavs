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
        "name": "Local File Inclusion",
        "desc": "Checks for local file inclusion vulnerability",
        "reportable": True,
        "db_table_name": "lfi_discovered",
        "wordlist_name": "lfi_injection",
        "author": "@ryan_ritchie"
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
