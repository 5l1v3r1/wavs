import concurrent.futures
from util_functions import info
from modules.core.InjectionScannerBase import InjectionScannerBase


class CommandInjectionScanner(InjectionScannerBase):
    """ A 'module' which scans for command injection vulnerabilies.

        This module injects payloads into parameters identified on the target
        application. It checks the resulting webpage for patterns which would
        match successful exploitation of the vulnerability.

        Args:
            main:   instance of the WebScanner object
    """

    info = {
        "name":             "Command Injection Scanner",
        "desc":             "Checks for OS command injection",
        "reportable":       True,
        "generate":         True,
        "db_table_name":    "os_injection_discovered",
        "wordlist_name":    "os_injection",
        "author":           "@ryan_ritchie",
        "report": {
            "level":            "High",
            "vulnerability":    "OS Command Injection",
            "description":
                "TODO: add description",
            "mitigation": [
                    "TODO: add mitigation"
                ],
            "link": "TODO: add link"
        }
    }

    def __init__(self, main):
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
        info("Searching for OS command injection...")

        # load in the attack strings
        initial_attack_strings = self.main.db.get_wordlist(
            self.info['wordlist_name'])

        self.attack_strings = []
        for attack in initial_attack_strings:
            self.attack_strings.append(f'test;{attack}')
            self.attack_strings.append(f'test && {attack}')
            self.attack_strings.append(f'test || {attack}')

        # the patterns to search the final page for
        self.re_search_strings = ['www-data',
                                  'root',
                                  'nt-authority',
                                  'os_command_found'
                                  ]

        # the parameters to inject payloads into
        injectable_params = self._get_previous_results('HTMLParser')

        # use multiple processes to inject payloads into parameters
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(self._run_thread, injectable_params)

        # put all the results into one list
        final = []
        for r in results:
            final.extend(r)

        # save the results
        self._save_scan_results(final)
