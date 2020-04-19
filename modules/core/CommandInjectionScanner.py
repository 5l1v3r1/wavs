import concurrent.futures
from util_functions import info, warning
from modules.core.InjectionScannerBase import InjectionScannerBase


class CommandInjectionScanner(InjectionScannerBase):
    """
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
        """
            @param main (WebScanner) - a webscanner object to share
                                        configuration between modules
        """
        InjectionScannerBase.__init__(self, main)

    def run_module(self):
        info("Searching for OS command injection...")

        # load in a list of lfi attach strings
        #self.attack_strings = self.main.db.get_wordlist(
        #    self.info['wordlist_name'])

        initial_attack_strings = ['whoami',
                               'python -c "print(\'os_com\' + \'mand_found\')"',
                               'VAR1="os_com";VAR2="mand_found";VAR3="$VAR1$VAR2";echo "$VAR3"']

        self.attack_strings = []
        for attack in initial_attack_strings:
            self.attack_strings.append(f'test;{attack}')
            self.attack_strings.append(f'test && {attack}')
            self.attack_strings.append(f'test || {attack}')

        # the search strings will be the attack strings themselves
        # because python will not interpret any javascript
        self.re_search_strings = ['www-data',
                                  'root',
                                  'nt-authority',
                                  'os_command_found'
                                  ]

        injectable_params = self._get_previous_results('HTMLParser')

        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = executor.map(self._run_thread, injectable_params)

        final = []
        for r in results:
            final.extend(r)

        # save the results
        self._save_scan_results(final)
