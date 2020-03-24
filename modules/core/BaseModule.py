from tinydb import where
from util_functions import load_module, warning


class BaseModule:
    # marks a class as a module that can be loaded
    __wavs_mod__ = True

    def __init__(self, main):
        # save a reference to the WebScanner object
        self.main = main

    def generate_text(self):
        """ use generative model to generate a wordlist based upon a wordlist's
            default wordlist
        """
        # load in text to be trained
        text_list = self.main.db.get_wordlist(self.info['wordlist_name'])

        # generate a list of words based on training text
        generated_list = self.main.text_generator.generate(text_list)

        # save generated list to be run on next scan
        self.main.db.save_generated_text(generated_list,
                                         self.info['wordlist_name'])

    def _get_previous_results(self, module_name):
        """ loads in results from previous scans, should be overwritten to load
            in specific results needed for this module
        """
        module = load_module("modules.core", module_name)

        if not module:
            warning(f'Could not find module {module_name}')
            exit()
        table_name = module.info['db_table_name']

        table = self.main.db.get_scan_db().table(table_name)
        results = table.search(where('scan_id') == self.main.id)

        final = []
        for r in results:
            final.extend(r['results'])

        return final

    def _save_scan_results(self, results, update_count=True):
        table = self.main.db.get_scan_db().table(self.info['db_table_name'])

        table.insert({
            "scan_id": self.main.id,
            "results": results
        })

        if update_count:
            # update wordlist count for successful words
            self.main.db.update_count(results, self.info['wordlist_name'])

    def _run_thread(self):
        """ This method should be run as a thread, using multiprocessing

            Override this.
        """
        pass

    def run_module(self):
        """ This method is called by the WebScanner object when a scan is run.
            The scan logic should be implemented here.

            Override this.
        """
        pass

    def get_report_data(self, scan_id=None):
        """ This method is called when a report is being generated, it should
            take the results it has found and construct a report 'section' to
            be included in the report

            Override this.
        """
        if self.info['reportable']:
            table_name = self.info['db_table_name']
        else:
            return

        table = self.main.db.get_scan_db().table(table_name)

        if not scan_id:
            scan_id = self.main.id
        results = table.search(where('scan_id') == scan_id)

        final = []
        for r in results:
            final.extend(r['results'])

        if len(final) == 0:
            return None

        return {'module': self.info['name'],
                'results': final,
                'report': self.info['report']}
