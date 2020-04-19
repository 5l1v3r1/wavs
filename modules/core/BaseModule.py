from tinydb import where
from util_functions import load_module, warning


class BaseModule:
    """ Root class for vulnerability scanning modules.

        This class is intended to be inherited by every vulnerability scanning
        module class. It implements functionality common to all vulnerability
        scanning modules.

        Args:
            main:   instance of the WebScanner
    """
    # marks a class as a module that can be loaded
    __wavs_mod__ = True

    def __init__(self, main):
        # save a reference to the WebScanner object
        self.main = main

    def generate_text(self):
        """ use generative model to generate a wordlist based upon a wordlist's
            default wordlist

            Args:
                None
            Returns:
                None
        """
        if not self.info['generate']:
            return

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

            Args:
                module_name:    name of the module to load results from
            Returns:
                a list of results from a module
        """
        # modules should be located in the modules.core package
        module = load_module("modules.core", module_name)

        # if the module didnt load
        if not module:
            warning(f'Could not find module {module_name}')
            exit()

        # get the modules table name
        table_name = module.info['db_table_name']

        # get the contents of the table
        table = self.main.db.get_scan_db().table(table_name)

        # get the results for this scan
        results = table.search(where('scan_id') == self.main.id)

        # put all the results into one list
        final = []
        for r in results:
            final.extend(r['results'])

        return final

    def _save_scan_results(self, results, update_count=True):
        """ Saves the scan results of the module into the scans database.

            Args:
                results:        a list of results from the module
                update_count:   whether to update the count in wordlist db

            Returns:
                None
        """
        # get the table for this module in the scans db
        table = self.main.db.get_scan_db().table(self.info['db_table_name'])

        # insert the results into the db
        table.insert({
            "scan_id": self.main.id,
            "results": results
        })

        if update_count:
            # update wordlist count for successful payloads
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

            Args:
                scan_id:    unique identifier of the scan

            Returns:
                a dict containing data for the report,
                None if the module had no results
        """
        # if this module is reportable
        if self.info['reportable']:
            # get the table name for scans db
            table_name = self.info['db_table_name']
        else:
            # if not reportable then just get out of here
            return

        # get the table for this module from scans db
        table = self.main.db.get_scan_db().table(table_name)

        # if the scan id was not provided we use this scan's id
        if not scan_id:
            scan_id = self.main.id

        # get the results of this module
        results = table.search(where('scan_id') == scan_id)

        # put all the resutls in one list
        final = []
        for r in results:
            final.extend(r['results'])

        # if the module had no results return None
        if len(final) == 0:
            return None

        return {'module': self.info['name'],
                'results': final,
                'report': self.info['report']}
