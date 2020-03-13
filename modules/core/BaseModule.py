

class BaseModule:
    # marks a class as a module that can be loaded
    __wavs_mod__ = True

    # save information about the module
    info = {}

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

    def _get_previous_results(self):
        """ Gets scan results from modules which have run

            Override this.
        """
        pass

    def _save_scan_results(self, results):
        """ Saves a scans results to the scan database

            Override this.
        """
        pass

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

    def generate_report_section(self):
        """ This method is called when a report is being generated, it should
            take the results it has found and construct a report 'section' to
            be included in the report

            Override this.
        """
        pass
