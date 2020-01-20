from utils import success, warning, info
from utils import db_get_wordlist

class DirectoryScanner:
    def __init__(self, main, options=None):
        self.info = {
            "name": "Directory Scanner",
            "desc": "Scans a web application for directories",
            "author": "@ryan_ritchie"
        }

        self.options = {
            # the number of threads the directory scanner should use
            "numberOfThreads": 8
        }

    def _run(self):
        start_time = datetime.now()
        info('Starting scan on {}:{} at {}'.format(self.host, self.port, datetime.strftime(start_time, '%d/%b/%Y %H:%M:%S')))

        # check if application returns 200 for random string
        # TODO: move this into a scan method
        #self._check_wrong_200()

        # create the threads
        # TODO: allow the user to change number of threads
        thread_pool = Pool(self.options['numberOfThreads'])

        # load in the wordlist from database
        word_list = db_get_wordlist('directory', 'general')

        # add an empty string so that the root directory is scanned
        word_list.append('')

        # map the wordlist to threads with _thread_scan method
        directories_found = thread_pool.map(self._thread_dir_scan, word_list)

        # remove None results
        directories_found = [directory for directory in self.directories_found if directory != None]

        # close the threads
        thread_pool.close()
        thread_pool.join()

        main.directories_found = directories_found

        end_time = datetime.now()
        info('Directory search completed. Elapsed: {}'.format(end_time - start_time))
