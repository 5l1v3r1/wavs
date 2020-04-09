import concurrent.futures
from modules.core.BaseModule import BaseModule

from util_functions import http_get_request
from util_functions import success, info, warning


class FileScanner(BaseModule):
    """
        This module saves its results in the following template:
            {
                 scan_id = # the current scans id,
                 files = [ # files found by scan ]
            }
    """
    info = {
        "name": "File Scanner",
        "db_table_name": "files_discovered",
        "wordlist_name": "file",
        "reportable": False,
        "desc": "Scans for files once ",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main):
        BaseModule.__init__(self, main)

    def generate_full_wordlist(self):
        """ generate a wordlist from the list of directories found, filenames
            from the files wordlist and extensions from config

            @return:    (list) - list of file paths in format:
                                    {directory}/{file}.{extension}
        """

        # get the main file wordlist
        filename_list = self.main.db.get_wordlist(self.info['wordlist_name'])

        # get the list of directories discovered
        dirs_discovered = self._get_previous_results('DirectoryScanner')

        # if there are no dirs found
        if not dirs_discovered:
            dirs_discovered.append('')

        exts = self.main.file_extensions

        final_list = []
        for directory in dirs_discovered:
            for file in filename_list:
                for extension in exts:
                    if directory != '':
                        path = f'{directory}/{file}.{extension}'
                    elif directory == '':
                        # extension already has . in it
                        path = f'{file}{extension}'

                    # we dont want to visit restricted paths
                    if path not in self.main.restrict_paths:
                        final_list.append(path)

        return final_list

    def _run_thread(self, path):
        """ makes a HTTP GET request to check if a file exists. to be used as
            a thread.

            :param directory:       the directory to search for files in
            :param word:            the file name to search for
            :return (list):         a list of found files
        """
        found_files = []

        # construct the url to be used in the GET request
        url = f'{self.main.get_host_url_base()}/'

        # make the GET request for the file
        resp = http_get_request(url + f'{path}', self.main.cookies)

        # check if the response code is a success code
        if (resp.status_code in self.main.success_codes):
            if self.main.options['verbose']:
                success(path, prepend='  ')

            found_files.append(path)

        # only return a list if files were actually found
        if found_files:
            return found_files

    def run_module(self):
        """ method that loads in a file wordlist and uses thread to search for
            the files

            :return:
        """
        info('Searching for files...')

        files_found = []

        wordlist = self.generate_full_wordlist()
        # debug wordlist
        # wordlist = ['index.php', 'contact.php', 'comments.php', 'about.html']
        with concurrent.futures.ProcessPoolExecutor() as executor:
            files_found += list(executor.map(self._run_thread, wordlist))

        # remove None results
        files_found = list(filter(None, files_found))
        files_found = [file for sublist in files_found for file in sublist]

        self._save_scan_results(files_found, update_count=False)
