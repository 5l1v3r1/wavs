import requests

from utils import success, warning, info
from utils import db_get_wordlist
from datetime import datetime
from multiprocessing import Pool
from functools import partial

class FileScanner:
    __wavs_mod__ = True

    def __init__(self, main, options=None):
        self.main = main

        self.info = {
            "name": "File Scanner",
            "desc": "Scans for files once ",
            "author": "@ryan_ritchie"
        }

        self.options = {
            # the number of threads the directory scanner should use
            "numberOfThreads": 8
        }

    def _parse_options(self, options):
        # parse the options
        return

    def _run_thread(self):
        return

    def _run_module(self):
        return
