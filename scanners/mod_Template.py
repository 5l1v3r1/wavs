import requests

from datetime import datetime
from multiprocessing import Pool
from functools import partial

from utils import success, warning, info
from utils import db_get_wordlist
from utils import http_get_request

class ScannerTemplate:
    __wavs_mod__ = True

    info = {
        "name": "",
        "desc": "",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main, options=None):
        self.main = main



        self.options = {
            # the number of threads the directory scanner should use
            "numberOfThreads": 8
        }

    def _run_thread(self):
        pass

    def run_module(self):
        pass
