#/usr/bin/python3

# author:       Ryan Ritchie
# student no:   17019225
# email:        ryan2.ritchie@live.uwe.ac.uk
# file:         wavs.py

# core imports
import os
import sys
import json
import requests
import argparse
import unittest

from datetime import datetime
from functools import partial
from multiprocessing import Pool

# my imports
from util_functions import load_module
from util_functions import cookie_parse
from util_functions import success, warning, info, banner_colour
from utils.DBManager import DBManager


# global constants
CONFIG_FILE_PATH = 'conf/config.json'

# argument parsing
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('host', help='The url of the web application to be scanned')
arg_parser.add_argument('--port', type=int, default=0, help='The port the web application is running on')
arg_parser.add_argument('--cookies', help='Cookies to be included in requests, <cookie_name>=<cookie_value>,[...]')
arg_parser.add_argument('--restrict_paths', default='', help='Paths which should not be visited, /restrict/path/1,/restrict/path/2')
arg_parser.add_argument('--scan_type', default='default', help='The type of scan to run. Determines which modules run and in what order.')
arg_parser.add_argument('--generator', default=False, help='Runs the attack string text generator')
arg_parser.add_argument('--manual_crawl', default=False, help='Use a proxy to manually crawl the target')
args = arg_parser.parse_args()

# TODO: make sure that modules that depend on previous results handle the lack
#       of those results graciously

class WebScanner():
    def __init__(self, arg_parse):
        # check that protocol is supplied
        if arg_parse.host[:4] != 'http':
            warning('Please specify the protocol for host, either http or https')
            exit()

        # split the host into protocol and ip/hostname
        self.proto, self.host = arg_parse.host.split('://')
        self.proto += '://'

        # if no port is specified then set port based on protocol
        if arg_parse.port == 0:
            if self.proto == 'http://':
                self.port = 80
            elif self.proto == 'https://':
                self.port = 443
        else:
            self.port = arg_parse.port

        self.cookies = cookie_parse(arg_parse.cookies)
        self.scan_type = arg_parse.scan_type

        if arg_parse.restrict_paths:
            if ',' in arg_parse.restrict_paths:
                self.restrict_paths = arg_parse.restrict_paths.split(',')
            else:
                self.restrict_paths = [arg_parse.restrict_paths]
        else:
            self.restrict_paths = None

        # TODO: add way to change success codes
        self.success_codes = [200, 201, 202, 203, 204, 301, 302, 303, 304]
        self.file_extensions = ['.html', '.php']
        self.options = {}
        self.modules = []
        self.scan_types = []

        self.db = DBManager()

        # save the scan in the database
        self.id = self.db.save_new_scan(self)

        self.options['manual_crawl'] = arg_parse.manual_crawl
        self.load_config()
        self._banner()

        if arg_parse.generator:
            self.run_text_generation()
        else:
            self.run_modules()

    def get_host_url_base(self):
        return f'{self.proto}{self.host}:{self.port}'

    def _banner(self):
        banner = """
`7MMF'     A     `7MF' db `7MMF'   `7MF'.M'''bgd
  `MA     ,MA     ,V  ;MM:  `MA     ,V ,MI    "Y
   VM:   ,VVM:   ,V  ,V^MM.  VM:   ,V  `MMb.
    MM.  M' MM.  M' ,M  `MM   MM.  M'    `YMMNq.
    `MM A'  `MM A'  AbmmmqMA  `MM A'   .     `MM
     :MM;    :MM;  A'     VML  :MM;    Mb     dM
      VF      VF .AMA.   .AMMA. VF     P"Ybmmd"

Web Application Vulnerability Scanner by Ryan Ritchie
        """
        if self.options['display_banner']:
            banner_colour(banner)

    def load_config(self):
        # the config file is needed for the program to run, so if it cant
        # be found the program will warn the user and exit
        if not os.path.exists(CONFIG_FILE_PATH):
            warning(f'Config file cannot be found at {CONFIG_FILE_PATH}')
            exit()

        # open the config file and read in the data
        try:
            with open(CONFIG_FILE_PATH, 'r') as f:
                data = f.read()
        except OSError:
            warning(f'Could not read from config file {CONFIG_FILE_PATH}')
            exit()

        # parse the JSON data to get a python dictionary
        try:
            config_dict = json.loads(data)
        except json.decoder.JSONDecodeError:
            warning(f'Config file at {CONFIG_FILE_PATH} is not valid JSON')
            exit()

        ## first load in the modules

        # this will load in a list of dictionaries referring to python modules
        # that need to be loaded and run
        dict_modules_to_load = config_dict['modules']

        # makes a list of the module path from the dicts
        modules_to_load = [d['path'] for d in dict_modules_to_load]

        # loads the modules in and initialises the objects, saved as a list
        self.modules = self._load_modules(modules_to_load)

        ## now load in the scan types

        self.scan_types = config_dict['scan types']

        ## now load in the options

        self.success_codes = config_dict['options']['success_codes']
        self.file_extensions = config_dict['options']['file_extensions']
        self.options['display_banner'] = config_dict['options']['display_banner']
        self.options['threads'] = config_dict['options']['threads']
        self.options['verbose'] = config_dict['options']['verbose']
        self.options['text_gen_epochs'] = config_dict['options']['text_generator_epochs']
        self.options['proxy_port'] = config_dict['options']['proxy_port']


    def _load_modules(self, modules_list):
        """ takes a list of module strings and loads them

            @param:     modules_list (list)     - a list of strings of modules to
                                                  load
            @returns:   a list of dictionaries containing loaded modules
        """
        # temporary list to hold loaded modules
        modules_loaded = {}

        # loop through each module string in the list
        for mod in modules_list:
            # TODO: remove this before production
            assert('/' in mod)

            # split the string into package name, and class name
            package_name, class_name = mod.split('/')

            temp_module = load_module(package_name, class_name)
            if not temp_module:
                warning(f"Could not load the module at {mod}. Check the config file at {CONFIG_FILE_PATH}")
                exit()

            temp_module = temp_module(self)
            modules_loaded[temp_module.info["name"]] = temp_module

        return modules_loaded

    def run_text_generation(self):
        for module in self.modules:
            module.generate_text()

    def run_modules(self):
        if not self.scan_type in self.scan_types:
            warning(f'Could not find scan type {self.scan_type} in config file')

        modules_to_run = []
        for module_name in self.scan_types[self.scan_type]:
            modules_to_run.append(self.modules[module_name])

        for module in modules_to_run:
            module.run_module()

class Test(unittest.TestCase):
    def test__load_config():
        test_scan = WebScanner(args)
        print(test_scan.load_config())

if __name__ == '__main__':
    wscan = WebScanner(args)
