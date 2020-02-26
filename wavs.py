#/usr/bin/python3

#################################################
# author:       Ryan Ritchie                    #
# student no:   17019225                        #
# email:        ryan2.ritchie@live.uwe.ac.uk    #
#################################################

################
# imports      #
################
import os
import sys
import json
import requests
import argparse

from datetime import datetime
from functools import partial
from multiprocessing import Pool

from utils.DBManager import DBManager
from util_functions import load_module
from util_functions import cookie_parse
from util_functions import success, warning, info, banner_colour


################
# globals      #
################
CONFIG_FILE_PATH = 'conf/config.json'


########################
# argument parsing     #
########################
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument(
    'host',
    help='The url of the web application to be scanned, including protocol')

arg_parser.add_argument(
    '-p',
    '--port',
    type=int,
    default=0,
    help='The port the web application is running on')

arg_parser.add_argument(
    '-c',
    '--cookies',
    help='Cookies to include in requests, <cookie_name>=<cookie_value>,[...]')

arg_parser.add_argument(
    '-r',
    '--restrict_paths',
    default='',
    help='Paths which should not be visited, /restrict/path/')

arg_parser.add_argument(
    '-s',
    '--scan_type',
    default='default',
    help='Determines which modules run and in what order. From config')

arg_parser.add_argument(
    '-g',
    '--generator',
    default=False,
    action='store_true',
    help='Runs the attack string text generator')

arg_parser.add_argument(
    '-m',
    '--manual_crawl',
    default=False,
    action='store_true',
    help='Use a proxy to manually crawl the target')

arg_parser.add_argument(
    '--add_success_codes',
    nargs='+',
    type=int,
    help='Add HTTP codes to consider a resource found. Space delimited list')

arg_parser.add_argument(
    '--remove_success_codes',
    nargs='+',
    type=int,
    help='Remove HTTP codes to consider a resource found. Space delimited list')

args = arg_parser.parse_args()


###############
# classes     #
###############
class WebScanner():
    """ TODO: provide docstring

    """
    def __init__(self, arg_parse):
        self.load_config()
        self.parse_cmd_line_args(arg_parse)

        self.options = {}
        self.modules = []
        self.scan_types = []

        self.db = DBManager()

        # save the scan in the database
        self.id = self.db.save_new_scan(self)

        self.options['manual_crawl'] = arg_parse.manual_crawl

        self._banner()

        if arg_parse.generator:
            self.run_text_generation()
        else:
            self.run_modules()

    def parse_cmd_line_args(self, arg_parse):
        """ parses the command line arguments passed into the program, and
            makes sure the arguments passed are valid.

            @param:     arg_parse   - argparser object containing cmd line args
            @returns:   None
        """

        # a protocol needs to be supplied in host and needs to be
        # either http or https, otherwise the program should exit
        if arg_parse.host[:4] != 'http':
            warning('Please specify the protocol for host, http or https')
            exit()

        # split the host into protocol and ip/hostname
        self.proto, self.host = arg_parse.host.split('://')
        self.proto += '://'

        # if no port is specified then set port based on protocol,
        # these are the default ports for the http and https protocols
        if arg_parse.port == 0:
            if self.proto == 'http://':
                self.port = 80
            elif self.proto == 'https://':
                self.port = 443
        else:
            self.port = arg_parse.port

        # if cookies are supplied, parses the cookies into a dictionary which
        # is required by the requests module
        self.cookies = cookie_parse(arg_parse.cookies)

        # store the scan type, must be a value listed in the config.json file
        # under 'scan_types', if not specified by command line argument the
        # 'default' scan type is stored
        self.scan_type = arg_parse.scan_type

        # parse any restricted paths passed in from command line
        # these paths on the target application that should not be crawled
        if arg_parse.restrict_paths:
            # if a list has been passed, split the list
            if ',' in arg_parse.restrict_paths:
                self.restrict_paths = arg_parse.restrict_paths.split(',')
            else:
                # otherwise make the single path into a list
                self.restrict_paths = [arg_parse.restrict_paths]
        else:
            self.restrict_paths = None

        # add success codes passed in from command line
        if arg_parse.add_success_codes:
            self.success_codes.extend([
                code for code
                in arg_parse.add_success_codes
                if code not in self.success_codes])

        # remove success codes passed in from command line
        if arg_parse.remove_success_codes:
            self.success_codes = [
                code for code
                in self.success_codes
                if code not in arg_parse.remove_success_codes]

    def get_host_url_base(self):
        return f'{self.proto}{self.host}:{self.port}'

    def _banner(self):
        banner = ''
        try:
            with open('etc/banner', 'r') as f:
                banner = f.read()
        except:
            banner = 'Web Application Vulnerability Scanner by Ryan Ritchie'

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
            module_path_list = mod.split('/')
            class_name = module_path_list[-1:][0]
            package_name = '.'.join(module_path_list[:-1])

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



if __name__ == '__main__':
    wscan = WebScanner(args)
