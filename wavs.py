#################################################
# author:       Ryan Ritchie                    #
# student no:   17019225                        #
# email:        ryan2.ritchie@live.uwe.ac.uk    #
#################################################

################
# imports      #
################
import os
import argparse

from conf import config
from time import sleep
from utils.DBManager import DBManager
from util_functions import clear_screen
from util_functions import load_module
from util_functions import cookie_parse
from util_functions import info, warning, banner_colour


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
    help='Add HTTP codes for a found resources. Space delimited list')

arg_parser.add_argument(
    '--remove_success_codes',
    nargs='+',
    type=int,
    help='Remove HTTP codes for found resources. Space delimited list')

args = arg_parser.parse_args()


###############
# classes     #
###############
class WebScanner():
    """ This class provides the 'framework' for the scanning program, it loads
        in configuration options, parses command line arguments, loads in the
        scanning modules and finally runs through all the loaded modules and
        runs them.

        @param:     arg_parse - this is an object from the argparse module
                                which contains all the command line arguments
    """

    def __init__(self, arg_parse):
        self.options = {}
        self.modules = []
        self.scan_types = []

        self._parse_cmd_line_args(arg_parse)
        self._init_database()
        self._load_config()
        self._banner()

        if arg_parse.generator:
            info('Starting text generation...')
            sleep(2)

            # suppress debugging output from tensorflow
            os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

            # start text generation
            from utils.TextGenerator import TextGenerator
            self.text_generator = TextGenerator(self)
            self.run_text_generation()

            # clear the screen because tensorflow creates a lot of output
            clear_screen()
            info('Completed text generation')
        else:
            self.run_modules()
            self.db.remove_generated_text()

    def _load_config(self):
        """ loads in the configuration data contained in conf/config.py then
            saves the various configuration variables into named attributes
            to be used during scanning

            @params:    None
            @returns:   None
        """
        # config is loaded in from config.py which contains a dict which has
        # all the config variables saved in it
        config_dict = config.config

        # this will load in a list of dictionaries referring to python modules
        # that need to be loaded and run
        dict_modules_to_load = config_dict['modules']

        # makes a list of the module path from the dicts
        modules_to_load = [d['path'] for d in dict_modules_to_load]

        # loads the modules in and initialises the objects, saved as a list
        self.modules = self._load_modules(modules_to_load)

        # load in the scan types, these are named lists of modules to run
        self.scan_types = config_dict['scan types']

        # load in the configuration variables from the dict and save them
        # into named attributes to be used in the scanning modules
        self.success_codes = \
            config_dict['options']['success_codes']
        self.file_extensions = \
            config_dict['options']['file_extensions']
        self.options['display_banner'] = \
            config_dict['options']['display_banner']
        self.options['threads'] = \
            config_dict['options']['threads']
        self.options['verbose'] = \
            config_dict['options']['verbose']
        self.options['text_gen_epochs'] = \
            config_dict['options']['text_generator_epochs']
        self.options['proxy_port'] = \
            config_dict['options']['proxy_port']
        self.options['text_generator_temp'] = \
            config_dict['options']['text_generator_temp']

    def _parse_cmd_line_args(self, arg_parse):
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

        # this option controls whether the 'Crawler' module should crawl the
        # target automatically, or whether it should use a proxy to let the
        # user crawl the target manually through a web browser
        self.options['manual_crawl'] = arg_parse.manual_crawl

    def _init_database(self):
        self.db = DBManager()

        # save the scan in the database
        self.id = self.db.save_new_scan(self)

    def get_host_url_base(self):
        """ constructs the url to access the target

            @params:             None
            @returns (string):   a url to access the target web application
        """
        return f'{self.proto}{self.host}:{self.port}'

    def _banner(self):
        """ displays the program banner on startup

            @params:        None
            @returns:       None
        """
        if self.options['display_banner']:
            banner_colour(config.banner)

    def _load_modules(self, modules_list):
        """ takes a list of module strings and loads them

            @param:     modules_list (list)     - modules to load
            @returns:   a list of dictionaries containing loaded modules
        """
        # temporary list to hold loaded modules
        modules_loaded = {}

        # loop through each module string in the list
        for mod in modules_list:

            # split the string into package name, and class name
            module_path_list = mod.split('/')
            class_name = module_path_list[-1:][0]
            package_name = '.'.join(module_path_list[:-1])

            # load the module
            temp_module = load_module(package_name, class_name)

            # if the module could not be found, exit
            if not temp_module:
                warning(f"Could not load the module at {mod}.")
                exit()

            # instantiate the loaded module, passing in the Webscanner instance
            temp_module = temp_module(self)

            # save the module instance by its name in a dict
            modules_loaded[temp_module.info["name"]] = temp_module

        # return all the instances of loaded modules
        return modules_loaded

    def run_text_generation(self):
        """ runs through each loaded module and calls the modules text
            generation method. the generated text is saved in a database
            table. the next time a scan is run, the generated text is used
            as search text for the corresponding module. if the generated
            text is successful in finding something, it will be saved in
            the main search text database to be used in future scans.

            @params:        None
            @returns:       None
        """

        conn = self.db.get_connection(self.db.db_paths['attack_strings'])
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS '
                       'generated_text ('
                       'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                       'text TEXT NOT NULL,'
                       'type TEXT NOT NULL);')
        conn.commit()
        conn.close()

        for module in self.modules.values():
            module.generate_text()

    def run_modules(self):
        """ runs through each module in the selected scan type and calls its
            run method, which runs the scan for that specific module

            @params:        None
            @returns:       None
        """

        # check that the scan type passed in by command line is defined
        # in the config file, if not exit
        if self.scan_type not in self.scan_types:
            warning(f'Scan type {self.scan_type} not in config file')
            exit()

        # build a list of the modules in the scan type
        modules_to_run = []
        for module_name in self.scan_types[self.scan_type]:
            modules_to_run.append(self.modules[module_name])

        # loop through the modules in the scan type and call the run method
        for module in modules_to_run:
            module.run_module()

    def get_modules(self):
        modules_to_run = []
        for module_name in self.scan_types[self.scan_type]:
            modules_to_run.append(self.modules[module_name])

        return modules_to_run


if __name__ == '__main__':
    wscan = WebScanner(args)
