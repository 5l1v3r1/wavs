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
from utils.ReportGenerator import ReportGenerator
from util_functions import clear_screen
from util_functions import load_module
from util_functions import cookie_parse
from util_functions import info, warning, success, banner_colour

########################
# argument parsing     #
########################
arg_parser = argparse.ArgumentParser()
subparsers = arg_parser.add_subparsers(dest='subcommand')

scan_parser = subparsers.add_parser("scan", help='Options to control a vulnerability scan')
tgen_parser = subparsers.add_parser("generate", help='Options to generate text payloads')
report_parser = subparsers.add_parser("report", help='Options to generate reports')
db_parser = subparsers.add_parser("database", help='Options to control databases')

###########################################
# command line arguments for scan command #
###########################################
scan_parser.add_argument(
    'host',
    help='The url of the web application to be scanned, including protocol')

scan_parser.add_argument(
    '-b',
    '--base_dir',
    default='',
    help='The base directory of the application to be scanned'
)

scan_parser.add_argument(
    '-p',
    '--port',
    type=int,
    default=0,
    help='The port the web application is running on')

scan_parser.add_argument(
    '-c',
    '--cookies',
    help='Cookies to include in requests, <cookie_name>=<cookie_value>,[...]')

scan_parser.add_argument(
    '-r',
    '--restrict_paths',
    default='',
    help='Paths which should not be visited, /restrict/path/')

scan_parser.add_argument(
    '-t',
    '--type',
    default='default',
    help='Determines which modules run and in what order. From config')

scan_parser.add_argument(
    '-m',
    '--manual_crawl',
    default=False,
    action='store_true',
    help='Use a proxy to manually crawl the target')

scan_parser.add_argument(
    '--add_success_codes',
    nargs='+',
    type=int,
    help='Add HTTP codes for a found resources. Space delimited list')

scan_parser.add_argument(
    '--remove_success_codes',
    nargs='+',
    type=int,
    help='Remove HTTP codes for found resources. Space delimited list')

scan_parser.add_argument(
    '--save_ext',
    type=str,
    default='html',
    choices=['html', 'txt', 'pdf'],
    help='Set the extension to save the report as'
)

scan_parser.add_argument(
    '-o',
    '--outfile',
    default=False,
    action='store_true',
    help='The path to save the report to'
)

################################################
# command line arguments for generator command #
################################################
tgen_parser.add_argument(
    '-g',
    '--generator',
    default=False,
    action='store_true',
    help='Runs the attack string text generator')

#############################################
# command line arguments for report command #
#############################################
report_parser.add_argument(
    '-o',
    '--outfile',
    help='The full path of the report file to be created, including extension'
)

###############################################
# command line arguments for database command #
###############################################
db_parser.add_argument(
    '--reset',
    action='store_true',
    help='Reset both wordlist and scans database. Deletes all data from scans, resets wordlist count'
)

db_parser.add_argument(
    '--reset_wordlist',
    action='store_true',
    help='Reset the count of the wordlist database'
)

db_parser.add_argument(
    '--reset_scans',
    action='store_true',
    help='Delete all previous scan data'
)

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
        self.cmd_args = arg_parse
        self.options = {}
        self.modules = []
        self.scan_types = []

        self._load_config()
        if self.cmd_args.subcommand == 'scan':
            self.db = DBManager()

            self._parse_cmd_line_args(arg_parse)
            self._init_database()
            self.report_gen = ReportGenerator(self)
            self._banner()
            self._run_scan()

        elif self.cmd_args.subcommand == 'report':
            self._banner()
            self._run_text_generator()

        elif self.cmd_args.subcommand == 'generate':
            self.report_gen = ReportGenerator(self)

            self._banner()
            self._run_report_generator()

        elif self.cmd_args.subcommand == 'database':
            self.db = DBManager()

            self._banner()
            self._database_reset()

    def _run_scan(self):
        # loop through all modules in current scan and run them
        self.run_modules()

        # generate a report for the current scan
        self.report_gen.generate_report(self.id)

        # remove any payloads generated by text generator
        self.db.remove_generated_text()

    def _run_text_generator(self):
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

    def _run_report_generator(self):
        info(f'Generating report...')
        scan_id = self.show_previous_scans()
        self.report_gen.generate_report(scan_id)

    def _database_reset(self):
        info('Resetting internal databases...')
        if self.cmd_args.reset:
            self.db.reset_wordlist()
            self.db.reset_scans()

        elif self.cmd_args.reset_scans:
            self.db.reset_scans()

        elif self.cmd_args.reset_wordlist:
            self.db.reset_wordlist()

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

        # make sure the base directory starts with a /
        # if base_dir is '' we dont need to worry
        if arg_parse.base_dir:
            self.base_dir = arg_parse.base_dir
            if self.base_dir[0] != '/':
                self.base_dir = f'/{self.base_dir}'
        else:
            self.base_dir = arg_parse.base_dir

        # if cookies are supplied, parses the cookies into a dictionary which
        # is required by the requests module
        self.cookies = cookie_parse(arg_parse.cookies)

        # store the scan type, must be a value listed in the config.json file
        # under 'scan_types', if not specified by command line argument the
        # 'default' scan type is stored
        self.scan_type = arg_parse.type

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
            self.restrict_paths = []

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

        self.options['report_extension'] = arg_parse.save_ext

    def _init_database(self):
        # save the scan in the database
        self.id = self.db.save_new_scan(self)

    def get_host_url_base(self):
        """ constructs the url to access the target

            @params:             None
            @returns (string):   a url to access the target web application
        """
        return f'{self.proto}{self.host}:{self.port}{self.base_dir}'

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
            if hasattr(temp_module, "info"):
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

    def show_previous_scans(self):
        info('Previous scans:')

        scans_table = self.db.get_scan_db().table('scans')
        scans = scans_table.all()

        for scan in scans:
            success(f'ID: {scan.doc_id}, Host: {scan["host"]}, Port: {scan["port"]}, Time: {scan["timestamp"]}', prepend='  ')

        check = False
        while not check:
            try:
                choice = int(input('> '))

                if not self.db.scan_exists(choice):
                    warning(f'Scan ID: {choice} does not exist')
                else:
                    check = True
            except (ValueError):
                pass

        return choice


if __name__ == '__main__':
    wscan = WebScanner(args)
