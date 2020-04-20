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
import requests
import http.cookies

from conf import config
from time import sleep
from utils.DBManager import DBManager
from utils.ReportGenerator import ReportGenerator
from util_functions import clear_screen
from util_functions import load_module
from util_functions import info, warning, success, banner_colour

########################
# argument parsing     #
########################
arg_parser = argparse.ArgumentParser()
subparsers = arg_parser.add_subparsers(dest='subcommand')

scan_parser = subparsers.add_parser(
    "scan",
    help='Options to control a vulnerability scan')
tgen_parser = subparsers.add_parser(
    "generate",
    help='Options to generate text payloads')
report_parser = subparsers.add_parser(
    "report",
    help='Options to generate reports')
db_parser = subparsers.add_parser(
    "database",
    help='Options to control databases')

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
    help='The base directory of the application to be scanned')

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
    '--no_report',
    default=False,
    action='store_true',
    help='Do not create a report for this scan')

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
    '-o',
    '--outfile',
    default=False,
    action='store_true',
    help='The path to save the report to')

scan_parser.add_argument(
    '--save_ext',
    type=str,
    default='html',
    choices=['html', 'txt', 'pdf'],
    help='Set the extension to save the report as'
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

report_parser.add_argument(
    '--save_ext',
    type=str,
    default='html',
    choices=['html', 'txt', 'pdf'],
    help='Set the extension to save the report as'
)

###############################################
# command line arguments for database command #
###############################################
db_parser.add_argument(
    '--reset',
    action='store_true',
    help='Reset both wordlist and scans database. \
          Deletes all data from scans, resets wordlist count'
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

# parse command line arguments
args = arg_parser.parse_args()


###############
# classes     #
###############
class WebScanner():
    """ Scans a web application using loaded in modules.

        This class provides the 'framework' for the scanning program, it loads
        in configuration options, parses command line arguments, loads in the
        scanning modules and finally runs through all the loaded modules and
        runs them.

        Args:
            arg_parse - contains parsed command line arguments
    """

    def __init__(self, arg_parse):
        self.cmd_args = arg_parse
        self.options = {}
        self.modules = []
        self.scan_types = []

        self._load_config()
        self.db = DBManager()

    def scan(self):
        """ Runs different code paths based on cmd-line subcommand.

            This method will run different code paths depending upon the
            subcommand used on the command line. The subcommands which could
            be used are: scan, generate, report and database. 'scan' runs a
            vulnerability scan against a target application, 'generate' runs
            the text generation system, 'report' generates vulnerability
            reports for past scans, 'database' performs actions on the
            databases used in this application.

            Args:
                None

            Returns:
                None
        """
        if self.cmd_args.subcommand == 'scan':
            # set scan options based on command line args
            self._parse_cmd_line_args()

            # create a new scan in the 'scans' database
            self._init_database()

            # save this for creating reports
            self.report_gen = ReportGenerator(self)

            # print the banner to stdout
            self._banner()

            # begin scanning the target
            self._run_scan()

        elif self.cmd_args.subcommand == 'generate':
            # print the banner to stdout
            self._banner()

            # generate new payloads
            self._run_text_generator()

        elif self.cmd_args.subcommand == 'report':
            # set the scan type because '_parse_cmd_line_args' isnt called
            self.scan_type = 'default'

            # save the extension to save the report as
            self.options['report_extension'] = self.cmd_args.save_ext

            # save this for creating reports
            self.report_gen = ReportGenerator(self)

            # print the banner to stdout
            self._banner()

            # create a report
            self._run_report_generator()

        elif self.cmd_args.subcommand == 'database':
            # an instance of database manager
            self.db = DBManager()

            # print the banner
            self._banner()

            # reset wordlist and/or scans database
            self._database_reset()

    def _run_scan(self):
        """ Runs a scan against target application using scanning modules.

            Calls a method which loops through loaded in modules and calls
            their 'run' method. Once finished it calls the report generation
            system's method to create a report. Finally it removes any text
            which has been generated.

            Args:
                None

            Returns:
                None
        """
        # loop through all modules in current scan and run them
        self.run_modules()

        # generate a report for the current scan
        if self.should_create_report:
            self.report_gen.generate_report(self.id)

        # remove any payloads generated by text generator
        self.db.remove_generated_text()

    def _run_text_generator(self):
        """ Runs text generation system, which creates new payloads.

            This method uses a 'TextGenerator' instance to create payloads
            based upon payloads in the 'wordlist' database. Once text has been
            generated it saves the text in the 'wordlist' database.

            Args:
                None

            Returns:
                None
        """
        info('Starting text generation...')

        # wait 2 seconds so user scan see the above message
        sleep(2)

        # suppress debugging output from tensorflow
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

        # start text generation and save it in database
        from utils.TextGenerator import TextGenerator
        self.text_generator = TextGenerator(self)
        self.run_text_generation()

        # clear the screen because tensorflow creates a lot of output
        clear_screen()
        info('Completed text generation')

    def _run_report_generator(self):
        """ Creates a report for a past scan.

            Method will display a list of past scans along with their scan id.
            Prompts the user to select a past scan, then generates a report for
            that scan.

            Args:
                None

            Returns:
                None
        """
        info(f'Generating report...')

        # display a list of past scans with scan ids
        scan_id = self.show_previous_scans()

        # generate a report for the selected scan
        self.report_gen.generate_report(scan_id)

    def _database_reset(self):
        """ Resets the wordlist and/or scans database back to defaults.

            Method will reset the 'count' column of the wordlist database back
            to 0, and/or it will delete everyting in the scans database.

            Args:
                None

            Returns:
                None
        """
        info('Resetting internal databases...')

        # if the --reset option is set
        if self.cmd_args.reset:
            self.db.reset_wordlist()
            self.db.reset_scans()

        # if the --reset_scans option is set
        elif self.cmd_args.reset_scans:
            self.db.reset_scans()

        # if the --reset_wordlist option is set
        elif self.cmd_args.reset_wordlist:
            self.db.reset_wordlist()

    def _load_config(self):
        """ Load in configuration options.

            loads in the configuration data contained in conf/config.py then
            saves the various configuration variables into named attributes
            to be used during scanning

            Args:
                None

            Returns:
                None
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

    def _parse_cmd_line_args(self):
        """ Parses command line arguments.

            parses the command line arguments passed into the program, and
            makes sure the arguments passed are valid.

            Args:
                None

            Returns:
                None
        """

        # save the command line arguments
        arg_parse = self.cmd_args

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
        temp_cookies = http.cookies.SimpleCookie(arg_parse.cookies)
        self.cookies = requests.cookies.RequestsCookieJar()
        self.cookies.update(temp_cookies)

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

        # whether or not to create report
        self.should_create_report = not arg_parse.no_report

        # this option controls whether the 'Crawler' module should crawl the
        # target automatically, or whether it should use a proxy to let the
        # user crawl the target manually through a web browser
        self.options['manual_crawl'] = arg_parse.manual_crawl

        # save the report extension
        self.options['report_extension'] = arg_parse.save_ext

    def _init_database(self):
        """ Creates a new scan in the 'scans' database.

            Creates a new scan in the 'scans' database and save the scan ID.

            Args:
                None

            Returns:
                None
        """
        # save the scan in the database
        self.id = self.db.save_new_scan(self)

    def get_host_url_base(self, incl_base_dir=True):
        """ Constructs the url to access the target

            Constructs a URL which can be used to access the target. The URL
            is constructed from the protocol, target IP/hostname, target port
            and the base directory.

            Args:
                incl_base_dir: Whether to use base directory in URL

            Returns:
                (string) URL to access target application
        """
        if incl_base_dir:
            return f'{self.proto}{self.host}:{self.port}{self.base_dir}'
        else:
            return f'{self.proto}{self.host}:{self.port}'

    def _banner(self):
        """ displays the program banner on startup

            Args:
                None

            Returns:
                None
        """
        if self.options['display_banner']:
            banner_colour(config.banner)

    def _load_modules(self, modules_list):
        """ Loads in vulnerability scanner modules.

            Takes a list of modules to load, imports the associated python
            module then instantiates the class in the module. It saves the
            instance in a list.

            Args:
                modules_list: a list of strings, the modules to be loaded

            Returns:
                a list of dictionaries containing instance of loaded module
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
        """ Runs the text generation system to create new payloads.

            runs through each loaded module and calls the modules text
            generation method. the generated text is saved in a database
            table. the next time a scan is run, the generated text is used
            as search text for the corresponding module. if the generated
            text is successful in finding something, it will be saved in
            the main search text database to be used in future scans.

            Args:
                None

            Returns:
                None
        """

        # create the text generation table if it doesnt already exist
        conn = self.db.get_connection(self.db.db_paths['wordlist'])
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS '
                       'generated_text ('
                       'id INTEGER PRIMARY KEY AUTOINCREMENT,'
                       'text TEXT NOT NULL,'
                       'type TEXT NOT NULL);')
        conn.commit()
        conn.close()

        # loop through each module and generate payloads for it
        for module in self.modules.values():
            module.generate_text()

    def run_modules(self):
        """ Runs all the modules in the current scan.

            runs through each module in the selected scan type and calls its
            run method, which runs the scan for that specific module

            Args:
                None

            Returns:
                None
        """

        # check that the scan type passed in by command line is defined
        # in the config file, if not exit
        if self.scan_type not in self.scan_types:
            warning(f'Scan type {self.scan_type} not in config file')
            exit()

        # build a list of the modules in the scan type
        modules_to_run = []
        for module_name in self.scan_types[self.scan_type]:
            try:
                modules_to_run.append(self.modules[module_name])
            except KeyError:
                warning(f'Module name {module_name} not found.'
                        'Please check the config file.')
                exit()

        # loop through the modules in the scan type and call the run method
        for module in modules_to_run:
            module.run_module()

    def get_modules(self):
        """ Gets a list of all the modules in the current scan

            Method gets the list of modules to be run in the current scan from
            the config file. It then creates a list of instances of those
            modules.

            Args:
                None

            Returns:
                a list of module instances
        """
        modules_to_run = []

        # loop through all the modules in the current scan type
        for module_name in self.scan_types[self.scan_type]:

            # add the module instance to the list
            modules_to_run.append(self.modules[module_name])

        return modules_to_run

    def show_previous_scans(self):
        """ Displays a list of past scans and allows user to select one.

            This method prints out a list of all the past scans saved in the
            'scans' database, along with their scan IDs. It prompts the user to
            enter the scan ID of the scan to be selected.

            Args:
                None

            Returns:
                the scan ID of the selected scan
        """
        info('Previous scans:')

        # store an instance of the 'scans' database
        scans_table = self.db.get_scan_db().table('scans')

        # get all the saved scans
        scans = scans_table.all()

        # loop through each scan
        for scan in scans:

            # print the scan details to stdout
            success(
                f'ID: {scan.doc_id},'
                f'Host: {scan["host"]}',
                f'Port: {scan["port"]}',
                f'Time: {scan["timestamp"]}', prepend='  ')

        # prompt the user to enter the scan ID of the scan to be selected
        # it will reject scan IDs which dont exist, and any input which is
        # not an int
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
    wscan.scan()
