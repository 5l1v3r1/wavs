banner = """
`7MMF'     A     `7MF' db `7MMF'   `7MF'.M'''bgd
  `MA     ,MA     ,V  ;MM:  `MA     ,V ,MI    "Y
   VM:   ,VVM:   ,V  ,V^MM.  VM:   ,V  `MMb.
    MM.  M' MM.  M' ,M  `MM   MM.  M'    `YMMNq.
    `MM A'  `MM A'  AbmmmqMA  `MM A'   .     `MM
     :MM;    :MM;  A'     VML  :MM;    Mb     dM
      VF      VF .AMA.   .AMMA. VF     P"Ybmmd"

       Web Application Vulnerability Scanner
"""

# configuration options that persist between different scans
config = {
    ################
    # options      #
    ################
    "options": {
        # these are the HTTP response codes that should be consider a 'success'
        # when scanning for directories and files i.e. the resource was found
        # can be added and removed on a per-scan basis using command line args
        "success_codes": [200, 201, 202, 203, 204, 301, 302, 303, 304],

        # these are the file extensions that should be scanned for during file
        # scans. can be added and removed on a per-scan basis using command
        # line args
        "file_extensions": [".html", ".php"],

        # whether to show the banner when program starts
        "display_banner": True,

        # the number of threads to use for modules that utilise multi-threading
        "threads": 8,

        # if true, the program will output detailed scan information
        "verbose": True,

        # used for text generation, the number of epochs algorithm is trained
        # the higher the number, the longer text generation will take
        "text_generator_epochs": 1,

        # the 'temperature' of text generation, 0 = exact copies of training
        # samples, 1 = essentially random new text
        "text_generator_temp": 0.7,

        # the port the HTTP proxy runs on when using manual crawling
        "proxy_port": 8081
    },

    ################
    # modules      #
    ################
    # the scanning modules which the program loads in at startup, the are the
    # modules which implement the scanning functionality, custom user made
    # modules need to be added here, or they will not be loaded.
    # the name needs to be the same as name defined in the module
    "modules": [
        {"name": "Initial Scanner",
         "path": "modules/core/InitialScanner"},
        {"name": "Directory Scanner",
         "path": "modules/core/DirectoryScanner"},
        {"name": "File Scanner",
         "path": "modules/core/FileScanner"},
        {"name": "Site Crawler",
         "path": "modules/core/Crawler"},
        {"name": "HTML Parser",
         "path": "modules/core/HTMLParser"},
        {"name": "SQL Injection Scanner",
         "path": "modules/core/SQLInjectionScanner"},
        {"name": "SQL Injection Scanner - Blind",
         "path": "modules/core/SQLInjectionScanner_Blind"},
        {"name": "Local File Inclusion",
         "path": "modules/core/LocalFileInclusion"},
        {"name": "Cross Site Scripting - Reflected",
         "path": "modules/core/CrossSiteScripting_Reflected"},
        {"name": "Cross Site Scripting - Stored",
         "path": "modules/core/CrossSiteScripting_Stored"},
        {"name": "Cross Site Request Forgery",
         "path": "modules/core/CSRF"},
        {"name": "Command Injection Scanner",
         "path": "modules/core/CommandInjectionScanner"},
        {"name": "Information Disclosure",
         "path": "modules/core/InformationDisclosure"},
    ],

    ################
    # scans        #
    ################
    # define scan types here, using the template:
    # "scan_name": ["module_name_1", "modules_name_2"]
    # scan name can be anything, module names need to be the names of modules
    # as defined in the 'modules' section above
    "scan types": {
        "default": [
            "Initial Scanner",
            "Directory Scanner",
            "File Scanner",
            "Site Crawler",
            "HTML Parser",
            "SQL Injection Scanner",
            "SQL Injection Scanner - Blind",
            "Local File Inclusion",
            "Cross Site Scripting - Reflected",
            "Cross Site Scripting - Stored",
            "Cross Site Request Forgery",
            "Command Injection Scanner",
            "Information Disclosure"
          ],
        "initial": [
            "Initial Scanner"
          ],
        "crawl": [
            "File Scanner",
            "Site Crawler"
        ],
        "sql": [
            "File Scanner",
            "Site Crawler",
            "HTML Parser",
            "SQL Injection Scanner",
            "SQL Injection Scanner - Blind"
        ],
        "lfi": [
            "File Scanner",
            "HTML Parser",
            "Local File Inclusion"
        ],
        "xss": [
            "File Scanner",
            "Site Crawler",
            "HTML Parser",
            "Cross Site Scripting - Reflected",
            "Cross Site Scripting - Stored"
        ],
        "csrf": [
            "File Scanner",
            "HTML Parser",
            "Cross Site Request Forgery"
        ],
        "info": [
            "Information Disclosure"
        ],
        "test": [
            "File Scanner",
            "Site Crawler",
            "HTML Parser",
            "Command Injection Scanner"
        ],
        "no_vuln": [
            "File Scanner",
            "HTML Parser"
        ]
    }
}
