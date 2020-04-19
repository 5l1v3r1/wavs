import os.path

from modules.core.BaseModule import BaseModule
from bs4 import BeautifulSoup

from util_functions import success, info, highlight
from util_functions import http_get_request
from utils.InterceptingProxy import InterceptingProxy


class Crawler(BaseModule):
    """ Implements link crawling of a target web application.

        Crawls links recursively, or uses a proxy to let user manually crawl
        the target.

        Args:
            main:   instance of the WebScanner
    """
    info = {
        "name": "Site Crawler",
        "db_table_name": "files_discovered",
        "reportable": False,
        "generate":   False,
        "desc": "Crawls through links to find new pages",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main):
        BaseModule.__init__(self, main)

    def _parse_link(self, page, link):
        """ Get the base webpage from a link.

            Args:
                page:   the webpage the link is found on
                link:   the hyperlink

            Returns:
                a link with extraneous information removed
        """
        # remove blanks and param links
        if not link or link[0] == '?':
            return

        # ignore relative paths
        if '../' in link:
            return

        # references to same page
        if link in ['#', '.']:
            link = page

        if not any(x in link for x in ['http://', 'https://']):
            if '?' in link:
                # get page from href
                linked_page = link.split('?')[0]
            else:
                linked_page = link

            if linked_page in self.main.restrict_paths:
                return

            # check that the page actually exists first
            url = f'{self.main.get_host_url_base()}/{linked_page}'
            page_exists = http_get_request(url, self.main.cookies).status_code
            if page_exists in self.main.success_codes:
                return linked_page

    def _parse_links(self, page):
        """ Get all the links on a webpage.

            Args:
                page:   the html of a webpage

            Returns:
                a list of all links found on the webpage
        """
        if page[0] == '/':
            page = page[1:]

        # get the html
        url = f'{self.main.get_host_url_base()}/{page}'
        html = http_get_request(url, self.main.cookies).text

        # look for params to inject into
        soup = BeautifulSoup(html, 'html.parser')

        return_links = []

        # parse all hyperlinks
        for link in soup.find_all('a'):
            href = link.get('href')
            parsed_href = self._parse_link(page, href)

            if parsed_href:
                return_links.append(parsed_href)

        # parse all forms
        for form in soup.find_all('form'):
            action = form.get('action')
            parsed_action = self._parse_link(page, action)

            if parsed_action:
                return_links.append(parsed_action)

        return return_links

    def proxy_response_handle(self, resp, path):
        """ Parses a response from the proxy.

            Args:
                resp:   the response from proxy. from 'requests' module
                path:   the path to the webpage for the request

            Returns:
                None
        """
        if self.main.base_dir in path:
            path = path.replace(self.main.base_dir, '/')

        if resp.status_code in self.main.success_codes:
            # get rid of any GET parameters in the path
            if '?' in path:
                path = path.split('?')[0]

            # we dont want to find files in restricted paths
            if path not in self.main.restrict_paths:

                # we dont want files which weve already found
                if path not in self.manual_found_pages:
                    # get the filename
                    file = os.path.normpath(path).split(os.path.sep)[-1]

                    if '.' in file:
                        # get the file extension
                        ext = file.split('.')[-1]

                        # we dont want file types not in the extension list
                        if f'.{ext}' in self.main.file_extensions:
                            self.manual_found_pages.append(path)
                            success(f'Found new page: {path}', prepend='    ')
                    else:
                        self.manual_found_pages.append(path)
                        success(f'Found new page: {path}', prepend='    ')

    def auto_crawl(self):
        """ recursively crawls all the links in a web application.

            Args:
                None

            Returns:
                None
        """
        # loop through all pages found so far
        loop_pages = self.found_pages
        for page in loop_pages:
            for link in self._parse_links(page):
                if link not in loop_pages:
                    success(f'Found page: {link}', prepend='  ')
                    loop_pages.append(link)

        self._save_scan_results(loop_pages, update_count=False)

    def run_module(self):
        """ Performs the actual scanning of the target application.

            Either automatically crawls the target application for links, or
            sets up a proxy so that user can manually crawl the target.

            Args:
                None

            Returns:
                None
        """
        info('Crawling links...')

        # get found pages
        self.found_pages = self._get_previous_results('FileScanner')

        # if there are no found pages, use the default path
        if not self.found_pages:
            self.found_pages = ['/']

        # if the manual crawl option is set
        if self.main.options['manual_crawl']:
            self.manual_found_pages = self.found_pages
            proxy_port = self.main.options['proxy_port']

            highlight(f'Proxy server started on http://127.0.0.1:{proxy_port}',
                      prepend='  ')
            highlight('Use browser to crawl target. CTRL+C to exit.',
                      prepend='  ')

            # set up the interceptin proxy and start it
            proxy = InterceptingProxy(self.main.host, proxy_port, self)
            proxy.start()

            self._save_scan_results(self.manual_found_pages, update_count=False)

            # automatically crawl the target
            self.auto_crawl()
        else:
            # automatically crawl the target
            self.auto_crawl()
