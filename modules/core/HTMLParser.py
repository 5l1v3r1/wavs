import concurrent.futures
from multiprocessing import Pool
from bs4 import BeautifulSoup
from modules.core.BaseModule import BaseModule

from util_functions import success, info, warning
from util_functions import http_get_request


class HTMLParser(BaseModule):
    info = {
        "name": "HTML Parser",
        "db_table_name": "parameters_discovered",
        "reportable": False,
        "desc": "Takes a webpage and parses the HTML to find params to inject",
        "author": "@ryan_ritchie"
    }

    def __init__(self, main):
        BaseModule.__init__(self, main)

    def _resolve_path(self, base_path, path):
        if path:
            if path[-1] == '.' or path[-1] == '#':
                path = path[:-1]

        if not "../" in path:
            final = f'{path}'

            if final:
                if final[0] == '/':
                    final = final[1:]
                return final
            else:
                return final

        # vulnerabilities/brute/
        # ../../vulnerabilities/fi/.

        dir_ups = path.count('../')
        new_path = path.replace('../', '')
        explode_base = base_path.split('/')
        explode_base = list(filter(('').__ne__, explode_base))
        new_base = explode_base[:-dir_ups]

        final = f'{"/".join(new_base)}/{new_path}'

        if final:
            if final[0] == '/':
                final = final[1:]
            return final
        else:
            return final

    def _extract_link_params(self, page, link, directory_path):
        assert('?' in link)

        action, params = link.split('?')

        if not action:
            action = page

        stored_params = []
        for param in params.split('&'):
            stored_params.append(param.split('=')[0])

        action = self._resolve_path(directory_path, action)

        return {'method': 'GET',
                'action': action,
                'params': stored_params}

    def _extract_links(self, page, html, directory_path):
        """ extract anchor links out of html data

            :param html:        a beautiful soup html object
            :return (list):     a list of links found in the html
        """
        links = []

        # loop through all the anchor tags
        for link in html.find_all('a'):
            href = link.get('href')

            if not href:
                continue

            # we only want links with parameters in
            if '?' not in href:
                continue

            # we assume if it is an absolute path it is external and ignore it
            if any(x in href for x in ['http://', 'https://']):
                continue

            # extract the parameters from the link
            links.append(self._extract_link_params(page, link.get('href'),
                                                   directory_path))

        return links

    def _extract_form_params(self, page, form, field):
        ''' from an html form, build param data

            :param form:        a beautiful soup form object
            :param field:       a beautiful soup field object
            :return (dict):     a dictionary with param data
        '''

        action = form.get('action')
        if not action:
            action = page

        if any(x in action for x in ['http://', 'https://']):
            return None

        return field.get('name')

    def _extract_forms(self, page, html, directory_path):
        """ extract params from html forms

            :param html:        a beautiful soup html object
            :return (list):     a list of params found in the html
        """

        all_forms = []
        forms = html.find_all('form')

        if not forms:
            return []

        for form in forms:
            method = form.get('method')
            action = form.get('action')

            if not method:
                continue

            # if there is no action set for the form then it should be
            # submitted back to the page it is on
            if not action or action == '#':
                action = page

            form_params = []
            for field in form.find_all(['input', 'textarea', 'select', 'radio']):
                field_name = self._extract_form_params(page, form, field)
                if field_name:
                    form_params.append(field_name)

            action = self._resolve_path(directory_path, action)

            all_forms.append({'method': method,
                              'action': f'{action}',
                              'params': form_params})

        return all_forms

    def _run_thread(self, webpage):
        """ runs in a thread. parses a webpage's html for form and links, then
            extracts parameters to inject attacks into

            :param webpage:         a beautiful soup html parser object
            :return (list):         a list of dictionaries containing params
        """
        # get the html
        url = f'{self.main.get_host_url_base()}/{webpage}'
        html = http_get_request(url, self.main.cookies).text

        # look for params to inject into
        soup = BeautifulSoup(html, 'html.parser')

        directory_path = ''
        # if the webpage has a directory
        if '/' in webpage:
            path_split = webpage.split('/')
            directory_path = '/'.join(path_split[:-1]) + '/'

        params = []
        params.extend(self._extract_links(webpage, soup, directory_path))
        params.extend(self._extract_forms(webpage, soup, directory_path))

        return params

    def run_module(self):
        """ the entrypoint into the module.

            takes any found webpages and uses threads to extract params from
            the html.
        """
        info('Parsing HTML...')

        # get the list of found pages
        found_pages = self._get_previous_results('FileScanner')

        # if there are no found pages, theres no need to run this module
        if not found_pages:
            return

        # pass the found pages to threads
        with concurrent.futures.ProcessPoolExecutor() as executor:
            results = list(executor.map(self._run_thread, found_pages))

        # clean up the results from the threads
        final = []
        _ = [final.extend(p) for p in results if p]
        final = list(filter(None, final))

        # remove duplicate found parameters
        final = [i for n, i in enumerate(final) if i not in final[n + 1:]]

        if self.main.options['verbose']:
            for params in final:
                success(f'Found params: {params["action"]} '
                        f'({" ".join(params["params"])})', prepend='  ')

        self._save_scan_results(final, update_count=False)
