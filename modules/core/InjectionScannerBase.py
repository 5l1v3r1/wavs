from modules.core.BaseModule import BaseModule
from util_functions import success
from util_functions import http_get_request, http_post_request

# TODO: make sure that modules that depend on previous results handle the lack
#       of those results graciously


class InjectionScannerBase(BaseModule):
    """ this is a base class used to provide common functionality to all
        injection scanner modules. should be inherited.
    """

    def __init__(self, main):
        BaseModule.__init__(self, main)

    def _save_scan_results(self, results, update_count=True):
        """ used to save the results of the module to the database

            @param: results -       a list of the results from the module,
                                    should be a list of text
        """
        # get the successful injections from results
        injections = [(p_dict['payload']) for p_dict in results]

        table = self.main.db.get_scan_db().table(self.info['db_table_name'])
        table.insert({
            "scan_id": self.main.id,
            "results": results
        })

        if update_count:
            self.main.db.update_count(injections, self.info['wordlist_name'])

    def _construct_get_url(self, page, params):
        url = f'{self.main.get_host_url_base()}/{page}?'

        # http://localhost:80/index.php?username=test&password=test&submit=submit

        for param in params:
            url += f'{param}=test&'

        # remove the last &
        url = url[:-1]

        return url

    def _construct_post_params(self, params):
        param_dict = {}
        for p in params:
            param_dict[p] = 'test'

        return param_dict

    def _check_page_content(self, method, injection, param, page, page_text):
        assert(hasattr(self, "re_search_strings"))

        search_strings = self.re_search_strings

        if any([s in page_text for s in search_strings]):
            if not (page, param) in self.injectable_params:
                if self.main.options['verbose']:
                    success(f'Vulnerable parameter: {page}/{param} ({injection})',
                            prepend='  ')
                # self.injectable_params.append((page, param, injection))
                self.injectable_params.append({'method': method,
                                               'page': page,
                                               'parameter': param,
                                               'payload': injection})

            return True

        return False

    def _run_thread(self, param):
        method = param['method']
        page = param['action']

        self.injections = []
        self.injectable_params = []
        inject_params = param['params']

        assert(hasattr(self, "attack_strings"))
        attack_strings = self.attack_strings

        if method == 'GET':
            url = self._construct_get_url(page, inject_params)

            for p in inject_params:
                for injection in attack_strings:
                    final_url = url.replace(f'{p}=test', f'{p}={injection}')

                    resp = http_get_request(final_url, self.main.cookies)
                    if self._check_page_content(method, injection, p, page, resp.text):
                        break

        elif method == 'POST':
            # construct the url to make the request to
            url = f'{self.main.get_host_url_base()}/{page}'

            for p in inject_params:
                params = self._construct_post_params(inject_params)

                for injection in attack_strings:
                    params[p] = injection

                    resp = http_post_request(url, params, self.main.cookies)
                    if self._check_page_content(method, injection, p, page, resp.text):
                        break

        return self.injectable_params
