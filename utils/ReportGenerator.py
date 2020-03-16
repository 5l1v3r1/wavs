

class ReportGenerator:
    """ generates reports of vulnerabilities found, and mitigation strategies
        into different report formats.
    """

    def __init__(self, main):
        self.main = main

    def _gather_data(self):
        # get the modules which were run in current scan
        modules_run = self.main.get_modules()

        # get db results for each module
        db_data = [module.get_report_data() for module in modules_run]
        db_data = list(filter(None, db_data))

        return db_data

    def generate_txt(self):
        report_text = 'WAVS Vulnerability Report\n'
        report_text += '-------------------------\n'
        print(report_text)

        module_data = self._gather_data()
        for module in module_data:
            print(module['module'])
            print('-' * len(module['module']))
            print()

            for result in module['results']:
                print(f'URL: {result["page"]}')
                print(f'Method: {result["method"]}')
                if result['parameter']:
                    print(f'Parameter[s]: {result["parameter"]}')
                if result['payload']:
                    print(f'Payload: {result["payload"]}')
                print()

    def generate_html(self):
        pass

    def generate_pdf(self):
        pass
