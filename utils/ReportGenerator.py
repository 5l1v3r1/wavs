

class ReportGenerator:
    """ generates reports of vulnerabilities found, and mitigation strategies
        into different report formats.
    """

    def __init__(self, main, out_path):
        self.main = main
        self.out_file = out_path

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

        module_data = self._gather_data()
        for module in module_data:
            report_text += module['section_title']
            report_text += '\n--------------------\n'

            # section_data is a list of vulnerabilities found in the module
            for key, value in module['section_data']:
                report_text += ''

    def generate_html(self):
        pass

    def generate_pdf(self):
        pass
