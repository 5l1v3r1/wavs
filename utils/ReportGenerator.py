from conf import config
from util_functions import success, warning
import datetime
import textwrap


class ReportGenerator:
    def __init__(self, main):
        self.main = main

    def generate_txt(self):
        generator = TextReportGenerator(self.main)
        print(generator.render())


class BaseGenerator:
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

    def _gather_stats(self, vuln_data):
        summary = {
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Information": 0
        }

        for thing in vuln_data:
            summary[thing['report']['level']] += len(thing['results'])

        return summary


class TextReportGenerator(BaseGenerator):
    def __init__(self, main):
        BaseGenerator.__init__(self, main)

        self.report_data = self._gather_data()
        self.__report_text = ''

    def _add_text(self, text,indent_level=0, nl=1):
        self.__report_text += f'{"  " * indent_level}{text}'
        if nl:
            t = '\n' * nl
            self.__report_text += t

    def _gen_heading(self, heading, indent_level=0, underline_char='-'):
        self._add_text(f'{heading}'.title(), indent_level)
        self._add_text(f'{underline_char * len(heading)}', indent_level)

    def _gen_summary(self):
        stats = self._gather_stats(self.report_data)

        self._add_text(self._format_heading("Vulnerability Summary"), 1)
        for k, v in stats.items():
            self._add_text(f'{k.capitalize()}: {v}', 2)

    def _gen_section(self, vuln, indent_level):
        report_data = vuln["report"]
        results = vuln["results"]

        self._gen_heading(report_data['vulnerability'], indent_level)
        self._add_text(f'Level: {report_data["level"]}', indent_level + 1)
        self._add_text('Description:', indent_level + 1)
        desc = textwrap.indent(textwrap.fill(report_data["description"], 80), '  ' * (indent_level + 2))
        self._add_text(f'{desc}')
        self._add_text('Mitigation:', indent_level + 1)
        for mit in report_data['mitigation']:
            self._add_text(f'{mit}', indent_level + 2)
        self._add_text(f'CWE Link: {report_data["link"]}', indent_level + 1, 2)
        self._add_text('Instances found', indent_level + 1)
        for r in results:
            self._gen_vuln_detail(r, indent_level+2)

    def _gen_vuln_detail(self, result, indent_level):
        self._add_text(f'URL: \t\t{self.main.get_host_url_base()}/{result["page"]}', indent_level)
        self._add_text(f'Method: \t\t{result["method"]}', indent_level)
        if result['parameter']:
            self._add_text(f'Parameter[s]: \t{result["parameter"]}', indent_level)
        if result['payload']:
            self._add_text(f'Payload: \t\t{result["payload"]}', indent_level, 2)

    def render(self):
        for vuln in self.report_data:
            self._gen_section(vuln, 0)

        return self.__report_text
