from conf import config
from util_functions import info, success, warning
import datetime
import textwrap
from weasyprint import HTML
from html import escape


class ReportGenerator:
    def __init__(self, main):
        self.main = main
        self.report_type = self.main.options['report_extension']

    def generate_report(self, scan_id):
        if self.report_type == 'html':
            self.generate_html(scan_id)
        elif self.report_type == 'txt':
            self.generate_txt(scan_id)
        elif self.report_type == 'pdf':
            self.generate_pdf(scan_id)

    def generate_txt(self, scan_id):
        generator = TextReportGenerator(self.main, scan_id)
        generator.save_report(generator.render())

    def generate_html(self, scan_id):
        generator = HTMLReportGenerator(self.main, scan_id)
        generator.save_report(generator.render())

    def generate_pdf(self, scan_id):
        generator = PDFReportGenerator(self.main, scan_id)
        generator.save_report(generator.render())


class BaseGenerator:
    """ generates reports of vulnerabilities found, and mitigation strategies
        into different report formats.
    """

    def __init__(self, main, scan_id):
        self.main = main
        self.type = ''
        self.scan_id = scan_id

    def save_report(self, text):
        ext = ''

        if self.type == 'text':
            ext = '.txt'
        elif self.type == 'html':
            ext = '.html'
        elif self.type == 'pdf':
            ext = '.pdf'
        else:
            ext = '.txt'

        date = datetime.datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
        filename = f'WAVS Report - {date}'
        path = f'reports/{filename}{ext}'

        if self.type == 'pdf':
            text.write_pdf(path)
        else:
            try:
                with open(path, 'w') as f:
                    f.write(text)
            except IOError:
                warning(f'Could not save report: {path}')
                exit()

        info(f'Saved report to: {path}')

    def _gather_data(self):
        # get the modules which were run in current scan
        modules_run = self.main.get_modules()

        # get db results for each module
        db_data = [module.get_report_data(self.scan_id) for module in modules_run]
        db_data = list(filter(None, db_data))

        return db_data

    def _gather_scan_details(self):
        scans_table = self.main.db.get_scan_db().table('scans')
        data = scans_table.get(doc_id=self.scan_id)
        return data

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


class PDFReportGenerator(BaseGenerator):
    def __init__(self, main, scan_id):
        BaseGenerator.__init__(self, main, scan_id)
        self.type = 'pdf'

        self.html_gen = HTMLReportGenerator(main)

    def render(self):
        html = self.html_gen.render()
        return HTML(string=html)


class HTMLReportGenerator(BaseGenerator):
    def __init__(self, main, scan_id):
        BaseGenerator.__init__(self, main, scan_id)

        self.type = 'html'
        self.report_data = self._gather_data()
        self.html = ''

    def add_text(self, text):
        self.html += f'{text}'

    def begin_html(self):
        self.add_text('<!doctype html>')
        self.add_text('<html><head><title>WAVS Vulnerability Report</title>')
        self.add_text('<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">')
        self.add_text('<script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN" crossorigin="anonymous"></script>')
        self.add_text('<script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>')
        self.add_text('<script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>')
        #self.add_text('<style>table,th,td {border-collapse: collapse;border: 1px solid black;}td,th{padding: 4px 4px;}</style>')
        self.add_text('</head><body><div class="container">')

    def end_html(self):
        self.add_text('</div></body></html>')

    def add_heading(self, text):
        self.add_text(f'<h2>{text}</h2>')

    def add_header(self):
        html = f'<br><pre class="text-center">{config.banner}</pre>'
        self.add_text(html)

    def add_scan_detail(self):
        data = self._gather_scan_details()

        html = f"""
        <h4 class="text-center">
        <span class="badge badge-dark">
            <span class="badge badge-info">
                Host: {data['host']}
            </span>
            <span class="badge badge-info">
                Port: {data['port']}
            </span>
            <span class="badge badge-info">
                Start: {datetime.datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S.%f').strftime("%d/%m/%Y-%H:%M:%S")}
            </span>
        </span>
        </h4>"""
        self.add_text(html)

    def add_summary(self):
        stats = self._gather_stats(self.report_data)

        self.add_heading("Summary")
        self.add_table(stats, ['Level', 'Number of Alerts'])

    def add_table(self, table_dict, headings=[]):
        table_html = '<p><table class="table table-sm">'
        if headings:
            table_html += f'<thead class="thead-dark"><tr><th>{headings[0]}</th><th>{headings[1]}</th></tr></thead>'

        for k, v in table_dict.items():
            table_html += f'<tr><td>{k}</td><td>{v}</td></tr>'

        table_html += '</table></p><br>'
        self.add_text(table_html)

    def add_list(self, list_items):
        list_html = '<ul>'
        for item in list_items:
            list_html += f'<li>{item.replace("-", "")}</li>'
        list_html += '</ul>'

        return list_html

    def add_section(self, vuln):
        report_data = vuln["report"]
        results = vuln["results"]

        thead_class = ''
        if report_data["level"] == 'High':
            thead_class = 'bg-danger'
        elif report_data["level"] == 'Medium':
            thead_class = 'bg-warning'
        elif report_data["level"] == 'Low':
            thead_class = 'bg-info'
        else:
            thead_class = 'bg-primary'

        table_html = '<p><table class="table table-sm">'
        table_html += f'<thead class="{thead_class}"><tr><th>{report_data["level"]}</th><th>{report_data["vulnerability"]}</th></tr></thead>'
        table_html += f'<tr><td>Description</td><td>{report_data["description"]}</td></tr>'
        table_html += f'<tr><td>Mitigation</td><td>{self.add_list(report_data["mitigation"])}</td></tr>'
        table_html += f'<tr><td>CWE Link</td><td><a href="{report_data["link"]}" target="_blank"><span class="badge badge-success">{report_data["link"]}</span></a></td></tr>'
        table_html += '<thead class="thead-light"><tr><th colspan="2">Instances found</th></tr></thead>'
        table_html += '<tr><td colspan="2"><div class="card-deck">'
        for result in results:
            table_html += self.add_vuln_detail(result)
        table_html += '</div></td></tr></table></p><br>'

        self.add_text(table_html)

    def add_vuln_detail(self, vuln):
        html = f"""
        <div class="card border-danger mb-3" style="max-width: 32rem;">
          <div class="card-header">{vuln['page']}</div>
          <div class="card-body text-danger">
            <p class="card-text">
                <p>URL: {vuln['page']}<br>
                Method: {vuln['method']}<br>
        """
        if vuln['parameter']:
            html += f'Parameter: {vuln["parameter"]}<br>'
        if vuln['payload']:
            # need to use escape function so we dont xss ourselves
            html += f'Payload: {escape(vuln["payload"])}<br>'

        html += '</p></p></div></div>'
        return html

    def render(self):
        self.begin_html()
        self.add_header()
        self.add_scan_detail()
        self.add_summary()
        self.add_heading("Vulnerabilities")
        if len(self.report_data) == 0:
            self.add_text('<div class="alert-success">No vulnerabilities were found.</div>')
        for vuln in self.report_data:
            self.add_section(vuln)
        self.end_html()

        return self.html


class TextReportGenerator(BaseGenerator):
    def __init__(self, main, scan_id):
        BaseGenerator.__init__(self, main, scan_id)

        self.type = 'text'
        self.report_data = self._gather_data()
        self.__report_text = ''

    def _add_text(self, text, indent_level=0, nl=1):
        self.__report_text += f'{"  " * indent_level}{text}'
        if nl:
            t = '\n' * nl
            self.__report_text += t

    def _gen_header(self):
        self._add_text(config.banner)
        self._gen_heading('WAVS Vulnerability Report', 0, '=')

    def _gen_heading(self, heading, indent_level=0, underline_char='-'):
        self._add_text(f'{heading}', indent_level)
        self._add_text(f'{underline_char * len(heading)}', indent_level)

    def _gen_detail(self, indent_level):
        data = self._gather_scan_details()
        self._gen_heading('Scan Details', indent_level)
        self._add_text(f'Scan start: {data["timestamp"]}')
        self._add_text(f'Host: {data["host"]}')
        self._add_text(f'Port: {data["port"]}\n')

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
        desc = textwrap.indent(textwrap.fill(report_data["description"], 80),
                               '  ' * (indent_level + 2))
        self._add_text(f'{desc}')
        self._add_text('Mitigation:', indent_level + 1)
        for mit in report_data['mitigation']:
            self._add_text(f'{mit}', indent_level + 2)
        self._add_text(f'CWE Link: {report_data["link"]}', indent_level + 1, 2)
        self._add_text('Instances found', indent_level + 1)
        for r in results:
            self._gen_vuln_detail(r, indent_level+2)

    def _gen_vuln_detail(self, result, indent_level):
        self._add_text(
            f'URL: {self.main.get_host_url_base()}/{result["page"]}',
            indent_level)
        self._add_text(f'Method: {result["method"]}', indent_level)
        if result['parameter']:
            self._add_text(f'Parameter[s]: {result["parameter"]}',
                           indent_level)
        if result['payload']:
            self._add_text(f'Payload: {result["payload"]}',
                           indent_level,
                           2)

    def render(self):
        self._gen_header()
        self._gen_detail(0)

        for vuln in self.report_data:
            self._gen_section(vuln, 0)

        return self.__report_text
