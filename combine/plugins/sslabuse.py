import datetime

from yapsy.IPlugin import IPlugin


class PluginOne(IPlugin):
    NAME = "sslabuse"
    DIRECTION = "outbound"
    URLS = ['https://sslbl.abuse.ch/blacklist/sslipblacklist.csv' ]

    def get_URLs(self):
        return self.URLS

    def get_direction(self):
        return self.DIRECTION

    def get_name(self):
        return self.NAME

    def process_data(self, source, response):
        data = []
        current_date = str(datetime.date.today())
        for line in response.splitlines():
            if line.startswith('# Last updated: '):
                date = line.partition('# Last updated: ')[2].rstrip('# ')
            if not line.startswith('#') and len(line) > 0:
                i = line.partition(',')[0].strip()
                ## FIXME! where can we put DsPort, Malware Identification?
                data.append({'indicator': i, 'indicator_type': "IPv4", 'indicator_direction': self.DIRECTION,
                                 'source_name': self.NAME, 'source': source, 'date': current_date})
        return data
