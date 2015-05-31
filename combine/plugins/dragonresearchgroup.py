import datetime

from yapsy.IPlugin import IPlugin


class PluginOne(IPlugin):
    NAME = "dragonresearchgroup"
    DIRECTION = "inbound"
    URLS = ['http://dragonresearchgroup.org/insight/sshpwauth.txt',
            'http://dragonresearchgroup.org/insight/vncprobe.txt',
            'https://dragonresearchgroup.org/insight/http-report.txt'
            ]

    def get_URLs(self):
        return self.URLS

    def get_direction(self):
        return self.DIRECTION

    def get_name(self):
        return self.NAME

    def process_data(self, source, response):
        data = []
        for line in response.splitlines():
            if not line.startswith('#') and len(line) > 0:
                i = line.split('|')[2].strip()
                date = line.split('|')[3].strip()
## FIXME! have AS(num+name) inside report, how to keep that
                if 'sshpwauth' in source:
                    data.append({'indicator': i, 'indicator_type': "IPv4", 'indicator_direction': self.DIRECTION,
                                 'source_name': self.NAME, 'source': source, 'note': 'sshpwauth', 'date': date})
                if 'vncprobe' in source:
                    data.append({'indicator': i, 'indicator_type': "IPv4", 'indicator_direction': self.DIRECTION,
                                 'source_name': self.NAME, 'source': source, 'note': 'vncprobe', 'date': date})
                if 'http-report' in source:
                    data.append({'indicator': i, 'indicator_type': "Subnet", 'indicator_direction': self.DIRECTION,
                                 'source_name': self.NAME, 'source': source, 'note': 'http-report', 'date': date})
        return data
