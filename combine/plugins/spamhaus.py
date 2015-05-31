import re

from yapsy.IPlugin import IPlugin


class PluginOne(IPlugin):
    NAME = "spamhaus"
    DIRECTION = "inbound"
    URLS = ['http://www.spamhaus.org/drop/drop.txt', 'http://www.spamhaus.org/drop/edrop.txt' ]

    def get_URLs(self):
        return self.URLS

    def get_direction(self):
        return self.DIRECTION

    def get_name(self):
        return self.NAME

    def process_data(self, source, response):
        data = []
        for line in response.splitlines():
            if line.startswith('; Last-Modified: '):
                date = line.partition('; Last-Modified: ')[2]
            if not line.startswith(';') and len(line) > 0:
                i = line.partition(';')[0].strip()
                data.append({'indicator': i, 'indicator_type': "Subnet", 'indicator_direction': self.DIRECTION,
                             'source_name': self.NAME, 'source': source, 'date': date})
        return data

