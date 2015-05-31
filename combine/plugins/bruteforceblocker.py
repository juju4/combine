import datetime

from yapsy.IPlugin import IPlugin


class PluginOne(IPlugin):
    NAME = "bruteforceblocker"
    DIRECTION = "inbound"
    URLS = ['http://danger.rulez.sk/projects/bruteforceblocker/blist.php' ]

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
                i = line.split()[0]
                date = line.split()[2]
                data.append({'indicator': i, 'indicator_type': "IPv4", 'indicator_direction': self.DIRECTION,
                                 'source_name': self.NAME, 'source': source, 'date': date})
        return data

