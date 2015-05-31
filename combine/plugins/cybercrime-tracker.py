import datetime

from yapsy.IPlugin import IPlugin


class PluginOne(IPlugin):
    NAME = "cybercrime-tracker"
    DIRECTION = "outbound"
    URLS = ['http://cybercrime-tracker.net/all.php']

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
            if not line.startswith('#') and len(line) > 0:
## FIXME! can have FQDN or IP with URI (duplicate function or re-import ?)
                i = line.split()[0].rsplit('/')[0]
                data.append({'indicator': i, 'indicator_type': "IPv4", 'indicator_direction': self.DIRECTION,
                                 'source_name': self.NAME, 'source': source, 'date': current_date})
        return data
