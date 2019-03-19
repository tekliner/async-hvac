
from aioresponses import aioresponses
import json as json_util


class Mocker(aioresponses):

    def __init__(self):
        super(Mocker, self).__init__()

    def register_uri(self, method='GET', url='', status_code=200, json=None):
        if json:
            json = json_util.dumps(json)
        else:
            json = ''
        if method == 'GET':
            self.get(url=url, status=status_code, body=json)
        if method == 'POST':
            self.post(url=url, status=status_code, body=json)
        if method == 'DELETE':
            self.delete(url=url, status=status_code, body=json)
