import requests
from checklib import *

PORT = 8000


class CheckMachine:

    def __init__(self, checker):
        self.checker = checker

    def ping(self):
        r = requests.get(f'http://{self.checker.host}:{PORT}/', timeout=3)
        self.checker.check_response(r, 'Check failed')

    def put_flag(self, flag, vuln):
        # TODO: Implement flag placement logic
        pass

    def get_flag(self, flag_id, flag, vuln):
        # TODO: Implement flag retrieval logic
        pass
