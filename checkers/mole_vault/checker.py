#!/usr/bin/env python3

import random
import sys

import requests
from checklib import *
from mole_lib import CheckMachine


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 20
    uses_attack_data: bool = True

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.c = CheckMachine(self)

    def check(self):
        for _ in range(random.randint(3, 6)):
            random.choice([self._check_scenario1, self._check_scenario2])()

        self.cquit(Status.OK)
    
    def put(self, _flag_id: str, flag: str, _vuln: str):
        sess = get_initialized_session()
        username, password = rnd_username(), rnd_password()
        self.c.register(sess, username, password)

        secret_id = self.c.add(sess, flag, False)

        for _ in range(random.randint(1, 20)):
            self.c.add(sess, rnd_string(random.randint(1, 100)), random.choice([True, False]))

        self.cquit(Status.OK, f"{username}:{secret_id}", f"{username}:{secret_id}:{password}")

    def get(self, flag_id: str, flag: str, vuln: str):
        username, secret_id, password = flag_id.split(':')
        s1 = get_initialized_session()
        self.c.login(s1, username, password, status=Status.CORRUPT)

        secret = self.c.get(s1, secret_id, status=Status.CORRUPT)
        self.assert_eq(secret.get('author'), username, 'Invalid author', status=Status.CORRUPT)
        self.assert_eq(secret.get('content'), flag, 'Invalid content', status=Status.CORRUPT)
        self.assert_eq(secret.get('is_public'), False, 'Invalid is_public', status=Status.CORRUPT)
        
        self.cquit(Status.OK)

    def _check_scenario1(self):
        s1 = get_initialized_session()
        username, password = rnd_username(), rnd_password()
        self.c.register(s1, username, password)

        s2 = get_initialized_session()
        self.c.login(s2, username, password)

        s3 = get_initialized_session()
        other_username, other_password = rnd_username(), rnd_password()
        self.c.register(s3, other_username, other_password)

        rnds = lambda: random.choice([s1, s2])

        secrets = []
        for _ in range(10):
            content = rnd_string(random.randint(1, 100))
            public = random.choice([True, False])
            secrets.append((self.c.add(rnds(), content, public), content, public))

        for id, content, public in secrets:
            secret = self.c.get(rnds(), id)
            self.assert_eq(secret.get('author'), username, 'Invalid author')
            self.assert_eq(secret.get('is_public'), public, 'Invalid is_public')
            self.assert_eq(secret.get('content'), content, 'Invalid content')

            if public:
                other_secret = self.c.get(s3, id)
                self.assert_eq(other_secret.get('author', ''), '', 'Public secret author check')
                self.assert_eq(other_secret.get('content'), content, 'Public secret content check')

        self.cquit(Status.OK)

    def _check_scenario2(self):
        s1 = get_initialized_session()
        username, password = rnd_username(), rnd_password()
        self.c.register(s1, username, password)

        s2 = get_initialized_session()
        self.c.login(s2, username, password)

        rnds = lambda: random.choice([s1, s2])

        secrets = []
        for _ in range(60):
            content = rnd_string(random.randint(1, 100))
            secrets.append((self.c.add(rnds(), content, False), content))

        secrets.sort(key=lambda x: x[0])

        lst = self.c.list(rnds())
        self.assert_eq(len(lst), 50, 'Invalid list length')

        got_secrets = []
        start = ''
        for _ in range(2):
            lst = self.c.list(rnds(), start=start)
            if not lst:
                break
            got_secrets.extend(lst)
            start = lst[-1].get('id')

        got_secrets.sort(key=lambda x: x.get('id'))

        for need_secret, got_secret in zip(secrets, got_secrets):
            self.assert_eq(need_secret[0], got_secret.get('id'), 'Invalid id')
            self.assert_eq(need_secret[1], got_secret.get('content'), 'Invalid content')
            self.assert_eq(False, got_secret.get('is_public'), 'Invalid is_public')
            self.assert_eq(username, got_secret.get('author'), 'Invalid author')

        self.cquit(Status.OK)
    
    def action(self, action, *args, **kwargs):
        try:
            super(Checker, self).action(action, *args, **kwargs)
        except requests.exceptions.ConnectionError:
            self.cquit(Status.DOWN, 'Connection error', 'Got requests connection error')

if __name__ == '__main__':
    c = Checker(sys.argv[2])

    try:
        c.action(sys.argv[1], *sys.argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)