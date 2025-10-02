from checklib import *

PORT = 31339

class CheckMachine:
    @property
    def url(self):
        return f"http://{self.c.host}:{self.port}"

    def __init__(self, c: BaseChecker):
        self.c = c
        self.port = PORT

    def register(self, s, username: str, password: str) -> None:
        resp = s.post(f"{self.url}/register", data={"username": username, "password": password})
        self.c.check_response(resp, 'Registration failed')
        s.headers["Authentication"] = resp.headers.get("Authentication")

    def login(self, s, username: str, password: str, status: int = Status.MUMBLE) -> None:
        resp = s.post(f"{self.url}/login", data={"username": username, "password": password})
        self.c.check_response(resp, 'Login failed')
        s.headers["Authentication"] = resp.headers.get("Authentication")

    def add(self, s, content: str, is_public: bool, status: int = Status.MUMBLE) -> str:
        resp = s.post(f"{self.url}/add", data={"content": content, "is_public": 'true' if is_public else 'false'})
        self.c.check_response(resp, 'Add failed', status=status)
        self.c.assert_in('id', self.c.get_json(resp, 'Add failed'), 'Add failed')
        return self.c.get_json(resp, 'Add failed')['id']

    def get(self, s, id: str, status: int = Status.MUMBLE) -> dict:
        resp = s.get(f"{self.url}/get", params={"id": id})
        self.c.check_response(resp, 'Get failed', status=status)
        return self.c.get_json(resp, 'Get failed')

    def list(self, s, start: str = "", status: int = Status.MUMBLE) -> list[dict]:
        resp = s.get(f"{self.url}/list", params={"start": start})
        self.c.check_response(resp, 'List failed', status=status)
        res = self.c.get_json(resp, 'List failed')
        if res is None:
            return []
        return res
