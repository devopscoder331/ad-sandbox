# ad-sandbox 

Sandbox for learning and training CTF - Attack & Defense. Generated from [C4T-BuT-S4D/ad-boilerplate] (https://github.com/C4T-BuT-S4D/ad-boilerplate)

## Services

| Service                            | Language    | Checker                       | Sploits                      | Authors                                                  |
|------------------------------------|-------------|-------------------------------|------------------------------|----------------------------------------------------------|
| **[docs](services/docs/)**         | Python & Go | [Checker](checkers/docs/)     | [Sploits](sploits/docs/)     | [C4T-BuT-S4D/ctfcup-2024-ad](https://github.com/C4T-BuT-S4D/ctfcup-2024-ad) |


## Infrastructure

Checksystem: [ForcAD](https://github.com/pomo-mondreganto/ForcAD)

## How send flag



```bash

# Request
curl -X 'PUT' \
  'http://192.168.1.200:8080/flags/' \
  -H 'accept: application/json' \
  -H 'X-Team-Token: 3b01f42ef0272a1f' \
  -H 'Content-Type: application/json' \
  -d '[
  "D8CVHOKORQN21FAAF2GNKE40HQLU1QI="
]'

# Response
[{"flag":"D8CVHOKORQN21FAAF2GNKE40HQLU1QI=","msg":"[D8CVHOKORQN21FAAF2GNKE40HQLU1QI=] Flag accepted! Earned 96.82458365518542 flag points!"}]
```