#!/usr/bin/env python

import requests
import json

server_address = "http://localhost:8080"
token = "E9C74407570DBA7C6D2DE3CE9ECC9699"

friend = {
	"username": "bob"
}

headers = {
	"X-Bro-Token": token
}

r = requests.post(server_address + "/add_friend", data=json.dumps(friend), headers=headers)

print r.status_code
print r.text