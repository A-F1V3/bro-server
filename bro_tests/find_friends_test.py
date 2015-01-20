#!/usr/bin/env python

import requests
import json

server_address = "http://localhost:8080"
token = "E9C74407570DBA7C6D2DE3CE9ECC9699"

friends = []

friends_request = {
	"phone_numbers": ["123-555-0001", "123-555-0002"]
}

headers = {
	"X-Bro-Token": token
}

r = requests.post(server_address + "/find_friends", data=json.dumps(friends_request), headers=headers)

print r.status_code
print r.text