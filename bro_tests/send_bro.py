#!/usr/bin/env python

import requests
import json

server_address = "http://192.168.0.11:8080"
token = "D563F4ABBDC9C1145ABE2A7F3E9C9D0F"

headers = {
	"X-Bro-Token": token
}

bro = {
	"username": "bob"
}

r = requests.post(server_address + "/bro", data=json.dumps(bro), headers=headers)

print r.status_code
print r.text
