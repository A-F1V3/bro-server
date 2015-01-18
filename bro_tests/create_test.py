#!/usr/bin/env python

import requests
import json

server_address = "http://192.168.0.11:8080"

user = {
	"username": "fred",
	"phone": 	"123-555-0002",
	"password": "testpass"
}

r = requests.post(server_address + "/sign_up", data=json.dumps(user))

print r.status_code
print r.text