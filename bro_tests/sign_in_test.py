#!/usr/bin/env python

import requests
import json

server_address = "http://192.168.0.11:8080"

user = {
	"username": "testuser",
	"password": "testpass",
	"device_id": "testdevice",
	"device_type": "python"
}

r = requests.post(server_address + "/sign_in", data=json.dumps(user))

print r.status_code
print r.text
