#!/usr/bin/env python

import requests
import json

server_address = "http://localhost:8080"
token = "E9C74407570DBA7C6D2DE3CE9ECC9699"

headers = {
	"X-Bro-Token": token
}

r = requests.get(server_address + "/friends", headers=headers)

print r.status_code
print r.text