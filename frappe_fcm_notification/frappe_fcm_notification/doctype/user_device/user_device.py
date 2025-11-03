# Copyright (c) 2024, Upscape Technologies and contributors
# For license information, please see license.txt

import frappe
import requests
import json
from frappe.model.document import Document
from frappe_fcm_notification.fcm_notification import get_cached_access_token


class UserDevice(Document):
	
	def after_insert(self):
		pass

		# if self.device_type == "ios":
		# 	self.device_token = get_ios_device_token(self.device_token)
		# 	frappe.log_error(f"Device Token:","Device Token")
		# 	self.save()

@frappe.whitelist(allow_guest=True)
def get_ios_device_token(device_token):
	print("inside get_ios_device_token")
	print(device_token)
	access_token = get_cached_access_token()
	
	# frappe.log_error(f"access_token: {access_token}","Access")

	url = "https://iid.googleapis.com/iid/v1:batchImport"

	payload = json.dumps({
		"application": "com.upscape.crm",
		"sandbox":False,
		"apns_tokens":[device_token]
	})

	headers = {
		'access_token_auth': 'true',
		'Content-Type': 'application/json',
		'Authorization': f'Bearer {access_token["access_token"]}'
	}

	response = requests.post(url, headers=headers, data=payload)
	response_data = response.json()
	# frappe.log_error(f"Response: {response.text}","Response")
	# frappe.log_error(f"Response2: {response}","Response")

	

	if response.status_code == 200:
		for result in response_data.get("results", []):
			if result.get("status") == "OK":
				return result.get("registration_token")
			else:
				frappe.log_error(f"Error processing token:", "Token Error")
	else:
		frappe.log_error(f"FCM API Error: {response.text}", "FCM Error")



