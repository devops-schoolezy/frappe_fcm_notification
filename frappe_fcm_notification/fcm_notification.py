import json
import requests
import frappe
from frappe import enqueue
from google.oauth2 import service_account
from google.auth.transport import requests as google_requests
from frappe.utils import now, add_to_date
import re

def cleanhtml(raw_html):
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', raw_html)
    return cleantext


def user_id(doc):
    user_email = doc.for_user
    user_device_id = frappe.get_all(
        "User Device", filters={"user": user_email, "is_active": 1}, fields=["device_token"]
    )
    return user_device_id

@frappe.whitelist()

def notification_queue(doc,method):
    device_token = user_id(doc)
    # frappe.log_error(f"Device Token: {device_token}", "FCM Debugging")
    if device_token:
        for device in device_token:
            enqueue(
                send_fcm_notification,
                queue="default",
                now=False,
                device_token=device,
                notification=doc
            )

    # enqueue(
    #     send_fcm_notification,
    #     queue="default",
    #     now=False,
    #     notification=doc
    # )


@frappe.whitelist()
def get_fcm_credentials():
    """
    Retrieves FCM credentials from FCM Notification Settings DocType.
    """
    credentials_doc = frappe.get_single("FCM Notification Settings")
    service_account_info = {
        "type": "service_account",
        "project_id": credentials_doc.get("project_id"),
        "private_key_id": credentials_doc.get("private_key_id"),
        "private_key": credentials_doc.get_password("private_key").replace("\\n", "\n").strip(),
        "client_email": credentials_doc.get("client_email"),
        "client_id": credentials_doc.get("client_id"),
        "auth_uri": credentials_doc.get("auth_uri"),
        "token_uri": credentials_doc.get("token_uri"),
        "auth_provider_x509_cert_url": credentials_doc.get("auth_provider_x509_cert_url"),
        "client_x509_cert_url": credentials_doc.get("client_x509_cert_url")
    }
    return service_account_info

@frappe.whitelist()
def get_cached_access_token():
    """
    Retrieves the cached access token if valid, otherwise generates a new one.
    """
    try:
        credentials_doc = frappe.get_single("FCM Notification Settings")
        
        if credentials_doc.access_token and credentials_doc.expiration_time > now():
            return {"access_token": credentials_doc.get_password("access_token")}

        service_account_info = get_fcm_credentials()
        credentials = service_account.Credentials.from_service_account_info(
            service_account_info,
            scopes=["https://www.googleapis.com/auth/firebase.messaging"]
        )

        frappe.log_error(f"Credentials: {credentials}", "FCM Credentials Object")

        request = google_requests.Request()
        credentials.refresh(request)
        
        # Log for debugging purposes
        frappe.log_error(f"Refreshed Credentials: {credentials}", "FCM Credentials Object")

        access_token = credentials.token
        expiration_time = add_to_date(now(), minutes=55)

        credentials_doc.access_token = access_token
        credentials_doc.expiration_time = expiration_time
        credentials_doc.save()
        frappe.db.commit()


        return {"access_token": access_token}
    
    except Exception as e:
        frappe.log_error(f"Error in get_cached_access_token: {str(e)}")
        return {"error": str(e)}

@frappe.whitelist()
def send_fcm_notification(notification,device_token): #Add device token #add doc method here when implementin notification log with device token
    """
    Sends a push notification using the cached access token.

    """

    frappe.log_error("Notification:", notification)
    # frappe.log_error(f"Device Token: {device_token[:50]}", "FCM Debugging")
    body = notification.email_content
    title = notification.subject

    body = cleanhtml(body)
    title = cleanhtml(title)

    if isinstance(device_token, dict):
        device_token = device_token.get('device_token')
    access_token = get_cached_access_token()
    headers = {
        'Authorization': f'Bearer {access_token["access_token"]}',
        'Content-Type': 'application/json; UTF-8',
    }
    payload = {
        "message": {
            "token": device_token,
            
            "notification": {
                "title": title,
                "body": body,
            },
        "android": {
        },
        "apns": {
            "payload":{
                "aps":{
                    "sound": 'cash_notification.wav',
                }
            }
        },
            "data": {
                "doctype": notification.document_type,
                "docname": str(notification.document_name),
            }
        }
    }

    frappe.log_error(f"Payload sent: {json.dumps(payload, indent=2)}", "FCM Debugging")


    fcm_endpoint = f'https://fcm.googleapis.com/v1/projects/{get_fcm_credentials()["project_id"]}/messages:send'
    response = requests.post(fcm_endpoint, headers=headers, json=payload)
    
    if response.status_code == 200:
        frappe.log_error("Notification sent successfully:", response.json())
        return {"status": "success", "response": response.json()}
    
    else:
        error_message = f"Failed to send notification: {response.text}"
        frappe.log_error(error_message, "FCM Notification Error")
        
        # Parse error response to check for invalid/unregistered token error codes
        # Reference: https://firebase.google.com/docs/cloud-messaging/error-codes
        should_delete_device = False
        error_code = None
        
        try:
            error_response = response.json()
            
            if isinstance(error_response, dict) and "error" in error_response:
                error_obj = error_response["error"]
                
                # Extract error code from different possible locations in FCM response
                # FCM v1 API can return error codes in status, message, or details
                error_code = (
                    error_obj.get("status") or 
                    error_obj.get("message", "") or
                    ""
                )
                
                # Check details array for FcmError errorCode
                details = error_obj.get("details", [])
                if details and isinstance(details, list):
                    for detail in details:
                        if isinstance(detail, dict):
                            fcm_error_code = detail.get("errorCode") or detail.get("@type", "")
                            if fcm_error_code:
                                error_code = fcm_error_code
                                break
                
                # Official Firebase error codes that indicate invalid/unregistered tokens
                # Reference: https://firebase.google.com/docs/cloud-messaging/error-codes
                invalid_token_codes = [
                    "messaging/registration-token-not-registered",
                    "messaging/invalid-registration-token",
                    "messaging/invalid-argument",
                    "NOT_FOUND",
                    "INVALID_ARGUMENT",
                    "UNREGISTERED"
                ]
                
                # Check if error code matches invalid token codes
                error_code_str = str(error_code).upper()
                error_message_lower = str(error_obj.get("message", "")).lower()
                
                if any(code in error_code_str or code.lower() in error_message_lower for code in invalid_token_codes):
                    should_delete_device = True
                elif any(code in error_message_lower for code in ["registration-token-not-registered", "invalid-registration-token", "invalid-argument", "not found", "unregistered"]):
                    should_delete_device = True
                    
        except (json.JSONDecodeError, AttributeError, KeyError, ValueError) as e:
            # Fallback to string matching if JSON parsing fails
            error_message_lower = error_message.lower()
            if any(err in error_message_lower for err in [
                "registration-token-not-registered",
                "invalid-registration-token", 
                "invalid-argument",
                "notfound",
                "unregistered",
                "requested entity was not found"
            ]):
                should_delete_device = True
        
        if should_delete_device:
            short_token = device_token[:20] + "..."
            frappe.log_error(
                f"Deleted invalid FCM token (starts with): {short_token}, Error code: {error_code}",
                "FCM Cleanup"
            )
            delete_invalid_device(device_token)
        
        return {"status": "failed", "error": error_message}

def delete_invalid_device(token):
    """Deletes User Device record if FCM token is invalid or expired."""
    try:
        device_name = frappe.db.get_value("User Device", {"device_token": token}, "name")
        if device_name:
            frappe.delete_doc("User Device", device_name, force=1)
            frappe.db.commit()
            frappe.logger().info(f"🗑️ Deleted invalid device for token: {token}")
    except Exception as e:
        frappe.logger().error(f"Failed to delete device for token {token}: {e}")

def delete_old_user_devices():
    """Deletes User Device records older than 1 month based on creation time."""
    try:
        # Calculate the cutoff date (1 month ago)
        cutoff_date = add_to_date(now(), months=-1)
        
        # Get all User Device records older than 1 month
        old_devices = frappe.get_all(
            "User Device",
            filters={
                "creation": ["<", cutoff_date]
            },
            fields=["name"]
        )
        
        deleted_count = 0
        for device in old_devices:
            try:
                frappe.delete_doc("User Device", device.name, force=1)
                deleted_count += 1
            except Exception as e:
                frappe.logger().error(f"Failed to delete old device {device.name}: {e}")
        
        frappe.db.commit()
        frappe.logger().info(f"🗑️ Deleted {deleted_count} old User Device records (older than 1 month)")
        return {"status": "success", "deleted_count": deleted_count}
    except Exception as e:
        frappe.logger().error(f"Error in delete_old_user_devices: {e}")
        frappe.log_error(f"Error in delete_old_user_devices: {str(e)}", "FCM Cleanup Error")
        return {"status": "failed", "error": str(e)}
 