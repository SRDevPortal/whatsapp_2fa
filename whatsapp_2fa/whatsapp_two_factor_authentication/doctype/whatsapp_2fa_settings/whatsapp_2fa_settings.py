import frappe
from frappe.model.document import Document


class WhatsApp2FASettings(Document):
	def validate(self):
		if not 60 <= int(self.otp_expiry or 0) <= 600:
			frappe.throw("OTP Expiry must be between 60 and 600 seconds.")
		if self.enabled:
			from whatsapp_2fa.providers import validate

			validate(self)
