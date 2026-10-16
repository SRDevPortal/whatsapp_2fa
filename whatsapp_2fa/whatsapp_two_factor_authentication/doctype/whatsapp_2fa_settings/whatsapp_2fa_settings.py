import frappe
from frappe.model.document import Document
from whatsapp_2fa.limits import integer, validate_limits


class WhatsApp2FASettings(Document):
    def validate(self):
        self.otp_expiry = integer(self, "otp_expiry", 300)
        if not 60 <= self.otp_expiry <= 600:
            frappe.throw("Login Code Expiry must be between 60 and 600 seconds.")
        validate_limits(self)
        self.audit_retention_days = integer(self, "audit_retention_days", 30)
        if not 1 <= self.audit_retention_days <= 365:
            frappe.throw("Keep Audit Logs For must be between 1 and 365 days.")
        for field in ("channel_account", "template_name", "template_language"):
            value = self.get(field)
            if isinstance(value, str):
                self.set(field, value.strip())
        if self.enabled:
            from whatsapp_2fa.providers import validate
            validate(self)
