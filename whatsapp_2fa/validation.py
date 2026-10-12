"""Validate WhatsApp configuration before changing the site's login method."""

import frappe
from frappe import _


def validate_system_settings(doc, method=None):
    if doc.two_factor_method != "WhatsApp":
        return
    settings = frappe.get_single("WhatsApp 2FA Settings")
    if not settings.enabled:
        frappe.throw(_("Enable and configure WhatsApp 2FA Settings before selecting WhatsApp."))
    settings.validate()
