"""Install site metadata needed by the WhatsApp authentication method."""

import frappe
from frappe.custom.doctype.property_setter.property_setter import make_property_setter


def sync_system_settings():
    """Append the method without discarding existing site-specific options."""
    field = frappe.get_meta("System Settings", cached=False).get_field("two_factor_method")
    options = (field.options or "").splitlines()
    if "WhatsApp" in options:
        return
    make_property_setter(
        "System Settings", "two_factor_method", "options",
        "\n".join(options + ["WhatsApp"]), "Text",
    )
    frappe.clear_cache(doctype="System Settings")


def sync_user_fields():
    from frappe.custom.doctype.custom_field.custom_field import create_custom_fields
    meta = frappe.get_meta("User", cached=False)
    section_anchor = "login_security_end" if meta.get_field("login_security_end") else "mobile_no"
    create_custom_fields({"User": [
        {"fieldname": "custom_whatsapp_2fa_section", "fieldtype": "Section Break", "label": "WhatsApp Two-Factor Authentication", "insert_after": section_anchor},
        {"fieldname": "custom_whatsapp_verified_number", "fieldtype": "Data", "label": "Verified WhatsApp Number", "read_only": 1, "no_copy": 1, "insert_after": "custom_whatsapp_2fa_section"},
        {"fieldname": "custom_whatsapp_verified_on", "fieldtype": "Datetime", "label": "WhatsApp Verified On", "read_only": 1, "no_copy": 1, "insert_after": "custom_whatsapp_verified_number"},
        {"fieldname": "custom_whatsapp_2fa_enabled", "fieldtype": "Check", "label": "Enable WhatsApp 2FA", "depends_on": "eval:doc.custom_whatsapp_verified_number && (doc.mobile_no || doc.phone || '').trim().replace(/[^\\d+]/g, '') === doc.custom_whatsapp_verified_number", "default": "0", "no_copy": 1, "description": "Verify the saved number first, then enable WhatsApp 2FA for this user.", "insert_after": "custom_whatsapp_verified_on"},
    ]})


def sync_configuration():
    if frappe.get_meta("WhatsApp 2FA Settings").get_field("audit_retention_days"):
        saved = frappe.db.get_singles_dict("WhatsApp 2FA Settings")
        if saved.get("audit_retention_days") in (None, ""):
            frappe.db.set_single_value("WhatsApp 2FA Settings", "audit_retention_days", 30)
    sync_system_settings()
    sync_user_fields()
