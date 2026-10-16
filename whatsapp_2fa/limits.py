"""Defaults also cover challenges/settings created before configurable limits."""
import frappe
DEFAULTS = {"login_sends_per_hour":5, "verification_sends_per_hour":5, "resend_cooldown":60,
            "verification_expiry":300, "verification_attempts":5, "login_max_lifetime":900}
RANGES = {"login_sends_per_hour":(1,100), "verification_sends_per_hour":(1,100),
          "resend_cooldown":(10,3600), "verification_expiry":(60,600),
          "verification_attempts":(1,10), "login_max_lifetime":(60,3600)}

def integer(settings, name, default):
    raw = settings.get(name)
    if raw is None or raw == "" or not isinstance(raw, (int, float, str)):
        return default
    try:
        number = int(raw)
        if isinstance(raw, float) and raw != number:
            raise ValueError
    except (ValueError, TypeError, OverflowError):
        frappe.throw(f"{settings.meta.get_label(name)} must be a whole number.")
    return number


def value(settings, name):
    return integer(settings, name, DEFAULTS[name])

def validate_limits(settings):
    for name, (low, high) in RANGES.items():
        if not low <= value(settings, name) <= high:
            frappe.throw(f"{settings.meta.get_label(name)} must be between {low} and {high}.")
    if value(settings, "resend_cooldown") >= min(value(settings, "verification_expiry"), int(settings.otp_expiry or 300)):
        frappe.throw("Resend Cooldown must be shorter than both code expiry times.")
    if value(settings, "login_max_lifetime") < int(settings.otp_expiry or 300):
        frappe.throw("Total Login Time Limit must be at least Login Code Expiry.")
