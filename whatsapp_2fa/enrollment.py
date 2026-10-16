"""Authenticated, rate-limited proof of ownership for User WhatsApp numbers."""

import hashlib
import hmac
import secrets
import time

import frappe
import phonenumbers
from frappe import _
from frappe.utils import cint, now_datetime

VERIFIED_FIELDS = ("custom_whatsapp_verified_number", "custom_whatsapp_verified_on")


def number_for(user):
    return (user.get("mobile_no") or user.get("phone") or "").strip()


def normalize(number, required=True):
    try:
        parsed = phonenumbers.parse(number, None)
        if not number.startswith("+") or not phonenumbers.is_valid_number(parsed):
            raise ValueError
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except (phonenumbers.NumberParseException, ValueError):
        if required:
            frappe.throw(_("Enter a valid WhatsApp number with country code in Mobile No or Phone (for example +91...)."))
        return ""


def is_enrolled(user):
    number = normalize(number_for(user), required=False)
    return bool(cint(user.get("custom_whatsapp_2fa_enabled")) and number
                and number == user.get("custom_whatsapp_verified_number"))


def validate_user(doc, method=None):
    # Read-only fields must also be protected against crafted API saves/imports.
    previous = frappe.db.get_value("User", doc.name, list(VERIFIED_FIELDS), as_dict=True) if not doc.is_new() else None
    number = normalize(number_for(doc), required=False)
    verified = previous and previous.custom_whatsapp_verified_number
    if not number or number != verified:
        doc.custom_whatsapp_verified_number = None
        doc.custom_whatsapp_verified_on = None
        if verified:
            doc.custom_whatsapp_2fa_enabled = 0
    else:
        for field in VERIFIED_FIELDS:
            doc.set(field, previous.get(field))
    if cint(doc.get("custom_whatsapp_2fa_enabled")):
        if not is_enrolled(doc):
            frappe.throw(_("Verify this user's WhatsApp number before enabling WhatsApp 2FA."))
        settings = frappe.get_single("WhatsApp 2FA Settings")
        if not settings.enabled:
            frappe.throw(_("Enable WhatsApp 2FA Settings first."))
        settings.validate()


def _authorized_user(user, for_update=False):
    if frappe.session.user == "Guest":
        frappe.throw(_("Please log in first."), frappe.PermissionError)
    if frappe.session.user != user and "System Manager" not in frappe.get_roles():
        frappe.throw(_("You may only verify your own WhatsApp number."), frappe.PermissionError)
    doc = frappe.get_doc("User", user, for_update=for_update)
    doc.check_permission("write")
    if user in ("Guest", "Administrator") or not doc.enabled:
        frappe.throw(_("Select an enabled regular user for WhatsApp verification."))
    return doc


def _key(user, suffix):
    return "whatsapp_2fa:enroll:" + user + ":" + suffix


def _digest(reference, code):
    return hashlib.sha256((reference + ":" + code).encode()).hexdigest()


@frappe.whitelist(methods=["POST"])
def send_verification(user):
    doc = _authorized_user(user)
    number = normalize(number_for(doc))
    settings = frappe.get_single("WhatsApp 2FA Settings")
    if not settings.enabled:
        frappe.throw(_("Enable WhatsApp 2FA Settings first."))
    settings.validate()
    from whatsapp_2fa.limits import value
    cooldown = value(settings, "resend_cooldown")
    expiry = value(settings, "verification_expiry")
    cache = frappe.cache
    with cache.lock(cache.make_key(_key(user, "lock")), timeout=30, blocking_timeout=5):
        now = time.time()
        rate = cache.get_value(_key(user, "rate"), expires=True) or {"count": 0, "last": 0, "until": now + 3600}
        if now - rate["last"] < cooldown:
            frappe.throw(_("Wait {0} seconds before requesting another code.").format(cooldown))
        if rate["count"] >= value(settings, "verification_sends_per_hour"):
            frappe.throw(_("Verification send limit reached. Try again in one hour."))
        rate["count"] += 1
        rate["last"] = now
        cache.set_value(_key(user, "rate"), rate, expires_in_sec=max(1, int(rate["until"] - now)))
        previous = cache.get_value(_key(user, "challenge"), expires=True)
        cache.delete_value(_key(user, "challenge"))
        code = f"{secrets.randbelow(1000000):06d}"
        reference = secrets.token_hex(24)
        from whatsapp_2fa.audit import send, correlation
        group = previous.get("audit_group") if previous else None
        group = group or correlation(reference)
        result = send(user, "Number Verification", "Resend" if previous else "Initial Send", number, code, reference, settings, expiry, group=group)
        if result.get("outcome") != "accepted":
            frappe.throw(_("The verification code could not be sent. Try again later."))
        challenge = {"number": number, "actor": frappe.session.user, "reference": reference,
                     "audit_group": group, "digest": _digest(reference, code), "attempts": 0, "max_attempts": value(settings, "verification_attempts"), "until": now + expiry}
        cache.set_value(_key(user, "challenge"), challenge, expires_in_sec=expiry)
        return {"destination": number[:3] + "******" + number[-3:], "expires_in": expiry, "resend_after": cooldown}


@frappe.whitelist(methods=["POST"])
def verify_number(user, code):
    _authorized_user(user)
    from whatsapp_2fa.audit import verification
    cache = frappe.cache
    with cache.lock(cache.make_key(_key(user, "lock")), timeout=30, blocking_timeout=5):
        challenge = cache.get_value(_key(user, "challenge"), expires=True)
        now = time.time()
        if not challenge or challenge["until"] <= now:
            if challenge and challenge.get("audit_group"):
                verification(challenge["audit_group"], "Expired", hashed=True)
            frappe.throw(_("Verification expired. Request a new code."))
        if challenge["actor"] != frappe.session.user:
            frappe.throw(_("Request a verification code from your own session."), frappe.PermissionError)
        doc = _authorized_user(user, for_update=True)
        if normalize(number_for(doc)) != challenge["number"]:
            if challenge.get("audit_group"):
                verification(challenge["audit_group"], "Superseded", hashed=True)
            cache.delete_value(_key(user, "challenge"))
            frappe.throw(_("The number changed. Request a new verification code."))
        if not hmac.compare_digest(challenge["digest"], _digest(challenge["reference"], str(code).strip())):
            challenge["attempts"] += 1
            if challenge.get("audit_group"):
                verification(challenge["audit_group"], "Attempts Exhausted" if challenge["attempts"] >= challenge.get("max_attempts",5) else "Incorrect", hashed=True, incorrect=True)
            if challenge["attempts"] >= challenge.get("max_attempts", 5):
                cache.delete_value(_key(user, "challenge"))
            else:
                cache.set_value(_key(user, "challenge"), challenge, expires_in_sec=max(1, int(challenge["until"] - now)))
            frappe.throw(_("Incorrect verification code. After {0} attempts you must request a new code.").format(challenge.get("max_attempts", 5)))
        frappe.db.set_value("User", user, {
            "custom_whatsapp_verified_number": challenge["number"],
            "custom_whatsapp_verified_on": now_datetime(),
        })
        frappe.clear_document_cache("User", user)
        # Consume once. A database rollback requires a fresh verification code.
        cache.delete_value(_key(user, "challenge"))
        if challenge.get("audit_group"):
            group = challenge["audit_group"]
            frappe.db.after_commit.add(lambda: verification(group, "Successful", hashed=True))
        return {"verified": True}
