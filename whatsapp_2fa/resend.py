"""Resend only to a password-authenticated, still-eligible login challenge."""
import secrets
import time
import frappe
from frappe import _


def reserve_send(user):
    cache = frappe.cache
    key = "whatsapp_2fa:login-rate:" + user
    with cache.lock(cache.make_key(key + ":lock"), timeout=15, blocking_timeout=5):
        now = time.time()
        rate = cache.get_value(key, expires=True) or {"count": 0, "last": 0, "until": now + 3600}
        if now - rate["last"] < 60:
            frappe.throw(_("Wait 60 seconds before requesting another code."))
        if rate["count"] >= 5:
            frappe.throw(_("Code send limit reached. Try again in one hour."))
        rate.update(count=rate["count"] + 1, last=now)
        cache.set_value(key, rate, expires_in_sec=max(1, int(rate["until"] - now)))


def remember_challenge(user, tmp_id, expiry):
    doc = frappe.get_doc("User", user)
    frappe.cache.set_value("whatsapp_2fa:login:" + tmp_id, {
        "user": user, "number": doc.custom_whatsapp_verified_number, "created": time.time(),
    }, expires_in_sec=expiry)


@frappe.whitelist(allow_guest=True, methods=["POST"])
def resend_login_code(tmp_id):
    from whatsapp_2fa.runtime import should_run_2fa, _deliver
    cache = frappe.cache
    if not isinstance(tmp_id, str) or len(tmp_id) != 32 or not tmp_id.isalnum():
        frappe.throw(_("Login session expired. Log in again."))
    key = "whatsapp_2fa:login:" + tmp_id
    with cache.lock(cache.make_key(key + ":lock"), timeout=30, blocking_timeout=5):
        state = cache.get_value(key, expires=True)
        secret = cache.get(tmp_id + "_otp_secret")
        user = frappe.safe_decode(cache.get(tmp_id + "_usr"))
        token = cache.get(tmp_id + "_token")
        if not state or not secret or not user or token is None or user != state["user"]:
            frappe.throw(_("Login session expired. Log in again."))
        doc = frappe.get_doc("User", user)
        if not doc.enabled or not should_run_2fa(user) or doc.custom_whatsapp_verified_number != state["number"]:
            frappe.throw(_("Login settings changed. Log in again."))
        settings = frappe.get_single("WhatsApp 2FA Settings")
        expiry = min(int(settings.otp_expiry or 300), int(state["created"] + 900 - time.time()))
        if expiry < 1:
            frappe.throw(_("Login session expired. Log in again."))
        reserve_send(user)
        new_token = secrets.randbelow(2**63)
        while new_token == int(token):
            new_token = secrets.randbelow(2**63)
        verification = _deliver(user, new_token, secret, settings, tmp_id)
        cache.set(tmp_id + "_token", new_token)
        for suffix in ("_token", "_usr", "_pwd", "_otp_secret"):
            cache.expire(tmp_id + suffix, expiry)
        cache.set_value(key, state, expires_in_sec=expiry)
        return {"verification": verification, "tmp_id": tmp_id, "expires_in": expiry, "resend_after": 60}
