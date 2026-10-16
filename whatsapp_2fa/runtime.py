"""Bridge WhatsApp delivery into Frappe's native two-factor login."""

import pyotp

import frappe
from frappe.twofactor import get_otpsecret_for_


def install(*_ignored):
	"""Replace only the imported OTP starter, never LoginManager or /login."""
	import frappe.auth

	if getattr(frappe.auth.authenticate_for_2factor, "_whatsapp_2fa", False):
		return
	authenticate_for_2factor._whatsapp_2fa = True
	frappe.auth.authenticate_for_2factor = authenticate_for_2factor
	frappe.auth.should_run_2fa = should_run_2fa
	frappe.auth.confirm_otp_token = confirm_otp_token


def authenticate_for_2factor(user):
	from frappe.twofactor import authenticate_for_2factor as native_authenticate

	if frappe.db.get_single_value("System Settings", "two_factor_method") != "WhatsApp":
		return native_authenticate(user)
	if frappe.form_dict.get("otp"):
		return

	from whatsapp_2fa.enrollment import is_enrolled
	user_doc = frappe.get_doc("User", user)
	if not is_enrolled(user_doc):
		return

	settings = frappe.get_single("WhatsApp 2FA Settings")
	if not settings.enabled:
		return

	from whatsapp_2fa.resend import reserve_send, remember_challenge
	reserve_send(user)
	secret = get_otpsecret_for_(user)
	token = int(pyotp.TOTP(secret).now())
	tmp_id = frappe.generate_hash(length=32)
	_cache_challenge(user, token, secret, tmp_id, int(settings.otp_expiry or 300))
	frappe.local.response["verification"] = _deliver(user, token, secret, settings, tmp_id)
	frappe.local.response["tmp_id"] = tmp_id
	remember_challenge(user, tmp_id, int(settings.otp_expiry or 300))
	from whatsapp_2fa.limits import value
	frappe.local.response["resend_after"] = value(settings, "resend_cooldown")
	frappe.local.response["expires_in"] = int(settings.otp_expiry or 300)


def _cache_challenge(user, token, secret, tmp_id, expiry):
	expiry = max(60, min(expiry, 600))
	values = {
		"_usr": user,
		"_pwd": frappe.form_dict.get("pwd"),
		"_otp_secret": secret,
		"_token": token,
	}
	for suffix, value in values.items():
		frappe.cache.set(f"{tmp_id}{suffix}", value)
		frappe.cache.expire(f"{tmp_id}{suffix}", expiry)


def _deliver(user, token, secret, settings, reference, action="Initial Send", expiry=None):
	from whatsapp_2fa.audit import send

	from whatsapp_2fa.enrollment import is_enrolled
	user_doc = frappe.get_doc("User", user)
	if not is_enrolled(user_doc):
		frappe.throw("Verify and enable this user's WhatsApp number first.", frappe.AuthenticationError)
	destination = user_doc.custom_whatsapp_verified_number

	result = send(user, "Login", action, destination, pyotp.HOTP(secret).at(token), reference, settings, expiry or int(settings.otp_expiry or 300))
	if result.get("outcome") != "accepted":
		frappe.throw(
			"The WhatsApp verification code could not be sent. Try again later.",
			frappe.AuthenticationError,
		)

	masked = destination[:3] + "******" + destination[-3:] if len(destination) > 6 else "******"
	return {
		"token_delivery": True,
		"prompt": f"Enter the verification code sent by WhatsApp to {masked}",
		"method": "WhatsApp",
		"setup": True,
	}



def should_run_2fa(user):
    """Require all WhatsApp activation conditions before entering native 2FA."""
    from frappe.twofactor import should_run_2fa as native_should_run
    from whatsapp_2fa.enrollment import is_enrolled

    if not native_should_run(user):
        return False
    if frappe.db.get_single_value("System Settings", "two_factor_method") != "WhatsApp":
        return True
    if not frappe.db.get_single_value("WhatsApp 2FA Settings", "enabled"):
        return False
    return is_enrolled(frappe.get_doc("User", user))



def confirm_otp_token(login_manager, otp=None, tmp_id=None):
    from frappe.twofactor import confirm_otp_token as native_confirm, ExpiredLoginException
    from whatsapp_2fa.audit import verification
    reference = tmp_id or frappe.form_dict.get("tmp_id")
    attempted = otp or frappe.form_dict.get("otp")
    try:
        result = native_confirm(login_manager, otp=otp, tmp_id=tmp_id)
    except ExpiredLoginException:
        if reference and attempted:
            verification(reference, "Expired")
        raise
    except frappe.AuthenticationError:
        if reference and attempted:
            verification(reference, "Incorrect", incorrect=True)
        raise
    if result and reference and attempted:
        verification(reference, "Successful")
    return result
