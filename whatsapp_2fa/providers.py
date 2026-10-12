"""Provider boundary for authentication-message delivery."""

import re

import frappe


def validate(settings):
	if settings.provider != "Interakt (WA Chat Hub)":
		frappe.throw("Unsupported WhatsApp 2FA provider.")
	if not settings.channel_account or not settings.template_name or not settings.template_language:
		frappe.throw("Complete the WhatsApp 2FA provider configuration.")
	try:
		from wa_chat_hub.authentication import validate_account
	except ImportError:
		frappe.throw("WA Chat Hub must be installed for the selected provider.")
	validate_account(settings.channel_account)


def send(settings, phone, code, reference):
	validate(settings)
	if not re.fullmatch(r"[0-9]{6}", code):
		raise ValueError("Invalid OTP format")
	from wa_chat_hub.authentication import send_login_otp

	return send_login_otp(
		settings.channel_account,
		phone,
		code,
		settings.template_name,
		settings.template_language,
		reference,
	)
