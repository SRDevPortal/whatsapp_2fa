"""WhatsApp challenges require all activation conditions; no fallback."""
import unittest
from unittest.mock import patch
import frappe
from whatsapp_2fa import runtime


class TestLoginGate(unittest.TestCase):
    def test_all_four_conditions(self):
        for site_enabled in (False, True):
            for whatsapp_method in (False, True):
                for provider_enabled in (False, True):
                    for verified in (False, True):
                        for user_enabled in (False, True):
                            doc = frappe._dict(mobile_no="+14155552671", custom_whatsapp_verified_number="+14155552671" if verified else None, custom_whatsapp_2fa_enabled=int(user_enabled))
                            def setting(doctype, field):
                                if doctype == "WhatsApp 2FA Settings":
                                    return provider_enabled
                                return "WhatsApp" if whatsapp_method else "OTP App"
                            with patch("frappe.twofactor.should_run_2fa", return_value=site_enabled), patch.object(frappe.db, "get_single_value", side_effect=setting), patch.object(frappe, "get_doc", return_value=doc):
                                expected = site_enabled and (not whatsapp_method or (provider_enabled and verified and user_enabled))
                                self.assertEqual(runtime.should_run_2fa("test@example.com"), expected)

    def test_unenrolled_starter_sends_nothing(self):
        with patch.object(frappe.db, "get_single_value", return_value="WhatsApp"), patch.object(frappe, "get_doc", return_value=frappe._dict()), patch.object(runtime, "_deliver") as delivery, patch("frappe.twofactor.authenticate_for_2factor") as native:
            runtime.authenticate_for_2factor("test@example.com")
            delivery.assert_not_called()
            native.assert_not_called()

    def test_login_manager_uses_gate(self):
        import frappe.auth
        runtime.install()
        self.assertIs(frappe.auth.should_run_2fa, runtime.should_run_2fa)
