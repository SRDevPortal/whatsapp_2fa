"""Challenge-bound login resend regression checks; never send messages."""
import time
import unittest
from unittest.mock import Mock, patch
import frappe
from whatsapp_2fa import resend
from whatsapp_2fa.test_enrollment import MemoryCache


class LoginCache(MemoryCache):
    def get(self, key): return self.values.get(key)
    def set(self, key, value): self.values[key] = value
    def expire(self, key, ttl): self.expiries[key] = ttl
    def __init__(self):
        super().__init__()
        self.expiries = {}


class TestLoginResend(unittest.TestCase):
    def setUp(self):
        self.cache = LoginCache()
        self.tmp = "a" * 32
        self.key = "whatsapp_2fa:login:" + self.tmp
        self.doc = frappe._dict(enabled=1, custom_whatsapp_verified_number="+14155552671")
        self.cache.values.update({self.key:{"user":"test@example.com", "number":self.doc.custom_whatsapp_verified_number, "created":time.time()}, self.tmp+"_usr":"test@example.com", self.tmp+"_pwd":"private", self.tmp+"_otp_secret":"secret", self.tmp+"_token":123})
        self.patches = [patch.object(frappe,"cache",self.cache), patch.object(frappe,"get_doc",return_value=self.doc), patch.object(frappe,"get_single",return_value=Mock(otp_expiry=300)), patch("whatsapp_2fa.runtime.should_run_2fa",return_value=True), patch("whatsapp_2fa.runtime._deliver",return_value={"method":"WhatsApp"}), patch.object(resend.secrets,"randbelow",return_value=456)]
        for p in self.patches:
            p.start(); self.addCleanup(p.stop)

    def test_success_replaces_code_and_preserves_login_identity(self):
        result = resend.resend_login_code(self.tmp)
        self.assertEqual(result["tmp_id"], self.tmp)
        self.assertEqual(self.cache.get(self.tmp+"_token"),456)
        self.assertEqual(self.cache.get(self.tmp+"_usr"),"test@example.com")
        self.assertEqual(self.cache.get(self.tmp+"_pwd"),"private")
        self.assertEqual(self.cache.expiries[self.tmp+"_token"],300)
        with self.assertRaises(frappe.ValidationError): resend.resend_login_code(self.tmp)

    def test_expired_or_consumed_challenge_cannot_resend(self):
        self.cache.values.pop(self.tmp+"_token")
        with self.assertRaises(frappe.ValidationError): resend.resend_login_code(self.tmp)

    def test_changed_number_cannot_resend(self):
        self.doc.custom_whatsapp_verified_number="+442079460018"
        with self.assertRaises(frappe.ValidationError): resend.resend_login_code(self.tmp)

    def test_disabled_2fa_cannot_resend(self):
        with patch("whatsapp_2fa.runtime.should_run_2fa",return_value=False):
            with self.assertRaises(frappe.ValidationError): resend.resend_login_code(self.tmp)

    def test_failed_send_preserves_previous_token(self):
        with patch("whatsapp_2fa.runtime._deliver",side_effect=frappe.AuthenticationError):
            with self.assertRaises(frappe.AuthenticationError): resend.resend_login_code(self.tmp)
        self.assertEqual(self.cache.get(self.tmp+"_token"),123)

    def test_missing_challenge_and_invalid_reference(self):
        with self.assertRaises(frappe.ValidationError): resend.resend_login_code("short")
        self.cache.values.pop(self.key)
        with self.assertRaises(frappe.ValidationError): resend.resend_login_code(self.tmp)

    def test_maximum_login_lifetime(self):
        self.cache.values[self.key]["created"]=time.time()-901
        with self.assertRaises(frappe.ValidationError): resend.resend_login_code(self.tmp)

    def test_user_send_limit(self):
        for i in range(5):
            with patch.object(resend.time,"time",return_value=10000+i*61): resend.reserve_send("test@example.com")
        with patch.object(resend.time,"time",return_value=10400):
            with self.assertRaises(frappe.ValidationError): resend.reserve_send("test@example.com")
