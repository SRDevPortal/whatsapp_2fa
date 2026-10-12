import unittest
from unittest.mock import patch, Mock
import frappe
from whatsapp_2fa import enrollment, resend
from whatsapp_2fa.limits import DEFAULTS, validate_limits
from whatsapp_2fa.test_enrollment import TestEnrollment
from whatsapp_2fa.test_resend import TestLoginResend

class TestCustomEnrollment(TestEnrollment):
    def test_custom_limits_snapshot(self):
        self.settings.get.side_effect=lambda name: {"verification_expiry":120,"verification_attempts":2,"resend_cooldown":20,"verification_sends_per_hour":2}.get(name)
        result=self.send()
        self.assertEqual(result["expires_in"],120)
        self.assertEqual(result["resend_after"],20)
        self.settings.get.side_effect=lambda name: 10
        for _ in range(2):
            with self.assertRaises(frappe.ValidationError): enrollment.verify_number(self.doc.name,"999999")
        self.assertIsNone(self.cache.get_value(enrollment._key(self.doc.name,"challenge")))

class TestCustomLogin(TestLoginResend):
    def test_existing_challenge_retains_expiry(self):
        self.cache.values[self.key].update(code_expiry=120,max_lifetime=500)
        result=resend.resend_login_code(self.tmp)
        self.assertEqual(result["expires_in"],120)

class TestSettingsLimits(unittest.TestCase):
    def settings(self,**changes):
        settings=frappe._dict(DEFAULTS,otp_expiry=300)
        settings.update(changes)
        settings.meta=Mock()
        return settings
    def test_ranges_and_relationships(self):
        for change in ({"login_sends_per_hour":0},{"verification_attempts":11},{"resend_cooldown":300},{"login_max_lifetime":100}):
            with self.assertRaises(frappe.ValidationError): validate_limits(self.settings(**change))
        validate_limits(self.settings(login_sends_per_hour=10,resend_cooldown=30,verification_expiry=120))
