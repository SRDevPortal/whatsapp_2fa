"""Enrollment regression tests. Delivery is mocked; no messages are sent."""
import unittest
from contextlib import nullcontext
from unittest.mock import Mock, patch

import frappe
from whatsapp_2fa import enrollment, runtime


class MemoryCache:
    def __init__(self):
        self.values = {}
    def make_key(self, key):
        return key
    def lock(self, *args, **kwargs):
        return nullcontext()
    def get_value(self, key, **kwargs):
        return self.values.get(key)
    def set_value(self, key, value, **kwargs):
        self.values[key] = value.copy()
    def delete_value(self, key):
        self.values.pop(key, None)


class TestEnrollment(unittest.TestCase):
    def setUp(self):
        self.cache = MemoryCache()
        self.doc = frappe._dict(name="test@example.com", mobile_no="+14155552671", phone="",
                                custom_whatsapp_verified_number=None, custom_whatsapp_2fa_enabled=0)
        self.settings = Mock(enabled=True)
        self.code = "012345"
        self.patches = [
            patch.object(enrollment, "_authorized_user", return_value=self.doc),
            patch.object(frappe, "cache", self.cache),
            patch.object(frappe, "get_single", return_value=self.settings),
            patch("whatsapp_2fa.providers.send", return_value={"outcome": "accepted"}),
            patch.object(enrollment.secrets, "randbelow", return_value=12345),
            patch.object(enrollment, "now_datetime", return_value="2026-10-12 12:00:00"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def send(self):
        return enrollment.send_verification(self.doc.name)

    def test_verify_does_not_enable_and_is_single_use(self):
        self.send()
        with patch.object(frappe.db, "set_value") as write, patch.object(frappe, "clear_document_cache"):
            self.assertTrue(enrollment.verify_number(self.doc.name, self.code)["verified"])
            fields = write.call_args.args[2]
            self.assertEqual(fields["custom_whatsapp_verified_number"], self.doc.mobile_no)
            self.assertNotIn("custom_whatsapp_2fa_enabled", fields)
            with self.assertRaises(frappe.ValidationError):
                enrollment.verify_number(self.doc.name, self.code)

    def test_wrong_code_limit(self):
        self.send()
        for _ in range(5):
            with self.assertRaises(frappe.ValidationError):
                enrollment.verify_number(self.doc.name, "999999")
        self.assertIsNone(self.cache.get_value(enrollment._key(self.doc.name, "challenge")))

    def test_expiry(self):
        self.send()
        challenge = self.cache.values[enrollment._key(self.doc.name, "challenge")]
        with patch.object(enrollment.time, "time", return_value=challenge["until"] + 1):
            with self.assertRaises(frappe.ValidationError):
                enrollment.verify_number(self.doc.name, self.code)

    def test_changed_number_rejects_old_code(self):
        self.send()
        self.doc.mobile_no = "+442079460018"
        with self.assertRaises(frappe.ValidationError):
            enrollment.verify_number(self.doc.name, self.code)

    def test_actor_binding(self):
        self.send()
        self.cache.values[enrollment._key(self.doc.name, "challenge")]["actor"] = "other@example.com"
        with self.assertRaises(frappe.PermissionError):
            enrollment.verify_number(self.doc.name, self.code)

    def test_resend_limits_and_replaces_previous_code(self):
        with patch.object(enrollment.time, "time", return_value=10000):
            self.send()
            with self.assertRaises(frappe.ValidationError):
                self.send()
        for i in range(1, 5):
            with patch.object(enrollment.time, "time", return_value=10000 + i * 61):
                self.send()
        with patch.object(enrollment.time, "time", return_value=10366):
            with self.assertRaises(frappe.ValidationError):
                self.send()

    def test_failed_delivery_creates_no_challenge(self):
        with patch("whatsapp_2fa.providers.send", return_value={"outcome": "rejected"}):
            with self.assertRaises(frappe.ValidationError):
                self.send()
        self.assertIsNone(self.cache.get_value(enrollment._key(self.doc.name, "challenge")))


class TestUserGuard(unittest.TestCase):
    def doc(self, **values):
        doc = Mock()
        data = frappe._dict(name="test@example.com", mobile_no="+14155552671", phone="",
                           custom_whatsapp_2fa_enabled=0, **values)
        doc.name = data.name
        doc.get.side_effect = data.get
        doc.set.side_effect = lambda k,v: data.__setitem__(k,v)
        doc.is_new.return_value = False
        return doc, data

    def test_number_change_clears_verification_and_activation(self):
        doc, _ = self.doc()
        previous = frappe._dict(custom_whatsapp_verified_number="+442079460018", custom_whatsapp_verified_on="old")
        with patch.object(frappe.db, "get_value", return_value=previous):
            enrollment.validate_user(doc)
        self.assertIsNone(doc.custom_whatsapp_verified_number)
        self.assertIsNone(doc.custom_whatsapp_verified_on)
        self.assertEqual(doc.custom_whatsapp_2fa_enabled, 0)

    def test_new_user_cannot_forge_verification(self):
        doc, data = self.doc()
        doc.is_new.return_value = True
        data.custom_whatsapp_2fa_enabled = 1
        with self.assertRaises(frappe.ValidationError):
            enrollment.validate_user(doc)

    def test_enrollment_requires_verified_matching_number_and_activation(self):
        doc = frappe._dict(mobile_no="+14155552671", custom_whatsapp_verified_number="+14155552671", custom_whatsapp_2fa_enabled=0)
        self.assertFalse(enrollment.is_enrolled(doc))
        doc.custom_whatsapp_2fa_enabled = 1
        self.assertTrue(enrollment.is_enrolled(doc))
        doc.mobile_no = "+442079460018"
        self.assertFalse(enrollment.is_enrolled(doc))

class TestEnrollmentPermissions(unittest.TestCase):
    def test_guest_cannot_enroll(self):
        with patch.dict(frappe.session, {"user": "Guest"}):
            with self.assertRaises(frappe.PermissionError):
                enrollment._authorized_user("test@example.com")

    def test_regular_user_cannot_enroll_another_user(self):
        with patch.dict(frappe.session, {"user": "other@example.com"}), patch.object(frappe, "get_roles", return_value=[]):
            with self.assertRaises(frappe.PermissionError):
                enrollment._authorized_user("test@example.com")
