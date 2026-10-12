"""Regression checks for method selection; never send real messages."""

import unittest
from unittest.mock import Mock, patch

import frappe
from whatsapp_2fa.validation import validate_system_settings


class TestSystemSettingsValidation(unittest.TestCase):
    def test_native_methods_do_not_require_whatsapp_settings(self):
        with patch("whatsapp_2fa.validation.frappe.get_single") as get_single:
            for method in ("OTP App", "SMS", "Email"):
                validate_system_settings(frappe._dict(two_factor_method=method))
            get_single.assert_not_called()

    def test_disabled_provider_blocks_whatsapp_selection(self):
        with patch("whatsapp_2fa.validation.frappe.get_single", return_value=Mock(enabled=False)):
            with self.assertRaises(frappe.ValidationError):
                validate_system_settings(frappe._dict(two_factor_method="WhatsApp"))

    def test_invalid_enabled_provider_blocks_whatsapp_selection(self):
        settings = Mock(enabled=True)
        settings.validate.side_effect = frappe.ValidationError("Invalid provider configuration")
        with patch("whatsapp_2fa.validation.frappe.get_single", return_value=settings):
            with self.assertRaises(frappe.ValidationError):
                validate_system_settings(frappe._dict(two_factor_method="WhatsApp"))

    def test_valid_provider_allows_whatsapp_selection(self):
        settings = Mock(enabled=True)
        with patch("whatsapp_2fa.validation.frappe.get_single", return_value=settings):
            validate_system_settings(frappe._dict(two_factor_method="WhatsApp"))
        settings.validate.assert_called_once_with()
