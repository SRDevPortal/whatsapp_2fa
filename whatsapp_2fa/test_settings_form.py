"""Settings validation and metadata checks; no real messages or settings saves."""
import unittest
from unittest.mock import patch
import frappe
from whatsapp_2fa.limits import DEFAULTS, integer


class TestSettingsForm(unittest.TestCase):
    def settings(self, **changes):
        values=dict(DEFAULTS, doctype='WhatsApp 2FA Settings',enabled=0,otp_expiry=300,audit_retention_days=30)
        values.update(changes)
        return frappe.get_doc(values)

    def test_malformed_and_fractional_numbers_have_clear_errors(self):
        for raw in ('abc','1.5',1.5):
            settings=self.settings()
            settings.resend_cooldown=raw
            with self.assertRaisesRegex(frappe.ValidationError,'whole number'):
                integer(settings,'resend_cooldown',60)

    def test_retention_boundaries(self):
        for days in (0,366):
            with self.assertRaises(frappe.ValidationError):
                self.settings(audit_retention_days=days).validate()
        self.settings(audit_retention_days=1).validate()
        self.settings(audit_retention_days=365).validate()

    def test_trim_provider_fields_and_validate_enabled_provider(self):
        doc=self.settings(enabled=1,channel_account=' Confirmation ',template_name=' otp_verification ',template_language=' en ')
        with patch('whatsapp_2fa.providers.validate') as provider:
            doc.validate()
            provider.assert_called_once_with(doc)
        self.assertEqual(doc.channel_account,'Confirmation')
        self.assertEqual(doc.template_name,'otp_verification')
        self.assertEqual(doc.template_language,'en')

    def test_sections_and_conditional_required_fields(self):
        meta=frappe.get_meta('WhatsApp 2FA Settings')
        self.assertEqual(len([f for f in meta.fields if f.fieldtype=='Section Break']),5)
        for field in ('channel_account','template_name','template_language'):
            self.assertEqual(meta.get_field(field).mandatory_depends_on,'eval:doc.enabled')
