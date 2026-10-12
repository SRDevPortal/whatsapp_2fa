app_name = "whatsapp_2fa"
app_title = "WhatsApp Two Factor Authentication"
app_publisher = "Custom Apps"
app_description = "Secure WhatsApp verification for Frappe login"
app_email = "dev@example.com"
app_license = "mit"

otp_methods = ["WhatsApp"]
from whatsapp_2fa.runtime import install as _install
_install()

after_install = "whatsapp_2fa.setup.sync_configuration"
after_migrate = "whatsapp_2fa.setup.sync_configuration"

doc_events = {
    "System Settings": {"validate": "whatsapp_2fa.validation.validate_system_settings"},
    "User": {"validate": "whatsapp_2fa.enrollment.validate_user"},
}

web_include_js = ["/assets/whatsapp_2fa/js/login.js?v=20261012-limits-1"]
doctype_js = {"User": "public/js/user.js"}


