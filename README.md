### WhatsApp Two Factor Authentication

Secure WhatsApp verification for Frappe login

### Installation

You can install this app using the [bench](https://github.com/frappe/bench) CLI:

```bash
cd $PATH_TO_YOUR_BENCH
bench get-app $URL_OF_THIS_REPO --branch develop
bench install-app whatsapp_2fa
```

### Contributing

This app uses `pre-commit` for code formatting and linting. Please [install pre-commit](https://pre-commit.com/#installation) and enable it for this repository:

```bash
cd apps/whatsapp_2fa
pre-commit install
```

Pre-commit is configured to use the following tools for checking and formatting your code:

- ruff
- eslint
- prettier
- pyupgrade

### License

mit

### WhatsApp method setup

Installation and migration add WhatsApp to the System Settings two-factor
method options through a Property Setter, preserving existing site options.
For an already installed app, apply the customization with:

```bash
bench --site sriaas.local execute whatsapp_2fa.setup.sync_system_settings
bench --site sriaas.local clear-cache
```

Configure and enable WhatsApp 2FA Settings with an active Interakt account,
an approved authentication template, its language, and an expiry of 60-600
seconds. Then reload System Settings and select WhatsApp as the two-factor
method. Saving that selection validates the provider settings without sending
an OTP. Each user needs a valid WhatsApp number in international format
(for example, +91...) in Mobile No or Phone.

Keep the current login method until message delivery has been verified.
Frappe excludes the Administrator account from native two-factor challenges;
use a regular user for the end-to-end login test.

Timing and send/attempt limits described below are defaults and can be changed in WhatsApp 2FA Settings.

### Per-user number verification and activation

On a saved User record, click **Verify WhatsApp Number**, enter the six-digit
code, then select **Enable WhatsApp 2FA** and save. Only the verified saved
Mobile No (or Phone when Mobile No is empty) is used for login delivery.
Verification alone does not activate WhatsApp 2FA. Changing the destination
clears its verification date and disables that user's WhatsApp activation.
Existing users must enroll; no existing number is automatically marked verified.

When System Settings selects WhatsApp, a challenge runs only when site 2FA,
the WhatsApp provider, and the user's verified-number activation are enabled.
Users without all these conditions log in normally without a 2FA challenge.
There is no OTP App, email, or SMS fallback. Existing native 2FA role rules,
Administrator exemption, and restricted-IP settings still apply.

Enrollment endpoints require a logged-in user. Users can verify themselves;
System Managers with write permission can verify another regular user.
The challenge is bound to the user, saved number, and requesting session user.
Codes expire after five minutes, are consumed once, and allow five failed
attempts. Resends require a 60-second wait and are limited to five per hour
per target user. No enrollment code or provider credential is stored in User.

### Resending verification codes

Both the User verification dialog and WhatsApp login form offer **Resend code**
after a 60-second countdown. Sending is limited to five times per hour per user
for each flow. Use the latest code after resending.

Login resend requires the active password-authenticated challenge, rechecks
user activation and the verified destination, and replaces the previous login
code on successful delivery. Expired/completed challenges require a new login.
Resending cannot keep a login challenge alive beyond fifteen minutes.

### Configurable limits

WhatsApp 2FA Settings provides Login Code Sends per Hour (default 5), Number
Verification Sends per Hour (5), Resend Cooldown (60 seconds), Number
Verification Code Expiry (300 seconds), Number Verification Attempts per Code
(5), and Maximum Login Challenge Lifetime (900 seconds). Existing OTP Expiry
continues to control login-code expiry. Send counts include initial sends and
resends and remain separate per user for enrollment and login.

New challenges snapshot their expiry, attempt limit, and maximum lifetime.
Changing settings does not change those values on an existing challenge.
Hourly send limits and resend cooldown use the current configuration.

### Structured authentication audit log

System Managers can open **WhatsApp 2FA Log** (`/app/whatsapp-2fa-log`).
Each send attempt has one row with ordinary fields; resends create separate
rows linked by a non-usable SHA-256 correlation reference. The row records
masked destination, flow/action, provider message ID, delivery and verification
results, incorrect-attempt count, timestamps, and a safe provider error summary.
No JSON, OTP, password, authentication secret, API key, raw webhook payload,
full destination, or usable login challenge is stored in this DocType.

Audit writes use a separate database transaction so failed HTTP/login requests
do not roll back their audit records. They are best effort: storage failures
produce a generic server warning and do not change authentication decisions.
Enrollment success is recorded after its User update commits. Verification
success means the OTP was accepted, not that every later login check passed.
Expired pending records are marked by daily cleanup; Redis expiry alone does
not create an immediate audit event.

The optional WA Chat Hub webhook hook correlates provider IDs or opaque audit
callbacks. New authentication delivery events are consumed before chat-message
reconstruction. A delayed Sent event cannot overwrite Failed, Delivered, or
Read. Provider error text is mapped to fixed safe summaries; raw text is not
stored. Historical chat messages are not removed or backfilled.

**Audit Log Retention (days)** defaults to 30 (allowed range 1-365). A daily
scheduled job marks expired attempts and deletes old audit rows in bounded
batches. The scheduler and worker must be running for automatic cleanup.

Deploy both whatsapp_2fa and wa_chat_hub changes and run the site's migration
before restarting services. This workspace's schema was applied locally to
sriaas.local; this does not deploy changes to a remote site.
