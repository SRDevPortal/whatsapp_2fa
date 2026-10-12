// Reuse Frappe's delivered-code form for WhatsApp challenges.
(function () {
    let resendTimer;
    function addResendControl(tmpId, cooldown) {
        if (resendTimer) clearInterval(resendTimer);
        const form = $(".form-verify");
        if (!form.length) return;
        const button = $('<button type="button" class="btn btn-default btn-block mt-3"></button>');
        form.append(button);
        const availableAt = Date.now() + cooldown * 1000;
        const update = () => {
            if (!document.body.contains(button[0])) { clearInterval(resendTimer); return; }
            const seconds = Math.max(0, Math.ceil((availableAt - Date.now()) / 1000));
            button.prop("disabled", seconds > 0).text(seconds ? __("Resend code in {0}s", [seconds]) : __("Resend code"));
        };
        button.on("click", async () => {
            button.prop("disabled", true);
            try {
                const response = await frappe.call({
                    method: "whatsapp_2fa.resend.resend_login_code",
                    args: {tmp_id: tmpId}, freeze: true,
                });
                if (response.message?.verification) {
                    window.login.login_handlers[200](response.message);
                }
            } finally {
                if (document.body.contains(button[0])) update();
            }
        });
        update();
        resendTimer = setInterval(update, 1000);
    }
    function installWhatsAppVerification() {
        const handlers = window.login && window.login.login_handlers;
        if (!handlers || !handlers[200] || handlers[200]._whatsapp2fa) return;
        const nativeHandler = handlers[200];
        function handleVerification(data) {
            const whatsapp = data && data.verification && data.verification.method === "WhatsApp";
            if (data && data.verification && data.verification.method === "WhatsApp") {
                // The native SMS branch renders a delivered-code prompt and submits
                // otp + tmp_id. Keep the actual response and server method intact.
                data = Object.assign({}, data, {
                    verification: Object.assign({}, data.verification, { method: "SMS", prompt: data.verification.prompt + (data.expires_in ? " " + __("Code expires in {0} seconds.", [data.expires_in]) : "") }),
                });
            }
            const result = nativeHandler.apply(this, [data, ...Array.prototype.slice.call(arguments, 1)]);
            if (whatsapp && data.message !== "Logged In") addResendControl(data.tmp_id, data.resend_after || 60);
            return result;
        }
        handleVerification._whatsapp2fa = true;
        handlers[200] = handleVerification;
    }
    $(document).on("login_rendered", installWhatsAppVerification);
    frappe.ready(installWhatsAppVerification);
})();


