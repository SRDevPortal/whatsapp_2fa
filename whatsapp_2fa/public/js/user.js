frappe.ui.form.on("User", {
    refresh(frm) { frm.trigger("whatsapp_2fa_controls"); },
    mobile_no(frm) { frm.trigger("whatsapp_2fa_controls"); },
    phone(frm) { frm.trigger("whatsapp_2fa_controls"); },
    whatsapp_2fa_controls(frm) {
        const currentNumber = (frm.doc.mobile_no || frm.doc.phone || "").trim().replace(/[^\d+]/g, "");
        const verified = Boolean(currentNumber && currentNumber === frm.doc.custom_whatsapp_verified_number);
        frm.toggle_display("custom_whatsapp_2fa_enabled", verified);
        frm.remove_custom_button(__("Verify WhatsApp Number"));
        if (verified) return;
        if (frm.is_new() || frm.doc.name === "Administrator" || frm.doc.name === "Guest") return;
        if (frm.doc.name !== frappe.session.user && !frappe.user.has_role("System Manager")) return;
        frm.add_custom_button(__("Verify WhatsApp Number"), async () => {
            if (frm.is_dirty()) {
                frappe.msgprint(__("Save the User and phone number before requesting verification."));
                return;
            }
            const response = await frappe.call({
                method: "whatsapp_2fa.enrollment.send_verification",
                args: {user: frm.doc.name}, freeze: true,
                freeze_message: __("Sending WhatsApp verification code..."),
            });
            const challenge = response.message;
            if (!challenge) return;
            const dialog = new frappe.ui.Dialog({
                title: __("Verify WhatsApp Number"),
                fields: [
                    {fieldname: "info", fieldtype: "HTML", options: `<p>${frappe.utils.escape_html(__("Enter the code sent to {0}. It expires in {1} seconds.", [challenge.destination, challenge.expires_in]))}</p>`},
                    {fieldname: "code", fieldtype: "Data", label: __("Verification Code"), reqd: 1},
                ],
                primary_action_label: __("Verify"),
                async primary_action(values) {
                    if (!/^\d{6}$/.test(values.code.trim())) {
                        frappe.msgprint(__("Enter the six-digit verification code."));
                        return;
                    }
                    const verified = await frappe.call({
                        method: "whatsapp_2fa.enrollment.verify_number",
                        args: {user: frm.doc.name, code: values.code.trim()}, freeze: true,
                    });
                    if (verified.message?.verified) {
                        dialog.hide();
                        await frm.reload_doc();
                        frappe.msgprint(__("Number verified. You can now enable WhatsApp 2FA for this user and save."));
                    }
                },
            });
            let resendAt = Date.now() + challenge.resend_after * 1000;
            const resend = $('<button type="button" class="btn btn-default btn-sm"></button>');
            dialog.$body.append(resend);
            const updateResend = () => {
                const seconds = Math.max(0, Math.ceil((resendAt - Date.now()) / 1000));
                resend.prop("disabled", seconds > 0).text(seconds ? __("Resend code in {0}s", [seconds]) : __("Resend code"));
            };
            resend.on("click", async () => {
                resend.prop("disabled", true);
                try {
                    const sent = await frappe.call({method: "whatsapp_2fa.enrollment.send_verification", args: {user: frm.doc.name}, freeze: true});
                    if (sent.message) {
                        resendAt = Date.now() + sent.message.resend_after * 1000;
                        dialog.fields_dict.info.$wrapper.html($(`<p></p>`).text(__("Enter the code sent to {0}. It expires in {1} seconds.", [sent.message.destination, sent.message.expires_in])));
                        dialog.set_value("code", "");
                        frappe.show_alert({message: __("New WhatsApp code sent. Use the latest code."), indicator: "green"});
                    }
                } finally { updateResend(); }
            });
            updateResend();
            const timer = setInterval(updateResend, 1000);
            dialog.$wrapper.one("hidden.bs.modal", () => clearInterval(timer));
            dialog.show();
        });
    },
});



