frappe.ui.form.on("WhatsApp 2FA Settings", {
    setup(frm) {
        frm.set_query("channel_account", () => ({
            filters: {channel_type: "Interakt", is_active: 1},
        }));
    },
    refresh(frm) {
        frm.add_custom_button(__("View 2FA Logs"), () => frappe.set_route("List", "WhatsApp 2FA Log"));
        frm.add_custom_button(__("System Settings"), () => frappe.set_route("Form", "System Settings", "System Settings"));
    },
});
