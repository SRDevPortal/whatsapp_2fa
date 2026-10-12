const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
let ready, rendered, received, renderedCodeForm = false;
const native = function(data) {
    received = data;
    if (data.verification?.method === "SMS" && data.message !== "Logged In") {
        renderedCodeForm = true;
    }
    return "native-result";
};
const context = {
    window: {}, document: {},
    $: () => ({on: (event, callback) => { assert.equal(event, "login_rendered"); rendered = callback; }}),
    frappe: {ready: callback => { ready = callback; }},
};
vm.runInNewContext(fs.readFileSync("apps/whatsapp_2fa/whatsapp_2fa/public/js/login.js", "utf8"), context);
ready(); // Assets may load before login.js creates its handler.
context.window.login = {login_handlers: {200: native}};
rendered();
const wrapped = context.window.login.login_handlers[200];
rendered(); ready();
assert.equal(context.window.login.login_handlers[200], wrapped);
const challenge = {tmp_id: "test-reference", verification: {method: "WhatsApp", setup: true, prompt: "Enter the WhatsApp code"}};
assert.equal(wrapped(challenge), "native-result");
assert.equal(renderedCodeForm, true);
assert.equal(received.verification.prompt, challenge.verification.prompt);
assert.equal(received.tmp_id, challenge.tmp_id);
assert.equal(challenge.verification.method, "WhatsApp");
for (const method of ["OTP App", "SMS", "Email"]) {
    const response = {verification: {method}};
    wrapped(response);
    assert.equal(received, response);
}
const success = {message: "Logged In"};
wrapped(success);
assert.equal(received, success);
console.log("PASS: WhatsApp opens delivered-code form; prompt/reference preserved; native methods unchanged; adapter installs once");
