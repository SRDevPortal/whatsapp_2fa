"""Database-backed audit tests. Transport is mocked; no real OTP is sent."""
import json
import uuid
import unittest
from unittest.mock import Mock, patch

import frappe
from frappe.utils import add_days, now_datetime
from whatsapp_2fa import audit


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.reference=uuid.uuid4().hex
        self.group=audit.correlation(self.reference)
        self.settings=frappe._dict(channel_account='Audit Test')
        self.ids=[]

    def tearDown(self):
        with audit._connection() as db:
            db.sql(f'DELETE FROM {audit.TABLE} WHERE correlation_reference=%s',(self.group,))

    def send(self,action='Initial Send',outcome='accepted'):
        provider_id='audit-test-'+uuid.uuid4().hex
        with patch('whatsapp_2fa.providers.send',return_value={'outcome':outcome,'message_id':provider_id}) as transport:
            audit.send('Administrator','Login',action,'+14155552671','123456',self.reference,self.settings,300)
        self.assertTrue(transport.call_args.args[3].startswith('wa2fa:'))
        self.assertNotIn(self.reference,transport.call_args.args[3])
        name=transport.call_args.args[3].split(':')[1]
        self.ids.append(name)
        return name,provider_id

    def row(self,name):
        with audit._connection() as db:
            return db.sql(f'SELECT * FROM {audit.TABLE} WHERE name=%s',(name,),as_dict=True)[0]

    def test_normal_fields_and_no_secrets(self):
        name,_=self.send()
        row=self.row(name)
        self.assertEqual(row.delivery_status,'Accepted')
        self.assertEqual(row.masked_destination,'+14******671')
        serialized=json.dumps(row,default=str)
        for secret in ('123456',self.reference,'+14155552671'):
            self.assertNotIn(secret,serialized)
        self.assertFalse(any(f.fieldtype in ('JSON','Code','Long Text') for f in frappe.get_meta(audit.DOCTYPE).fields))

    def test_failed_send_survives_request_rollback(self):
        name,_=self.send(outcome='rejected')
        frappe.db.rollback()
        self.assertEqual(self.row(name).delivery_status,'Failed')

    def test_resend_supersedes_old_attempt(self):
        first,_=self.send()
        second,_=self.send(action='Resend')
        self.assertEqual(self.row(first).verification_result,'Superseded')
        self.assertEqual(self.row(second).verification_result,'Pending')
        audit.verification(self.reference,'Incorrect',incorrect=True)
        audit.verification(self.reference,'Successful')
        row=self.row(second)
        self.assertEqual(row.incorrect_attempts,1)
        self.assertEqual(row.verification_result,'Successful')
        self.assertTrue(row.verified_at)

    def test_failed_resend_keeps_previous_challenge_pending(self):
        first,_=self.send()
        self.send(action='Resend',outcome='rejected')
        self.assertEqual(self.row(first).verification_result,'Pending')

    def test_webhook_failure_not_downgraded_by_delayed_sent(self):
        name,message_id=self.send()
        payload={'data':{'message':{'callback_data':'wa2fa:'+name,'channel_error_code':131031,'channel_failure_reason':'Unsafe raw detail 123456'}}}
        self.assertTrue(audit.delivery_status('Audit Test',message_id,'Failed',payload))
        self.assertTrue(audit.delivery_status('Audit Test',message_id,'Sent',payload))
        row=self.row(name)
        self.assertEqual(row.delivery_status,'Failed')
        self.assertEqual(row.provider_error_code,'131031')
        self.assertEqual(row.failure_reason,'Business Account locked')
        self.assertNotIn('123456',json.dumps(row,default=str))

    def test_provider_id_lookup_and_channel_scope(self):
        name,message_id=self.send()
        self.assertFalse(audit.delivery_status('Different Account',message_id,'Delivered',{}))
        self.assertTrue(audit.delivery_status('Audit Test',message_id,'Delivered',{}))
        self.assertTrue(self.row(name).delivered_at)

    def test_callback_before_response_and_missing_record(self):
        name,message_id=self.send()
        payload={'data':{'message':{'callbackData':'wa2fa:'+name,'channel_error_code':131031}}}
        audit.delivery_status('Audit Test',message_id,'Failed',payload)
        audit._finish(name,'Accepted',message_id,None)
        self.assertEqual(self.row(name).delivery_status,'Failed')
        self.assertTrue(audit.delivery_status('Audit Test','missing','Failed',{'callbackData':'wa2fa:'+uuid.uuid4().hex}))

    def test_concurrent_delivery_updates_preserve_final_state(self):
        from concurrent.futures import ThreadPoolExecutor
        name,message_id=self.send()
        site=frappe.local.site
        def deliver(status):
            frappe.init(site=site)
            frappe.connect()
            try:
                return audit.delivery_status('Audit Test',message_id,status,{})
            finally:
                frappe.destroy()
        with ThreadPoolExecutor(max_workers=3) as executor:
            results=list(executor.map(deliver,['Failed','Sent','Read']))
        self.assertTrue(all(results))
        self.assertEqual(self.row(name).delivery_status,'Read')

    def test_storage_failure_does_not_change_provider_result(self):
        with patch.object(audit,'_connection',side_effect=RuntimeError('unavailable')),patch('whatsapp_2fa.providers.send',return_value={'outcome':'accepted'}):
            result=audit.send('Administrator','Login','Initial Send','+14155552671','123456',self.reference,self.settings,300)
            self.assertEqual(result['outcome'],'accepted')

    def test_only_system_manager_can_read(self):
        self.assertFalse(frappe.has_permission(audit.DOCTYPE,'read',user='Guest'))
        permissions=frappe.get_meta(audit.DOCTYPE).permissions
        self.assertEqual([p.role for p in permissions],['System Manager'])
        self.assertFalse(permissions[0].write)
        self.assertFalse(permissions[0].create)

    def test_cleanup_and_expiry(self):
        old,_=self.send()
        current,_=self.send(action='Resend')
        with audit._connection() as db:
            db.sql(f'UPDATE {audit.TABLE} SET creation=%s WHERE name=%s',(add_days(now_datetime(),-31),old))
            db.sql(f'UPDATE {audit.TABLE} SET expires_at=%s WHERE name=%s',(add_days(now_datetime(),-1),current))
        with patch.object(frappe,'get_single',return_value=frappe._dict(audit_retention_days=30)):
            audit.cleanup()
        # Observe within the cleanup transaction; its writes are rolled back by the test.
        self.assertFalse(frappe.db.exists(audit.DOCTYPE,old))
        self.assertEqual(frappe.db.get_value(audit.DOCTYPE,current,'verification_result'),'Expired')
        frappe.db.rollback()


class TestVerificationWrapper(unittest.TestCase):
    def test_native_result_and_error_are_preserved(self):
        from whatsapp_2fa.runtime import confirm_otp_token
        with patch('frappe.twofactor.confirm_otp_token',return_value=True), patch.object(audit,'verification') as record:
            self.assertTrue(confirm_otp_token(Mock(),otp='123456',tmp_id='reference'))
            record.assert_called_once_with('reference','Successful')
        with patch('frappe.twofactor.confirm_otp_token',side_effect=frappe.AuthenticationError), patch.object(audit,'verification') as record:
            with self.assertRaises(frappe.AuthenticationError):
                confirm_otp_token(Mock(),otp='123456',tmp_id='reference')
            record.assert_called_once_with('reference','Incorrect',incorrect=True)

class TestWebhookAuditBridge(unittest.TestCase):
    def test_authentication_webhook_does_not_create_chat_message(self):
        from wa_chat_hub.api import webhook
        with patch.object(webhook,'_route_authentication_status',return_value=True), patch.object(webhook,'append_message') as append:
            result=webhook._create_interakt_outbound_from_webhook({'channel_account':'Audit Test','data':{'message':{'id':'message-id'}}},'Failed')
            self.assertTrue(result['authentication'])
            append.assert_not_called()

    def test_optional_hook_is_not_required_by_chat_hub(self):
        from wa_chat_hub.api import webhook
        with patch.object(frappe,'get_hooks',return_value=[]):
            self.assertFalse(webhook._route_authentication_status('account','id','Sent',{}))
        handler=Mock(return_value=True)
        with patch.object(frappe,'get_hooks',return_value=['example.handler']),patch.object(frappe,'get_attr',return_value=handler):
            self.assertTrue(webhook._route_authentication_status('account','id','Sent',{}))
            handler.assert_called_once_with('account','id','Sent',{})

    def test_transport_uses_opaque_audit_callback(self):
        from wa_chat_hub import authentication
        response=Mock(status_code=200)
        response.json.return_value={'result':True,'id':'provider-id'}
        account=Mock()
        account.get_password.return_value='mock-credential'
        with patch.object(authentication,'validate_account',return_value=account),patch.object(authentication.requests,'post',return_value=response) as post:
            authentication.send_login_otp('account','+14155552671','123456','template','en','wa2fa:'+'a'*32)
            self.assertEqual(post.call_args.kwargs['json']['callbackData'],'wa2fa:'+'a'*32)

