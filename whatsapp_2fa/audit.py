"""Restricted structured audit records. Never accept or persist raw payloads/codes."""
import hashlib
import re
import uuid
from contextlib import contextmanager

import frappe
from frappe.database import get_db
from frappe.utils import add_days, add_to_date, now_datetime

DOCTYPE = "WhatsApp 2FA Log"
TABLE = "`tabWhatsApp 2FA Log`"
RANK = {"Requested": 0, "Unknown": 1, "Accepted": 2, "Sent": 3, "Failed": 4, "Delivered": 5, "Read": 6}


def correlation(reference):
    return hashlib.sha256(str(reference).encode()).hexdigest()


def _identifier(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.+=:/-]{1,140}", value) else None


@contextmanager
def _connection():
    # Commit only audit data. Login/enrollment failures roll back the request DB.
    source = frappe.db
    db = get_db(**{key: getattr(source, key) for key in ("host", "user", "password", "port", "cur_db_name", "socket")})
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _safe(operation):
    try:
        with _connection() as db:
            return operation(db)
    except Exception:
        # Exception details could contain query arguments. Keep diagnostics generic.
        frappe.logger("whatsapp_2fa_audit").error("WhatsApp 2FA audit write failed; check database/schema availability.")
        return None


def _update(db, name, values):
    values = dict(values, modified=now_datetime(), modified_by="Administrator")
    columns = ", ".join(f"`{field}`=%s" for field in values)
    db.sql(f"UPDATE {TABLE} SET {columns} WHERE name=%s", tuple(values.values()) + (name,))


def send(user, flow, action, phone, code, reference, settings, expiry, group=None):
    """One row per send; the code is forwarded but never added to audit data."""
    from whatsapp_2fa.providers import send as provider_send
    name = uuid.uuid4().hex
    group = group or correlation(reference)
    now = now_datetime()
    record = dict(name=name, creation=now, modified=now, owner="Administrator", modified_by="Administrator",
                  docstatus=0, idx=0, user=user, flow=flow, action=action, correlation_reference=group,
                  masked_destination=phone[:3] + "******" + phone[-3:], channel_account=settings.channel_account,
                  delivery_status="Requested", verification_result="Pending", incorrect_attempts=0,
                  sent_at=now, expires_at=add_to_date(now, seconds=int(expiry)))
    def create(db):
        columns=", ".join(f"`{field}`" for field in record)
        placeholders=", ".join(["%s"] * len(record))
        db.sql(f"INSERT INTO {TABLE} ({columns}) VALUES ({placeholders})", tuple(record.values()))
        return name
    stored = _safe(create)
    # The callback is an opaque audit ID, never the usable login challenge ID.
    callback = "wa2fa:" + name
    try:
        result = provider_send(settings, phone, code, callback)
    except Exception:
        if stored:
            _finish(name, "Unknown", None, "Send outcome unavailable")
        raise
    status = {"accepted": "Accepted", "rejected": "Failed"}.get(result.get("outcome"), "Unknown")
    if stored:
        _finish(name, status, _identifier(result.get("message_id")), "Provider rejected request" if status == "Failed" else None)
        if status == "Accepted":
            def supersede(db):
                db.sql(f"UPDATE {TABLE} SET verification_result='Superseded', modified=%s WHERE correlation_reference=%s AND name!=%s AND verification_result IN ('Pending','Incorrect')", (now_datetime(), group, name))
            _safe(supersede)
    return result


def _finish(name, status, message_id, reason):
    def write(db):
        rows=db.sql(f"SELECT delivery_status FROM {TABLE} WHERE name=%s FOR UPDATE", (name,), as_dict=True)
        if not rows:
            return
        values={}
        if RANK[status] >= RANK.get(rows[0].delivery_status, 0):
            values.update(delivery_status=status)
            if reason:
                values['failure_reason']=reason
            if status == 'Failed':
                values['failed_at']=now_datetime()
        if message_id:
            values['provider_message_id']=message_id
        if values:
            _update(db, name, values)
    _safe(write)


def verification(reference, result, *, hashed=False, incorrect=False):
    group = reference if hashed else correlation(reference)
    def write(db):
        rows=db.sql(f"SELECT name, incorrect_attempts, verification_result FROM {TABLE} WHERE correlation_reference=%s AND delivery_status IN ('Accepted','Sent','Delivered','Read') AND verification_result IN ('Pending','Incorrect') ORDER BY creation DESC LIMIT 1 FOR UPDATE", (group,), as_dict=True)
        if not rows:
            return
        values=dict(verification_result=result)
        if incorrect:
            values['incorrect_attempts']=int(rows[0].incorrect_attempts or 0)+1
        if result == 'Successful':
            values['verified_at']=now_datetime()
        _update(db, rows[0].name, values)
    _safe(write)


def delivery_status(channel_account, message_id, status, payload):
    """Internal verified-webhook hook. Extract only IDs and a numeric error code."""
    message=(payload.get('data') or {}).get('message') or {}
    data=payload.get('data') or {}
    callback=next((obj.get(key) for obj in (message, data, payload) for key in ('callbackData','callback_data') if obj.get(key)), '')
    match=re.fullmatch(r"wa2fa:([a-f0-9]{32})", str(callback))
    name=match.group(1) if match else None
    message_id=_identifier(message_id)
    def write(db):
        if name:
            rows=db.sql(f"SELECT name, delivery_status FROM {TABLE} WHERE name=%s AND channel_account=%s FOR UPDATE", (name,channel_account), as_dict=True)
        elif message_id:
            rows=db.sql(f"SELECT name, delivery_status FROM {TABLE} WHERE provider_message_id=%s AND channel_account=%s LIMIT 1 FOR UPDATE", (message_id,channel_account), as_dict=True)
        else:
            return False
        if not rows:
            return bool(match)
        row=rows[0]
        values={}
        if message_id:
            values['provider_message_id']=message_id
        if status in RANK and RANK[status] >= RANK.get(row.delivery_status,0):
            values['delivery_status']=status
            if status in ('Delivered','Read'):
                values.update(delivered_at=now_datetime(), provider_error_code=None, failure_reason=None)
            if status == 'Failed':
                error=str(message.get('channel_error_code') or '')
                values.update(failed_at=now_datetime(), provider_error_code=error if re.fullmatch(r'\d{1,12}',error) else None,
                              failure_reason='Business Account locked' if error=='131031' else 'Provider reported delivery failure')
        if values:
            _update(db,row.name,values)
        return True
    handled=_safe(write)
    # Do not reconstruct OTP chat contents even when audit storage is unavailable.
    return bool(match) or bool(handled)


def cleanup():
    """Daily bounded cleanup; ordinary fields only, no raw payload storage."""
    settings=frappe.get_single('WhatsApp 2FA Settings')
    days=int(settings.audit_retention_days or 30)
    if not 1 <= days <= 365:
        return
    now=now_datetime()
    frappe.db.sql(f"UPDATE {TABLE} SET verification_result='Expired', modified=%s WHERE expires_at < %s AND verification_result IN ('Pending','Incorrect')",(now,now))
    for _ in range(10):
        names=frappe.get_all(DOCTYPE,filters={'creation':['<',add_days(now,-days)]},pluck='name',limit_page_length=5000)
        if not names:
            break
        frappe.db.delete(DOCTYPE,{'name':['in',names]})
