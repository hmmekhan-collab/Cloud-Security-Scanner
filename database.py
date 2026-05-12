"""Database layer using Supabase"""
import os
from datetime import datetime
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Supabase Client
url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)

def init_db():
    # Tables are manually created via supabase_schema.sql in the Supabase Dashboard
    pass

# Users
def user_get(uid):
    response = supabase.table('users').select('*').eq('id', uid).execute()
    return response.data[0] if response.data else None

def user_by_email(email):
    response = supabase.table('users').select('*').eq('email', email).execute()
    return response.data[0] if response.data else None

def user_create(full_name, email, org, pw_hash, role='admin'):
    data = {"full_name": full_name, "email": email, "organization": org, "password_hash": pw_hash, "role": role}
    response = supabase.table('users').insert(data).execute()
    return response.data[0] if response.data else None

def user_update(uid, **kw):
    response = supabase.table('users').update(kw).eq('id', uid).execute()
    return response.data[0] if response.data else None

def user_count():
    response = supabase.table('users').select('*', count='exact').execute()
    return response.count or 0

# Accounts
def accounts_by_user(uid):
    response = supabase.table('cloud_accounts').select('*').eq('user_id', uid).order('created_at', desc=True).execute()
    return response.data

def account_get(aid, uid):
    response = supabase.table('cloud_accounts').select('*').eq('id', aid).eq('user_id', uid).execute()
    return response.data[0] if response.data else None

def account_create(uid, provider, alias, access_key, secret_key, region):
    data = {"user_id": uid, "provider": provider, "alias": alias, "access_key": access_key, "secret_key": secret_key, "region": region}
    response = supabase.table('cloud_accounts').insert(data).execute()
    return response.data[0]['id'] if response.data else None

def account_delete(aid, uid):
    supabase.table('cloud_accounts').delete().eq('id', aid).eq('user_id', uid).execute()

# Scans
def scan_create(uid, acct_id, name, provider, cats):
    data = {"user_id": uid, "account_id": acct_id, "scan_name": name, "provider": provider, "status": "running", "categories": cats}
    response = supabase.table('scan_results').insert(data).execute()
    return response.data[0]['id'] if response.data else None

def scan_update(sid, **kw):
    response = supabase.table('scan_results').update(kw).eq('id', sid).execute()
    return response.data[0] if response.data else None

def scan_get(sid, uid):
    response = supabase.table('scan_results').select('*').eq('id', sid).eq('user_id', uid).execute()
    return response.data[0] if response.data else None

def scans_by_user(uid, limit=None):
    query = supabase.table('scan_results').select('*').eq('user_id', uid).order('created_at', desc=True)
    if limit:
        query = query.limit(limit)
    response = query.execute()
    return response.data

def scan_delete(sid, uid):
    supabase.table('scan_results').delete().eq('id', sid).eq('user_id', uid).execute()

def scan_count(uid):
    response = supabase.table('scan_results').select('*', count='exact').eq('user_id', uid).execute()
    return response.count or 0

# Findings
def finding_add(sid, rtype, rid, check, sev, desc, rec, comp):
    data = {"scan_id": sid, "resource_type": rtype, "resource_id": rid, "check_name": check, "severity": sev, "description": desc, "recommendation": rec, "compliance": comp}
    supabase.table('findings').insert(data).execute()

def findings_by_scan(sid):
    # Fetch findings for the scan
    response = supabase.table('findings').select('*').eq('scan_id', sid).execute()
    findings = response.data
    
    # Custom sort by severity in Python, since Supabase doesn't support complex CASE WHEN ORDER BY natively
    severity_order = {'High': 1, 'Medium': 2, 'Low': 3, 'Critical': 0}
    findings.sort(key=lambda x: severity_order.get(x.get('severity'), 4))
    return findings

def findings_count_by_user(uid, severity=None):
    # Supabase doesn't easily support cross-table filtering with exact counts using the regular select interface like this:
    # `SELECT COUNT(*) FROM findings f JOIN scan_results s ON f.scan_id=s.id WHERE s.user_id=?`
    # Instead, we first get scan IDs for the user
    scans_response = supabase.table('scan_results').select('id').eq('user_id', uid).execute()
    scan_ids = [s['id'] for s in scans_response.data]

    if not scan_ids:
        return 0

    query = supabase.table('findings').select('*', count='exact').in_('scan_id', scan_ids)
    if severity:
        query = query.eq('severity', severity)

    response = query.execute()
    return response.count or 0

# Reports
def report_create(uid, sid, name, fmt, fname, fpath):
    data = {"user_id": uid, "scan_id": sid, "report_name": name, "format": fmt, "filename": fname, "filepath": fpath}
    response = supabase.table('reports').insert(data).execute()
    return response.data[0]['id'] if response.data else None

def reports_by_user(uid, limit=None):
    query = supabase.table('reports').select('*').eq('user_id', uid).order('created_at', desc=True)
    if limit:
        query = query.limit(limit)
    response = query.execute()
    return response.data

def report_get(rid, uid):
    response = supabase.table('reports').select('*').eq('id', rid).eq('user_id', uid).execute()
    return response.data[0] if response.data else None

def report_delete(rid, uid):
    supabase.table('reports').delete().eq('id', rid).eq('user_id', uid).execute()

# ─── Breach Check History ─────────────────────────────────────────────────────
def init_breach_table():
    # Tables are manually created via supabase_schema.sql
    pass

def breach_save(user_id, check_type, identifier, result_json, found, breach_count):
    data = {
        "user_id": user_id,
        "check_type": check_type,
        "identifier": identifier,
        "result": result_json,
        "found": 1 if found else 0,
        "breach_count": breach_count
    }
    response = supabase.table('breach_checks').insert(data).execute()
    return response.data[0]['id'] if response.data else None

def breach_history(user_id, limit=20):
    response = supabase.table('breach_checks').select('*').eq('user_id', user_id).order('checked_at', desc=True).limit(limit).execute()
    return response.data

def breach_stats(user_id):
    total_response = supabase.table('breach_checks').select('*', count='exact').eq('user_id', user_id).execute()
    total = total_response.count or 0

    pwned_response = supabase.table('breach_checks').select('*', count='exact').eq('user_id', user_id).eq('found', 1).execute()
    pwned = pwned_response.count or 0

    return {'total': total, 'pwned': pwned, 'safe': total - pwned}
