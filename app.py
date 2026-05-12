from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort
import database as db
from scanner import aws_scanner
from azure_scanner import azure_scanner
from report_generator import generate_report
from risk_engine import full_analysis
import os, functools
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'csa-fyp-uw-2025-secret'
app.config['REPORTS_FOLDER'] = os.path.join(os.path.dirname(__file__), 'reports')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.template_filter('format_date')
def format_date_filter(s, fmt='%b %d, %Y'):
    if not s:
        return 'Unknown'
    # Supabase returns ISO format strings like: '2023-11-20T14:32:00.000+00:00'
    try:
        if isinstance(s, str):
            # Parse as datetime, ignoring fractional seconds and timezone for display
            parsed = datetime.fromisoformat(s.replace('Z', '+00:00').split('.')[0])
        else:
            parsed = s # Might already be a datetime
        return parsed.strftime(fmt)
    except Exception:
        return str(s)


def login_required(f):
    @functools.wraps(f)
    def d(*a,**kw):
        if 'user_id' not in session:
            flash('Please login first.','warning')
            return redirect(url_for('login'))
        return f(*a,**kw)
    return d

@app.route('/')
def index(): return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        u = db.user_by_email(request.form.get('email','').strip())
        if u and check_password_hash(u['password_hash'], request.form.get('password','')):
            session['user_id'] = u['id']
            session['user_name'] = u['full_name']
            db.user_update(u['id'], last_login=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
            flash(f"Welcome back, {u['full_name']}!", 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.','danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        org = request.form.get('organization', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            flash('Error: Passwords do not match.', 'danger')
        elif len(password) < 6:
            flash('Error: Password must be at least 6 characters.', 'danger')
        elif db.user_by_email(email):
            flash('Error: An account with that email already exists.', 'danger')
        else:
            try:
                db.user_create(full_name, email, org, generate_password_hash(password))
                user = db.user_by_email(email)
                if user:
                    session.permanent = True
                    session['user_id'] = user['id']
                    session['user_name'] = user['full_name']
                    flash('Account created successfully! Welcome to CSA.', 'success')
                    return redirect(url_for('dashboard'))
            except Exception as e:
                flash(f'Registration failed: {e}', 'danger')
    
    return render_template('register.html')



@app.route('/logout')
def logout():
    session.clear(); flash('Logged out.','info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    uid = session['user_id']; user = db.user_get(uid)
    return render_template('dashboard.html', user=user,
        accounts=db.accounts_by_user(uid),
        recent_scans=db.scans_by_user(uid,5),
        recent_reports=db.reports_by_user(uid,5),
        total_scans=db.scan_count(uid),
        total_findings=db.findings_count_by_user(uid),
        critical_count=db.findings_count_by_user(uid,'High'),
        medium_count=db.findings_count_by_user(uid,'Medium'))

@app.route('/accounts')
@login_required
def accounts():
    uid=session['user_id']
    return render_template('accounts.html', user=db.user_get(uid), accounts=db.accounts_by_user(uid))

@app.route('/accounts/add', methods=['GET','POST'])
@login_required
def add_account():
    uid=session['user_id']; user=db.user_get(uid)
    if request.method == 'POST':
        alias = request.form.get('alias','').strip()
        db.account_create(uid, request.form.get('provider'),
            alias, request.form.get('access_key','').strip(),
            request.form.get('secret_key','').strip(),
            request.form.get('region','us-east-1'))
        flash(f'Account "{alias}" added.','success')
        return redirect(url_for('accounts'))
    return render_template('add_account.html', user=user)

@app.route('/accounts/delete/<int:aid>', methods=['POST'])
@login_required
def delete_account(aid):
    db.account_delete(aid, session['user_id'])
    flash('Account removed.','info')
    return redirect(url_for('accounts'))

@app.route('/scan')
@login_required
def scan():
    uid=session['user_id']
    return render_template('scan.html', user=db.user_get(uid), accounts=db.accounts_by_user(uid))

@app.route('/scan/run', methods=['POST'])
@login_required
def run_scan():
    uid = session['user_id']
    aid = request.form.get('account_id')
    name = request.form.get('scan_name', f'Scan {datetime.now().strftime("%Y-%m-%d %H:%M")}')
    acct = db.account_get(int(aid), uid)
    if not acct: abort(404)

    provider = acct.get('provider', 'aws')

    # Default categories per provider
    if provider == 'azure':
        default_cats = ['iam','storage','vm','nsg','keyvault','sql','monitor']
    else:
        default_cats = ['iam','s3','ec2','sg','cloudtrail','rds']

    cats = request.form.getlist('categories') or default_cats

    sid = db.scan_create(uid, acct['id'], name, provider, ','.join(cats))

    # Create a simple object for scanner compat
    class Acct:
        pass
    a = Acct()
    for k,v in acct.items(): setattr(a,k,v)

    try:
        if provider == 'azure':
            raw = azure_scanner.run_scan(a, cats)
        else:
            raw = aws_scanner.run_scan(a, cats)

        analysis = full_analysis(raw)
        findings_clean = analysis['findings']
        suppressed = analysis['suppressed_fp']
        for f in findings_clean:
            db.finding_add(sid, f['resource_type'], f['resource_id'], f['check_name'],
                f['severity'], f['description'], f['recommendation'],
                f.get('compliance_detail') or f.get('compliance','CIS'))
        db.scan_update(sid, status='completed',
            total_findings=analysis['total'], high_count=analysis['high_count'],
            medium_count=analysis['medium_count'], low_count=analysis['low_count'],
            risk_score=analysis['risk_score'], completed_at=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
        crit=analysis['critical_count']; total=analysis['total']
        fp_note=f" ({suppressed} FP suppressed)" if suppressed else ""
        flash(f"Scan done! {total} findings — Crit:{crit} High:{analysis['high_count']} Med:{analysis['medium_count']} Low:{analysis['low_count']}{fp_note}. Score:{analysis['risk_score']}/100 ({analysis['risk_grade']})",'success')
    except Exception as e:
        db.scan_update(sid, status='failed', error_message=str(e))
        flash(f'Scan failed: {e}','danger')
    return redirect(url_for('scan_results', scan_id=sid))

@app.route('/scans')
@login_required
def scans():
    uid=session['user_id']
    return render_template('scans.html', user=db.user_get(uid), scans=db.scans_by_user(uid))

@app.route('/scans/<int:scan_id>')
@login_required
def scan_results(scan_id):
    uid=session['user_id']; scan=db.scan_get(scan_id,uid)
    if not scan: abort(404)
    findings=db.findings_by_scan(scan_id)
    by_sev={'Critical':[],'High':[],'Medium':[],'Low':[]}
    by_type={}
    for f in findings:
        by_sev.get(f['severity'],[]).append(f)
        by_type.setdefault(f['resource_type'],[]).append(f)
    from risk_engine import build_remediation_plan, compute_risk_score
    risk = compute_risk_score(findings)
    plan = build_remediation_plan(findings)
    return render_template('scan_results.html', user=db.user_get(uid),
        scan=scan, findings=findings, by_severity=by_sev, by_type=by_type,
        remediation_plan=plan, risk=risk)

@app.route('/scans/delete/<int:sid>', methods=['POST'])
@login_required
def delete_scan(sid):
    db.scan_delete(sid, session['user_id']); flash('Scan deleted.','info')
    return redirect(url_for('scans'))

@app.route('/reports')
@login_required
def reports():
    uid=session['user_id']
    return render_template('reports.html', user=db.user_get(uid), reports=db.reports_by_user(uid))

@app.route('/reports/generate/<int:scan_id>', methods=['POST'])
@login_required
def generate_report_route(scan_id):
    uid=session['user_id']; scan=db.scan_get(scan_id,uid)
    if not scan: abort(404)
    fmt=request.form.get('format','pdf')
    findings=db.findings_by_scan(scan_id)
    user=db.user_get(uid)
    try:
        fpath, fname = generate_report(scan, findings, user, fmt, app.config['REPORTS_FOLDER'])
        db.report_create(uid, scan_id, f"{scan['scan_name']} - {fmt.upper()} Report", fmt, fname, fpath)
        flash(f'Report generated in {fmt.upper()} format.','success')
        return redirect(url_for('reports'))
    except Exception as e:
        flash(f'Report generation failed: {e}','danger')
        return redirect(url_for('scan_results', scan_id=scan_id))

@app.route('/reports/download/<int:rid>')
@login_required
def download_report(rid):
    r=db.report_get(rid, session['user_id'])
    if not r: abort(404)
    if os.path.exists(r['filepath']):
        # Set correct MIME type based on format
        mime_types = {
            'pdf':  'application/pdf',
            'csv':  'text/csv',
            'json': 'application/json',
            'html': 'text/html',
            'xml':  'application/xml',
        }
        fmt = r.get('format', 'pdf')
        mimetype = mime_types.get(fmt, 'application/octet-stream')
        return send_file(r['filepath'], as_attachment=True,
                         download_name=r['filename'], mimetype=mimetype)
    flash('Report file not found.','danger')
    return redirect(url_for('reports'))

@app.route('/reports/delete/<int:rid>', methods=['POST'])
@login_required
def delete_report(rid):
    r=db.report_get(rid, session['user_id'])
    if r:
        if os.path.exists(r['filepath']): os.remove(r['filepath'])
        db.report_delete(rid, session['user_id'])
    flash('Report deleted.','info')
    return redirect(url_for('reports'))

@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    uid=session['user_id']; user=db.user_get(uid)
    if request.method == 'POST':
        new_pass = request.form.get('new_password','')
        updates = {'full_name': request.form.get('full_name', user['full_name']),
                   'organization': request.form.get('organization', user.get('organization',''))}
        if new_pass:
            if check_password_hash(user['password_hash'], request.form.get('current_password','')):
                updates['password_hash'] = generate_password_hash(new_pass)
                flash('Password updated.','success')
            else:
                flash('Current password incorrect.','danger')
                return render_template('profile.html', user=user)
        db.user_update(uid, **updates)
        session['user_name'] = updates['full_name']
        flash('Profile updated.','success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


# ─── Breach Checker ────────────────────────────────────────────────────────────
from breach_checker import check_email_breaches, check_password_pwned, check_password_strength, DEMO_BREACHES
import json as _json

@app.route('/breach')
@login_required
def breach_checker():
    uid = session['user_id']
    db.init_breach_table()
    stats = db.breach_stats(uid)
    history = db.breach_history(uid, 10)
    return render_template('breach_checker.html',
        user=db.user_get(uid),
        stats=stats,
        history=history)

@app.route('/breach/check-email', methods=['POST'])
@login_required
def breach_check_email():
    uid      = session['user_id']
    email    = request.form.get('email','').strip()
    api_key  = request.form.get('hibp_api_key','').strip() or None
    db.init_breach_table()

    if not email or '@' not in email:
        flash('Please enter a valid email address.','danger')
        return redirect(url_for('breach_checker'))

    # Use demo data if email matches, otherwise real API
    if email in DEMO_BREACHES and not api_key:
        result = DEMO_BREACHES[email]
    else:
        result = check_email_breaches(email, api_key)

    if 'error' in result:
        flash(f"Check failed: {result['error']}", 'warning')
        return redirect(url_for('breach_checker'))

    found  = result.get('found', False)
    count  = result.get('breach_count', 0)
    db.breach_save(uid, 'email', email, _json.dumps(result), found, count)

    return render_template('breach_result_email.html',
        user=db.user_get(uid),
        result=result,
        email=email)

@app.route('/breach/check-password', methods=['POST'])
@login_required
def breach_check_password():
    uid      = session['user_id']
    password = request.form.get('password','')
    db.init_breach_table()

    if not password:
        flash('Please enter a password.','danger')
        return redirect(url_for('breach_checker'))

    pwned    = check_password_pwned(password)
    strength = check_password_strength(password)

    # Save to DB (never save the actual password — just the result)
    found = pwned.get('pwned', False)
    count = pwned.get('count', 0)
    db.breach_save(uid, 'password', '(hidden)', _json.dumps({'pwned': found, 'count': count, 'strength': strength['label']}), found, count)

    return render_template('breach_result_password.html',
        user=db.user_get(uid),
        pwned=pwned,
        strength=strength)

if __name__ == '__main__':
    db.init_db()
    os.makedirs(app.config['REPORTS_FOLDER'], exist_ok=True)
    try:
        if db.user_count() == 0:
            db.user_create('Admin User','admin@csa.local','University of Wah',
                           generate_password_hash('admin123'))
            print("Demo admin created: admin@csa.local / admin123")
    except Exception as e:
        print(f"Warning: Could not create demo admin user. Database error: {e}")
        print("Please ensure you have configured your Supabase tables and RLS policies correctly.")
    
    print("\n" + "="*50)
    print("  Cloud Security Analyzer (CSA) is running!")
    print("  Open: http://localhost:5000")
    print("  Login: admin@csa.local / admin123")
    print("="*50 + "\n")
    app.run(debug=True, port=5000)

