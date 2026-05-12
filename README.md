# ☁ Cloud Security Analyzer (CSA)
**University of Wah FYP — Hamza Idrees (UW-22-CS-BS-040) & Muhammad Adnan (UW-21-CS-BS-071)**

---

## Project Overview
CSA is a web-based automated cloud security auditing platform that detects misconfigurations across AWS (and Azure coming soon) using CIS Benchmark rule-based analysis. It generates professional reports in 4 formats.

---

## Features
- ✅ Full user authentication (register/login/logout)
- ✅ SQLite database — zero hardcoded data
- ✅ AWS cloud account integration via boto3
- ✅ 6 security scan categories: IAM, S3, EC2, Security Groups, CloudTrail, RDS
- ✅ 30+ CIS Benchmark checks
- ✅ Severity-based risk scoring (0–100)
- ✅ Reports: PDF, CSV, JSON, HTML
- ✅ Scan history and report management
- ✅ Profile management

---

## Quick Start

### 1. Install Dependencies
```bash
pip install flask flask-sqlalchemy werkzeug boto3 reportlab pandas openpyxl
```

### 2. Run the Application
```bash
cd csa
python app.py
```

### 3. Open Browser
Visit: http://localhost:5000

### 4. Default Login
- **Email:** admin@csa.local
- **Password:** admin123

---

## AWS Setup Guide

### Step 1: Create IAM User for CSA
1. Login to AWS Console → Go to **IAM**
2. Click **Users** → **Create User**
3. Username: `csa-auditor`
4. Attach policy: **SecurityAudit** (or ReadOnlyAccess)
5. Click **Create User**

### Step 2: Generate Access Keys
1. Click the `csa-auditor` user
2. Go to **Security credentials** tab
3. Click **Create access key**
4. Choose "Application running outside AWS"
5. Copy **Access Key ID** and **Secret Access Key**

### Step 3: Add Account in CSA
1. Login to CSA → Cloud Accounts → Add Account
2. Enter your Access Key ID and Secret Access Key
3. Select your AWS Region
4. Save and run a scan!

### Required IAM Permissions (Minimum)
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:Get*", "iam:List*", "iam:GenerateCredentialReport",
      "s3:GetBucketAcl", "s3:GetBucketEncryption", "s3:GetBucketLogging",
      "s3:GetBucketVersioning", "s3:GetPublicAccessBlock", "s3:ListAllMyBuckets",
      "ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeSecurityGroups",
      "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
      "rds:DescribeDBInstances"
    ],
    "Resource": "*"
  }]
}
```

---

## Azure Setup Guide (For Future Integration)

### Step 1: Register App in Azure AD
1. Login to **portal.azure.com**
2. Go to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Name: `CSA-Auditor`
5. Note the **Application (client) ID** and **Directory (tenant) ID**

### Step 2: Create Client Secret
1. In your app → **Certificates & secrets**
2. Click **New client secret**
3. Copy the secret **Value** (shown once)

### Step 3: Assign Reader Role
1. Go to **Subscriptions**
2. Select your subscription → **Access control (IAM)**
3. Click **Add role assignment**
4. Role: **Reader** or **Security Reader**
5. Assign to: `CSA-Auditor` (your registered app)

### Step 4: Required Info for CSA
- **Tenant ID** (from App registration)
- **Client ID** (Application ID)
- **Client Secret** (from Step 2)
- **Subscription ID** (from Subscriptions page)

### Azure Python SDK Install (when ready)
```bash
pip install azure-identity azure-mgmt-resource azure-mgmt-storage azure-mgmt-compute azure-mgmt-network azure-mgmt-security
```

---

## Security Checks Implemented

| Category | Check | Severity | CIS Reference |
|----------|-------|----------|---------------|
| IAM | Root account MFA disabled | High | CIS 1.1 |
| IAM | No password policy | High | CIS 1.5 |
| IAM | User without MFA | High | CIS 1.10 |
| IAM | Stale access keys >90 days | Medium | CIS 1.4 |
| IAM | Weak password policy | Medium | CIS 1.5-1.11 |
| S3 | Public access not blocked | High | CIS 2.1.5 |
| S3 | No server-side encryption | High | CIS 2.1.1 |
| S3 | Versioning disabled | Medium | CIS 2.1.3 |
| S3 | Access logging disabled | Low | CIS 2.1.2 |
| EC2 | Unencrypted EBS volume | High | CIS 2.2.1 |
| EC2 | IMDSv2 not enforced | Medium | AWS Best Practice |
| EC2 | Instance has public IP | Low | AWS Best Practice |
| SG | SSH open to internet | High | CIS 5.2 |
| SG | RDP open to internet | High | CIS 5.3 |
| SG | DB ports exposed | Medium | CIS Best Practice |
| CloudTrail | No trails configured | High | CIS 3.1 |
| CloudTrail | Log validation disabled | Medium | CIS 3.2 |
| CloudTrail | Not multi-region | Medium | CIS 3.3 |
| CloudTrail | No KMS encryption | Medium | CIS 3.7 |
| RDS | Publicly accessible | High | CIS 2.3.2 |
| RDS | Storage not encrypted | High | CIS 2.3.1 |
| RDS | Deletion protection off | Medium | AWS Best Practice |
| RDS | Backup retention <7 days | Medium | AWS Best Practice |

---

## Project Structure
```
csa/
├── app.py              # Main Flask application
├── database.py         # SQLAlchemy models
├── scanner.py          # AWS security scanner + rule engine
├── report_generator.py # PDF, CSV, JSON, HTML report generation
├── requirements.txt
├── instance/
│   └── csa.db          # SQLite database (auto-created)
├── reports/            # Generated report files
└── templates/
    ├── base.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── scan.html
    ├── scan_results.html
    ├── scans.html
    ├── accounts.html
    ├── add_account.html
    ├── reports.html
    └── profile.html
```

---

*Cloud Security Analyzer — University of Wah, Session 2022-2026*
