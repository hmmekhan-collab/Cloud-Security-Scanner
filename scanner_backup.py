"""
AWS Security Scanner - Rule-Based Analysis Engine
Covers: IAM, S3, EC2, Security Groups, CloudTrail, RDS
Accuracy target: 80%+ via CIS AWS Benchmark rules
"""

import json
from datetime import datetime, timezone

# ─── Try importing boto3 (graceful fallback for demo) ─────────────────────────
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class AWSScanner:
    """
    Rule-Based AWS Security Scanner
    Implements CIS AWS Foundations Benchmark checks
    """

    def run_scan(self, account, categories):
        """Main entry: connect to AWS and run all selected checks."""
        if not BOTO3_AVAILABLE:
            return self._demo_findings(account, categories)

        try:
            session = boto3.Session(
                aws_access_key_id     = account.access_key,
                aws_secret_access_key = account.secret_key,
                region_name           = account.region
            )
            # Quick credential validation
            sts = session.client('sts')
            identity = sts.get_caller_identity()
        except Exception as e:
            raise Exception(f"AWS Authentication failed: {str(e)}")

        findings = []
        cat_map = {
            'iam':        lambda: self._check_iam(session),
            's3':         lambda: self._check_s3(session),
            'ec2':        lambda: self._check_ec2(session),
            'sg':         lambda: self._check_security_groups(session, account.region),
            'cloudtrail': lambda: self._check_cloudtrail(session),
            'rds':        lambda: self._check_rds(session),
        }
        for cat in categories:
            if cat in cat_map:
                try:
                    findings.extend(cat_map[cat]())
                except Exception as e:
                    findings.append({
                        'resource_type': cat.upper(),
                        'resource_id':   'scan_error',
                        'check_name':    f'{cat.upper()} Scan Error',
                        'severity':      'Low',
                        'description':   f'Could not complete {cat.upper()} checks: {str(e)}',
                        'recommendation': 'Ensure IAM permissions include read access.',
                        'compliance':    'N/A'
                    })
        return findings

    # ── IAM Checks ────────────────────────────────────────────────────────────
    def _check_iam(self, session):
        findings = []
        iam = session.client('iam')

        # CIS 1.1 - Root account MFA
        try:
            summary = iam.get_account_summary()['SummaryMap']
            if summary.get('AccountMFAEnabled', 0) == 0:
                findings.append(self._finding(
                    'IAM', 'root-account', 'Root Account MFA Disabled', 'High',
                    'The root account does not have MFA enabled. This is a critical security risk.',
                    'Enable MFA on the root account immediately using an authenticator app or hardware key.',
                    'CIS AWS 1.1'
                ))
        except: pass

        # CIS 1.2 - Password policy
        try:
            policy = iam.get_account_password_policy()['PasswordPolicy']
            if not policy.get('RequireUppercaseCharacters'):
                findings.append(self._finding('IAM', 'password-policy', 'Weak Password Policy: No Uppercase Required', 'Medium',
                    'IAM password policy does not require uppercase characters.',
                    'Update password policy to require uppercase characters (IAM > Account Settings).', 'CIS AWS 1.5'))
            if not policy.get('RequireSymbols'):
                findings.append(self._finding('IAM', 'password-policy', 'Weak Password Policy: No Symbols Required', 'Medium',
                    'IAM password policy does not require symbols.',
                    'Require symbols in IAM password policy.', 'CIS AWS 1.6'))
            if not policy.get('RequireNumbers'):
                findings.append(self._finding('IAM', 'password-policy', 'Weak Password Policy: No Numbers Required', 'Medium',
                    'IAM password policy does not require numbers.',
                    'Require numbers in IAM password policy.', 'CIS AWS 1.7'))
            min_len = policy.get('MinimumPasswordLength', 0)
            if min_len < 14:
                findings.append(self._finding('IAM', 'password-policy', f'Password Minimum Length Too Short ({min_len})', 'Medium',
                    f'Password minimum length is {min_len}. CIS recommends at least 14.',
                    'Set minimum password length to 14 or more characters.', 'CIS AWS 1.8'))
            if not policy.get('ExpirePasswords'):
                findings.append(self._finding('IAM', 'password-policy', 'Password Expiration Not Enabled', 'Low',
                    'IAM password policy does not enforce password expiration.',
                    'Enable password expiration (max 90 days).', 'CIS AWS 1.11'))
        except iam.exceptions.NoSuchEntityException:
            findings.append(self._finding('IAM', 'password-policy', 'No IAM Password Policy Configured', 'High',
                'No account-level IAM password policy is set. Default AWS passwords are weak.',
                'Configure a strong IAM password policy.', 'CIS AWS 1.5-1.11'))

        # CIS 1.15 - Users without MFA
        try:
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                    if not mfa_devices:
                        age_days = (datetime.now(timezone.utc) - user['CreateDate']).days
                        if age_days > 7:
                            findings.append(self._finding(
                                'IAM', f"user/{user['UserName']}",
                                f"IAM User Without MFA: {user['UserName']}", 'High',
                                f"IAM user '{user['UserName']}' has no MFA device enabled.",
                                'Enable MFA for this IAM user.', 'CIS AWS 1.10'
                            ))
        except: pass

        # CIS 1.4 - Access keys older than 90 days
        try:
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                    for key in keys:
                        if key['Status'] == 'Active':
                            age = (datetime.now(timezone.utc) - key['CreateDate']).days
                            if age > 90:
                                findings.append(self._finding(
                                    'IAM', f"user/{user['UserName']}",
                                    f"Stale Access Key (>{age} days): {user['UserName']}", 'Medium',
                                    f"Access key for '{user['UserName']}' is {age} days old.",
                                    'Rotate access keys every 90 days.', 'CIS AWS 1.4'
                                ))
        except: pass

        return findings

    # ── S3 Checks ─────────────────────────────────────────────────────────────
    def _check_s3(self, session):
        findings = []
        s3 = session.client('s3')

        try:
            buckets = s3.list_buckets()['Buckets']
        except Exception as e:
            return findings

        for bucket in buckets:
            name = bucket['Name']

            # Public access block
            try:
                pub = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
                if not all([pub.get('BlockPublicAcls'), pub.get('BlockPublicPolicy'),
                            pub.get('IgnorePublicAcls'), pub.get('RestrictPublicBuckets')]):
                    findings.append(self._finding(
                        'S3', name, f'S3 Bucket Public Access Not Fully Blocked: {name}', 'High',
                        f'Bucket "{name}" does not have all public access block settings enabled.',
                        'Enable all four S3 public access block settings on this bucket.', 'CIS AWS 2.1.5'
                    ))
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                findings.append(self._finding(
                    'S3', name, f'S3 Bucket No Public Access Block: {name}', 'High',
                    f'Bucket "{name}" has no public access block configuration.',
                    'Configure S3 Block Public Access for this bucket.', 'CIS AWS 2.1.5'
                ))
            except: pass

            # Versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                if ver.get('Status') != 'Enabled':
                    findings.append(self._finding(
                        'S3', name, f'S3 Bucket Versioning Disabled: {name}', 'Medium',
                        f'Versioning is not enabled on bucket "{name}".',
                        'Enable versioning to protect against accidental deletion.', 'CIS AWS 2.1.3'
                    ))
            except: pass

            # Server-side encryption
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
            except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                findings.append(self._finding(
                    'S3', name, f'S3 Bucket Not Encrypted: {name}', 'High',
                    f'Bucket "{name}" does not have server-side encryption enabled.',
                    'Enable AES-256 or AWS KMS encryption on this bucket.', 'CIS AWS 2.1.1'
                ))
            except: pass

            # Logging
            try:
                log = s3.get_bucket_logging(Bucket=name)
                if 'LoggingEnabled' not in log:
                    findings.append(self._finding(
                        'S3', name, f'S3 Bucket Logging Disabled: {name}', 'Low',
                        f'Access logging is not enabled for bucket "{name}".',
                        'Enable S3 access logging to track requests.', 'CIS AWS 2.1.2'
                    ))
            except: pass

        return findings

    # ── EC2 Checks ────────────────────────────────────────────────────────────
    def _check_ec2(self, session):
        findings = []
        ec2 = session.client('ec2')

        # EBS volume encryption
        try:
            vols = ec2.describe_volumes()['Volumes']
            for vol in vols:
                if not vol.get('Encrypted'):
                    findings.append(self._finding(
                        'EC2', vol['VolumeId'], f'Unencrypted EBS Volume: {vol["VolumeId"]}', 'High',
                        f'EBS volume "{vol["VolumeId"]}" is not encrypted.',
                        'Enable EBS encryption. Consider using default encryption for new volumes.', 'CIS AWS 2.2.1'
                    ))
        except: pass

        # IMDSv2 enforcement
        try:
            instances = ec2.describe_instances()['Reservations']
            for res in instances:
                for inst in res['Instances']:
                    if inst['State']['Name'] not in ('running', 'stopped'):
                        continue
                    meta = inst.get('MetadataOptions', {})
                    if meta.get('HttpTokens') != 'required':
                        findings.append(self._finding(
                            'EC2', inst['InstanceId'], f'IMDSv2 Not Required: {inst["InstanceId"]}', 'Medium',
                            f'Instance "{inst["InstanceId"]}" allows IMDSv1 (no token requirement). Vulnerable to SSRF.',
                            'Set MetadataOptions.HttpTokens to "required" to enforce IMDSv2.', 'AWS Best Practice'
                        ))
                    # Check for public IP
                    if inst.get('PublicIpAddress'):
                        findings.append(self._finding(
                            'EC2', inst['InstanceId'], f'EC2 Instance Has Public IP: {inst["InstanceId"]}', 'Low',
                            f'Instance "{inst["InstanceId"]}" has a public IP ({inst["PublicIpAddress"]}). Review if necessary.',
                            'Use Elastic IPs selectively. Consider placing instances behind a load balancer.', 'AWS Best Practice'
                        ))
        except: pass

        return findings

    # ── Security Group Checks ─────────────────────────────────────────────────
    def _check_security_groups(self, session, region):
        findings = []
        ec2 = session.client('ec2', region_name=region)

        DANGEROUS_PORTS = [22, 3389, 3306, 5432, 27017, 6379, 9200, 8080, 23, 21]
        PORT_NAMES = {22:'SSH', 3389:'RDP', 3306:'MySQL', 5432:'PostgreSQL',
                      27017:'MongoDB', 6379:'Redis', 9200:'Elasticsearch',
                      8080:'HTTP-Alt', 23:'Telnet', 21:'FTP'}

        try:
            sgs = ec2.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port   = rule.get('ToPort',   65535)

                    for cidr in rule.get('IpRanges', []):
                        if cidr.get('CidrIp') == '0.0.0.0/0':
                            if from_port == 0 and to_port == 65535:
                                findings.append(self._finding(
                                    'SecurityGroup', sg['GroupId'],
                                    f'SG Allows All Traffic from Internet: {sg["GroupId"]}', 'High',
                                    f'Security group "{sg["GroupId"]}" ({sg.get("GroupName")}) allows ALL inbound traffic from 0.0.0.0/0.',
                                    'Restrict inbound rules to specific IPs and ports.', 'CIS AWS 5.2'))
                            else:
                                for dport in DANGEROUS_PORTS:
                                    if from_port <= dport <= to_port:
                                        pname = PORT_NAMES.get(dport, str(dport))
                                        sev = 'High' if dport in [22, 3389] else 'Medium'
                                        findings.append(self._finding(
                                            'SecurityGroup', sg['GroupId'],
                                            f'SG Exposes {pname} to Internet: {sg["GroupId"]}', sev,
                                            f'Security group "{sg["GroupId"]}" allows {pname} (port {dport}) from 0.0.0.0/0.',
                                            f'Restrict port {dport} to known IP ranges or use a VPN/bastion.', f'CIS AWS 5.{2 if dport==22 else 3}'))

                    for cidr6 in rule.get('Ipv6Ranges', []):
                        if cidr6.get('CidrIpv6') == '::/0':
                            for dport in [22, 3389]:
                                if from_port <= dport <= to_port:
                                    pname = PORT_NAMES[dport]
                                    findings.append(self._finding(
                                        'SecurityGroup', sg['GroupId'],
                                        f'SG Exposes {pname} to IPv6 Internet: {sg["GroupId"]}', 'High',
                                        f'Port {dport} ({pname}) is open to ::/0 in "{sg["GroupId"]}".',
                                        f'Restrict {pname} access to specific IPv6 ranges.', f'CIS AWS 5.{2 if dport==22 else 3}'))
        except: pass

        return findings

    # ── CloudTrail Checks ─────────────────────────────────────────────────────
    def _check_cloudtrail(self, session):
        findings = []
        ct = session.client('cloudtrail')

        try:
            trails = ct.describe_trails(includeShadowTrails=False)['trailList']
            if not trails:
                findings.append(self._finding(
                    'CloudTrail', 'global', 'No CloudTrail Trails Configured', 'High',
                    'No AWS CloudTrail trails are configured. API activity is not being logged.',
                    'Create a CloudTrail trail that logs all regions to an S3 bucket.', 'CIS AWS 3.1'))
                return findings

            for trail in trails:
                name = trail['Name']
                # Check if logging is enabled
                status = ct.get_trail_status(Name=trail['TrailARN'])
                if not status.get('IsLogging'):
                    findings.append(self._finding(
                        'CloudTrail', name, f'CloudTrail Logging Disabled: {name}', 'High',
                        f'CloudTrail trail "{name}" exists but logging is not enabled.',
                        'Enable logging on the trail.', 'CIS AWS 3.1'))

                # Log file validation
                if not trail.get('LogFileValidationEnabled'):
                    findings.append(self._finding(
                        'CloudTrail', name, f'CloudTrail Log Validation Disabled: {name}', 'Medium',
                        f'Log file validation is not enabled for trail "{name}".',
                        'Enable log file validation to detect tampering.', 'CIS AWS 3.2'))

                # Multi-region
                if not trail.get('IsMultiRegionTrail'):
                    findings.append(self._finding(
                        'CloudTrail', name, f'CloudTrail Not Multi-Region: {name}', 'Medium',
                        f'Trail "{name}" only covers a single region.',
                        'Enable multi-region logging for complete audit coverage.', 'CIS AWS 3.3'))

                # KMS encryption
                if not trail.get('KMSKeyId'):
                    findings.append(self._finding(
                        'CloudTrail', name, f'CloudTrail Logs Not KMS Encrypted: {name}', 'Medium',
                        f'Trail "{name}" logs are not encrypted with KMS.',
                        'Configure KMS encryption for CloudTrail logs.', 'CIS AWS 3.7'))
        except Exception as e:
            pass

        return findings

    # ── RDS Checks ────────────────────────────────────────────────────────────
    def _check_rds(self, session):
        findings = []
        rds = session.client('rds')

        try:
            paginator = rds.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db in page['DBInstances']:
                    dbid = db['DBInstanceIdentifier']

                    if db.get('PubliclyAccessible'):
                        findings.append(self._finding(
                            'RDS', dbid, f'RDS Instance Publicly Accessible: {dbid}', 'High',
                            f'RDS instance "{dbid}" is publicly accessible from the internet.',
                            'Disable public accessibility. Place RDS in a private subnet.', 'CIS AWS 2.3.2'))

                    if not db.get('StorageEncrypted'):
                        findings.append(self._finding(
                            'RDS', dbid, f'RDS Storage Not Encrypted: {dbid}', 'High',
                            f'RDS instance "{dbid}" storage is not encrypted.',
                            'Enable storage encryption. Note: requires snapshot + restore for existing instances.', 'CIS AWS 2.3.1'))

                    if not db.get('MultiAZ'):
                        findings.append(self._finding(
                            'RDS', dbid, f'RDS Multi-AZ Disabled: {dbid}', 'Low',
                            f'RDS instance "{dbid}" does not use Multi-AZ deployment.',
                            'Enable Multi-AZ for high availability.', 'AWS Best Practice'))

                    if not db.get('BackupRetentionPeriod', 0) >= 7:
                        findings.append(self._finding(
                            'RDS', dbid, f'RDS Backup Retention Too Short: {dbid}', 'Medium',
                            f'Backup retention for "{dbid}" is {db.get("BackupRetentionPeriod",0)} days (recommended: 7+).',
                            'Set backup retention period to at least 7 days.', 'AWS Best Practice'))

                    if not db.get('DeletionProtection'):
                        findings.append(self._finding(
                            'RDS', dbid, f'RDS Deletion Protection Disabled: {dbid}', 'Medium',
                            f'RDS instance "{dbid}" does not have deletion protection enabled.',
                            'Enable deletion protection on production RDS instances.', 'AWS Best Practice'))
        except: pass

        return findings

    # ── Demo Findings (when boto3 unavailable or for testing) ─────────────────
    def _demo_findings(self, account, categories):
        """Realistic demo findings for UI testing without real AWS."""
        findings = []
        if 'iam' in categories:
            findings += [
                self._finding('IAM', 'root-account', 'Root Account MFA Disabled', 'High',
                    'The root account does not have MFA enabled.',
                    'Enable MFA on the root account immediately.', 'CIS AWS 1.1'),
                self._finding('IAM', 'user/developer1', 'IAM User Without MFA: developer1', 'High',
                    "IAM user 'developer1' has no MFA device enabled.",
                    'Enable MFA for all IAM users.', 'CIS AWS 1.10'),
                self._finding('IAM', 'password-policy', 'No IAM Password Policy Configured', 'High',
                    'No account-level password policy is configured.',
                    'Configure a strong IAM password policy.', 'CIS AWS 1.5'),
                self._finding('IAM', 'user/s3-bot', 'Stale Access Key (>120 days): s3-bot', 'Medium',
                    'Access key is 120 days old.',
                    'Rotate access keys every 90 days.', 'CIS AWS 1.4'),
            ]
        if 's3' in categories:
            findings += [
                self._finding('S3', 'my-public-data-bucket', 'S3 Bucket Public Access Not Fully Blocked', 'High',
                    'Bucket "my-public-data-bucket" does not block public access.',
                    'Enable all S3 Block Public Access settings.', 'CIS AWS 2.1.5'),
                self._finding('S3', 'app-assets-prod', 'S3 Bucket Not Encrypted: app-assets-prod', 'High',
                    'Bucket lacks server-side encryption.',
                    'Enable AES-256 or KMS encryption.', 'CIS AWS 2.1.1'),
                self._finding('S3', 'logs-archive', 'S3 Bucket Versioning Disabled: logs-archive', 'Medium',
                    'Versioning is not enabled.',
                    'Enable versioning to protect data.', 'CIS AWS 2.1.3'),
                self._finding('S3', 'backups-2024', 'S3 Bucket Logging Disabled: backups-2024', 'Low',
                    'Access logging not configured.',
                    'Enable S3 access logging.', 'CIS AWS 2.1.2'),
            ]
        if 'sg' in categories:
            findings += [
                self._finding('SecurityGroup', 'sg-0123abc', 'SG Exposes SSH to Internet: sg-0123abc', 'High',
                    'Port 22 (SSH) is open to 0.0.0.0/0.',
                    'Restrict SSH to known IPs only.', 'CIS AWS 5.2'),
                self._finding('SecurityGroup', 'sg-0456def', 'SG Exposes RDP to Internet: sg-0456def', 'High',
                    'Port 3389 (RDP) is open to 0.0.0.0/0.',
                    'Restrict RDP access. Use VPN or bastion.', 'CIS AWS 5.3'),
                self._finding('SecurityGroup', 'sg-0789ghi', 'SG Exposes MySQL to Internet: sg-0789ghi', 'Medium',
                    'Port 3306 (MySQL) is open from internet.',
                    'Move database to private subnet.', 'CIS Best Practice'),
            ]
        if 'cloudtrail' in categories:
            findings += [
                self._finding('CloudTrail', 'main-trail', 'CloudTrail Log Validation Disabled', 'Medium',
                    'Log integrity validation is not enabled.',
                    'Enable CloudTrail log file validation.', 'CIS AWS 3.2'),
                self._finding('CloudTrail', 'main-trail', 'CloudTrail Not Multi-Region', 'Medium',
                    'Trail only covers us-east-1.',
                    'Enable multi-region CloudTrail logging.', 'CIS AWS 3.3'),
            ]
        if 'ec2' in categories:
            findings += [
                self._finding('EC2', 'i-0abcd1234', 'IMDSv2 Not Required: i-0abcd1234', 'Medium',
                    'Instance allows IMDSv1, vulnerable to SSRF.',
                    'Enforce IMDSv2 on all instances.', 'AWS Best Practice'),
                self._finding('EC2', 'vol-0abcd5678', 'Unencrypted EBS Volume: vol-0abcd5678', 'High',
                    'EBS volume is not encrypted.',
                    'Enable EBS encryption.', 'CIS AWS 2.2.1'),
            ]
        if 'rds' in categories:
            findings += [
                self._finding('RDS', 'prod-mysql-db', 'RDS Instance Publicly Accessible: prod-mysql-db', 'High',
                    'RDS instance is publicly accessible.',
                    'Disable public accessibility.', 'CIS AWS 2.3.2'),
                self._finding('RDS', 'dev-postgres', 'RDS Storage Not Encrypted: dev-postgres', 'High',
                    'RDS storage is not encrypted.',
                    'Enable storage encryption.', 'CIS AWS 2.3.1'),
            ]
        return findings

    def _finding(self, resource_type, resource_id, check_name, severity, description, recommendation, compliance):
        return {
            'resource_type':  resource_type,
            'resource_id':    resource_id,
            'check_name':     check_name,
            'severity':       severity,
            'description':    description,
            'recommendation': recommendation,
            'compliance':     compliance
        }


aws_scanner = AWSScanner()
