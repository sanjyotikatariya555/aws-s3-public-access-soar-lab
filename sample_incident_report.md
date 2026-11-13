# SOC L1 Security Incident Triage Report

| Field | Details |
| :--- | :--- |
| **Incident ID** | INC-AWS-2026-001 |
| **Severity** | High (Auto-Contained) |
| **MITRE ATT&CK** | T1530 – Data from Cloud Storage |
| **Detection Source** | AWS CloudTrail / Amazon EventBridge |
| **Affected Resource** | Amazon S3 Bucket (`soc-remediation-lab-test-bucket`) |
| **Status** | Contained – Pending Owner Verification |

## 1. Executive Summary
An unauthorized or accidental modification disabled **Block Public Access** on an Amazon S3 bucket and introduced a `PublicReadAccess` bucket policy. Automated SOAR containment via AWS Lambda re-enabled all four Public Access Block settings immediately upon detection.

## 2. Log Analysis & Key Indicators
* **Event Source:** `://amazonaws.com`
* **API Calls Observed:** `PutPublicAccessBlock` (setting flags to `false`), `PutBucketPolicy` (`PublicReadAccess`)
* **Containment Action:** Automated execution of `s3:PutPublicAccessBlock` (`BlockPublicAcls=True`, `IgnorePublicAcls=True`, `BlockPublicPolicy=True`, `RestrictPublicBuckets=True`)

## 3. L1 Triage Actions Taken
1. Verified in AWS CloudTrail that the configuration change was logged accurately.
2. Confirmed via S3 console and CloudWatch Logs that automated remediation restored `Block all public access` to **On**.
3. Verified that the attached `PublicReadAccess` policy is overridden and no longer grants public object access.

## 4. Recommended Next Steps
* Contact the IAM user/bucket owner to verify whether the configuration change was part of an approved change ticket.
* Remove the residual `PublicReadAccess` bucket policy for defense-in-depth.
* Escalate to SOC Tier 2 if unauthorized IAM credential compromise is suspected.
