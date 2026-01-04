import requests
from typing import Dict, Any
from .base import BaseVerifier, VerificationResult

class S3Verifier(BaseVerifier):
    ids = [
        "S3 bucket policy with global write, read, or delete permissions",
        "S3 bucket configured for public access",
        "S3 bucket with Sensitive Data configured for public access",
        "S3 bucket with Sensitive Data configured for any authenticated user access",
        "S3 bucket with Block Public Access setting disabled",
        "S3 Bucket ACL allows READ access to ANY authenticated user",
        "S3 bucket policy allows public write access",
        "S3 bucket policy allows public read access",
        "S3 bucket configured for any authenticated user access"
    ]

    def verify(self, row: Dict[str, Any]) -> VerificationResult:
        resource_id = row.get('Resource ID', '') # Assuming Resource ID contains bucket name for S3
        # Fallback to finding bucket name in Findings if Resource ID is an ARN
        bucket_name = resource_id
        if resource_id.startswith("arn:aws:s3:::"):
            bucket_name = resource_id.split(":::")[1]
        
        if not bucket_name:
             return VerificationResult(
                execution_status="Skipped",
                exploit_status="Unknown",
                message="Could not extract bucket name from Resource ID."
            )

        # Construct Public URL
        # Trying standard regions and global
        # A more robust way would be to deduce region from 'Region' column
        region = row.get('Region', 'us-east-1')
        
        urls_to_test = [
            f"http://{bucket_name}.s3.amazonaws.com",
            f"http://{bucket_name}.s3.{region}.amazonaws.com"
        ]

        for url in urls_to_test:
            try:
                # We use a short timeout. We strictly look for public accessibility.
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    return VerificationResult(
                        execution_status="Executed",
                        exploit_status="Exploitable",
                        message=f"Bucket is publicly accessible. GET {url} returned 200 OK."
                    )
                elif response.status_code == 403:
                    # 403 means it exists but is private (or requires auth).
                    # For the purpose of 'Public Access', 403 usually means it's NOT public (secure).
                    # However, some misconfigurations might allow specific files but not listing.
                    # Without an object key, checking root 403 is a strong indicator of 'Not Publicly Listable'.
                    return VerificationResult(
                        execution_status="Executed",
                        exploit_status="Secure", 
                        message=f"Bucket exists but returned 403 Forbidden on root (Access Denied). Endpoint: {url}"
                    )
                elif response.status_code == 404:
                    # NoSuchBucket
                    continue
                else:
                     return VerificationResult(
                        execution_status="Executed",
                        exploit_status="Unknown",
                        message=f"Received unexpected status code {response.status_code} from {url}"
                    )

            except requests.RequestException as e:
                pass # Try next URL

        return VerificationResult(
            execution_status="Executed",
            exploit_status="Unknown", 
            message=f"Could not connect to bucket endpoint or bucket does not exist. URLs tested: {urls_to_test}"
        )
