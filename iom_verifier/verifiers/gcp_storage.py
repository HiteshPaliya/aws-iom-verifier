import requests
from typing import Dict, Any
from .base import BaseVerifier, VerificationResult

class GCPStorageVerifier(BaseVerifier):
    ids = [
        "Cloud Storage policy configured with 'allUsers' access",
        "Cloud Storage policy configured with 'allAuthenticatedUsers' access",
        "Cloud Storage policy configured with 'allUsers' access" # Duplicate in list usually handled by sets but explicit is fine
    ]

    def verify(self, row: Dict[str, Any]) -> VerificationResult:
        resource_id = row.get('Resource ID', '')

        # Standard GCP Storage ID: //storage.googleapis.com/BUCKET_NAME
        # Or just BUCKET_NAME
        
        bucket_name = None
        if resource_id.startswith("//storage.googleapis.com/"):
            bucket_name = resource_id.replace("//storage.googleapis.com/", "")
        elif resource_id.startswith("gs://"):
            bucket_name = resource_id.replace("gs://", "")
        elif "/" not in resource_id:
            bucket_name = resource_id
            
        if not bucket_name:
             return VerificationResult(
                execution_status="Skipped",
                exploit_status="Unknown",
                message="Could not extract bucket name from Resource ID."
            )

        # Public URL: https://storage.googleapis.com/<bucket>/
        url = f"https://storage.googleapis.com/{bucket_name}/"
        
        try:
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                # Returns XML listing if keys are public
                return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Exploitable",
                    message=f"Bucket is publicly listable. GET {url} returned 200 OK."
                )
            elif response.status_code == 403:
                 return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Secure",
                    message=f"Access Denied (403). Buckets with 'allAuthenticatedUsers' might still require auth token, so this is Secure from Unauthenticated perspective."
                )
            elif response.status_code == 404:
                 return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Unknown",
                    message=f"Bucket not found (404). URL: {url}"
                )
            else:
                 return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Unknown",
                    message=f"Received unexpected status {response.status_code}."
                )

        except Exception as e:
             return VerificationResult(
                execution_status="Executed",
                exploit_status="Error",
                message=f"Connection failed: {str(e)}"
            )
