import requests
from typing import Dict, Any
from .base import BaseVerifier, VerificationResult

class ServicesVerifier(BaseVerifier):
    ids = [
        "AWS - ECR Repository is Publicly Accessible",
        "ECR repository is configured to be publicly exposed",
        "AWS - Lambda Function with Public Access", # Only if it has a function URL or we can guess it?
        "Lambda function is configured to be publicly exposed",
        "Cloud Run Service is accessible by any users or any authenticated user"
    ]

    def verify(self, row: Dict[str, Any]) -> VerificationResult:
        rule_name = row.get('Rule Name', '')
        resource_id = row.get('Resource ID', '')

        if "ECR" in rule_name:
            return self._verify_ecr(resource_id)
        
        # Lambda is tricky without the URL. 
        # If the 'Findings' column contains a URL, we can test it.
        findings = row.get('Findings', '')
        url_match = self._extract_url(findings)
        if url_match:
            return self._check_http(url_match)
            
        return VerificationResult(
                execution_status="Skipped",
                exploit_status="Unknown",
                message="Verifier requires known public endpoint/URL which could not be found in Resource ID or Findings."
            )

    def _verify_ecr(self, resource_id: str) -> VerificationResult:
        # Resource ID for ECR usually is 'repo-name' or ARN.
        # Public ECR URLs: public.ecr.aws/namespace/repo
        # We assume if it's public, we might not know the namespace just from the repo name easily 
        # unless it's in the data.
        # If we can't construct the URL, we skip.
        
        # However, for private ECR made public, they are usually on standard AWS ECR endpoints?
        # A private ECR repo made public is actually a different thing than "Public ECR" gallery.
        # Private ECR repo made public usually means the POLICY allows * (everyone) to pull.
        # To verify this "externally" without credentials, we would need to try to `docker pull` or call ECR API.
        # That's complex for a lightweight script.
        
        return VerificationResult(
            execution_status="Skipped",
            exploit_status="Unknown",
            message="Verification of ECR public access requires authenticated docker client or AWS API calls which mimics an external attacker but is complex for this script version."
        )

    def _extract_url(self, text: str) -> str:
        import re
        # Simple URL extractor
        url_regex = r"(https?://[^\s]+)"
        found = re.search(url_regex, text)
        if found:
            return found.group(0)
        return None

    def _check_http(self, url: str) -> VerificationResult:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code < 400:
                return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Exploitable",
                    message=f"Endpoint {url} returned {response.status_code}. Publicly accessible."
                )
            else:
                return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Secure", 
                    message=f"Endpoint {url} returned {response.status_code}."
                )
        except Exception as e:
            return VerificationResult(
                execution_status="Executed",
                exploit_status="Error",
                message=f"Failed to connect to {url}: {e}"
            )
