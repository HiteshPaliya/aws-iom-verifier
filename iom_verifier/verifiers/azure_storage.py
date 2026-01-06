import requests
from typing import Dict, Any
from .base import BaseVerifier, VerificationResult

class AzureStorageVerifier(BaseVerifier):
    ids = [
        "Storage Account blob container configured with public access",
        "Storage Account container storing activity logs is publicly accessible",
        "Azure Disk configured with PUBLIC network access enabled", # Sometimes related to SAS/Snapshot URLs
        "Azure Disk public network access is enabled"
    ]

    def verify(self, row: Dict[str, Any]) -> VerificationResult:
        resource_id = row.get('Resource ID', '') 
        # Azure ID: /subscriptions/.../resourceGroups/.../providers/Microsoft.Storage/storageAccounts/NAME/blobServices/default/containers/CONTAINER
        
        account_name = None
        container_name = None

        if "storageAccounts" in resource_id and "containers" in resource_id:
            try:
                parts = resource_id.split('/')
                # Find index of storageAccounts
                sa_idx = parts.index('storageAccounts')
                account_name = parts[sa_idx + 1]
                
                # Find index of containers
                c_idx = parts.index('containers')
                container_name = parts[c_idx + 1]
            except (ValueError, IndexError):
                pass
        
        if not account_name:
             return VerificationResult(
                execution_status="Skipped",
                exploit_status="Unknown",
                message="Could not extract Storage Account name from Resource ID."
            )

        # If no container name, we might try to list containers if public access on account level?  
        # But usually 'Container' public access is per container.
        # If we don't have a container name, we can't easily verify container public access 
        # without guessing names or brute forcing.
        
        target_url = ""
        if container_name:
            # Check container public access (listing blobs)
            # URL: https://<account>.blob.core.windows.net/<container>?restype=container&comp=list
            target_url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"
        else:
             # Just check if the account endpoint resolves? Not very useful for "Public Access"
             # Might be "Blob public access is enabled" at account level, but that doesn't mean data is leaked yet.
             return VerificationResult(
                execution_status="Skipped",
                exploit_status="Unknown",
                message="Specific Container name not found in Resource ID. Cannot verify Container Public Access."
            )

        try:
            response = requests.get(target_url, timeout=5)
            
            if response.status_code == 200:
                 return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Exploitable",
                    message=f"Container is publicly listable. GET {target_url} returned 200 OK."
                )
            elif response.status_code == 404:
                # Container doesn't exist
                 return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Unknown",
                    message=f"Container not found (404). URL: {target_url}"
                )
            elif response.status_code == 403:
                 return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Secure",
                    message=f"Access Denied (403). Public access likely disabled. URL: {target_url}"
                )
            else:
                 return VerificationResult(
                    execution_status="Executed",
                    exploit_status="Unknown",
                    message=f"Received unexpected status {response.status_code}. URL: {target_url}"
                )

        except Exception as e:
             return VerificationResult(
                execution_status="Executed",
                exploit_status="Error",
                message=f"Connection failed: {str(e)}"
            )
