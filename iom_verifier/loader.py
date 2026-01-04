import csv
from typing import List, Dict, Any
from .verifiers.base import BaseVerifier, VerificationResult
from .verifiers import registry  # We will need a registry mechanism

class DataLoader:
    def __init__(self, csv_file_path: str):
        self.csv_file_path = csv_file_path

    def load_data(self) -> List[Dict[str, Any]]:
        """
        Reads the CSV and returns a list of rows.
        """
        data = []
        try:
            with open(self.csv_file_path, mode='r', encoding='utf-8-sig') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    data.append(row)
        except Exception as e:
            print(f"Error reading CSV file: {e}")
            return []
        return data

    @staticmethod
    def get_verifier_for_row(row: Dict[str, Any], verifiers: List[BaseVerifier]) -> BaseVerifier:
        """
        Finds a matching verifier for the given row based on 'Rule Name' or 'Violation Type'
        """
        rule_name = row.get('Rule Name', '')
        violation_type = row.get('Violation Type', '')
        
        # Simple matching logic - can be optimized
        for verifier in verifiers:
            if rule_name in verifier.ids or violation_type in verifier.ids:
                return verifier
        return None
