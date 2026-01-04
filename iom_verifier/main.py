import argparse
import csv
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

from .loader import DataLoader
from .verifiers.registry import ALL_VERIFIERS
from .verifiers.base import BaseVerifier, VerificationResult

# Lock for writing to CSV safely from multiple threads
csv_lock = threading.Lock()

def process_row(row: Dict[str, Any], verifiers: List[BaseVerifier]) -> Dict[str, Any]:
    """
    Finds the right verifier and executes it.
    Returns the modified row with new columns.
    """
    verifier = DataLoader.get_verifier_for_row(row, verifiers)
    
    result = None
    if verifier:
        result = verifier.verify(row)
    else:
        result = VerificationResult(
            execution_status="Skipped",
            exploit_status="Manual Check Required",
            message="Manual Check Required"
        )

    # Update row with results
    row['Verify_Execution'] = result.execution_status
    row['Verify_Exploit'] = result.exploit_status
    row['Verify_Result'] = result.message
    
    return row

def main():
    parser = argparse.ArgumentParser(description="AWS IoM Verifier - External Attacker Perspective")
    parser.add_argument("--input", required=True, help="Path to the input CSV file")
    parser.add_argument("--output", required=True, help="Path to the output CSV file")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads")
    
    args = parser.parse_args()
    
    # Load Data
    loader = DataLoader(args.input)
    rows = loader.load_data()
    
    if not rows:
        print("No data found or error reading input file.")
        sys.exit(1)
        
    print(f"Loaded {len(rows)} IoMs. Starting verification with {args.threads} threads...")
    
    # Prepare header
    fieldnames = list(rows[0].keys())
    # Add new columns if not present
    for col in ['Verify_Execution', 'Verify_Exploit', 'Verify_Result']:
        if col not in fieldnames:
            fieldnames.append(col)
            
    # Open output file
    try:
        with open(args.output, 'w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                future_to_row = {executor.submit(process_row, row, ALL_VERIFIERS): row for row in rows}
                
                completed_count = 0
                for future in as_completed(future_to_row):
                    processed_row = future.result()
                    
                    # Write immediately
                    with csv_lock:
                        writer.writerow(processed_row)
                        outfile.flush()
                        
                    completed_count += 1
                    if completed_count % 10 == 0:
                        print(f"Processed {completed_count}/{len(rows)}...")

    except Exception as e:
        print(f"Error executing verification: {e}")
        sys.exit(1)

    print("Verification complete.")

if __name__ == "__main__":
    main()
