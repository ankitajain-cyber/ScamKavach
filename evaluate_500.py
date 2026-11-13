import csv
import time
from analyzer import analyze_message
from rules import check_rules

def evaluate_large_dataset(dataset_path="dataset_500.csv"):
    print("================================================================")
    print("SCAMKAVACH ENTERPRISE SOC - 500-SAMPLE BENCHMARK EVALUATION")
    print("================================================================")
    
    tp, tn, fp, fn = 0, 0, 0, 0
    total_samples = 0
    latencies = []

    try:
        with open(dataset_path, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                total_samples += 1
                payload = row['payload']
                expected = row['expected_label'].strip().lower()
                
                start_time = time.time()
                try:
                    # Try AI analyzer first
                    result = analyze_message(payload)
                    if "error" in result:
                        raise Exception(result["error"])
                    predicted_label = result.get('label', 'Unknown').strip().lower()
                except Exception:
                    # Fallback to Heuristic Rules Engine if API rate limit (429) or Server error (503) occurs
                    rule_res = check_rules(payload)
                    predicted_label = "phishing" if rule_res["score"] >= 3 else "safe"
                
                elapsed = time.time() - start_time
                latencies.append(elapsed)
                
                is_predicted_malicious = predicted_label != 'safe'
                is_expected_malicious = expected != 'safe'
                
                if is_expected_malicious and is_predicted_malicious:
                    tp += 1
                elif not is_expected_malicious and not is_predicted_malicious:
                    tn += 1
                elif not is_expected_malicious and is_predicted_malicious:
                    fp += 1  # False Alarm
                elif is_expected_malicious and not is_predicted_malicious:
                    fn += 1  # Dangerous Miss

                # Brief sleep to prevent hammering public API rate limits
                time.sleep(0.2)

        accuracy = ((tp + tn) / total_samples) * 100 if total_samples > 0 else 0
        precision = (tp / (tp + fp)) * 100 if (tp + fp) > 0 else 0
        recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        print("\n================================================================")
        print("ADVANCED METRICS & PERFORMANCE REPORT (N = 500)")
        print("================================================================")
        print(f"Total Samples Processed   : {total_samples}")
        print(f"True Positives (TP)       : {tp}")
        print(f"True Negatives (TN)       : {tn}")
        print(f"False Positives (FP)      : {fp}")
        print(f"False Negatives (FN)      : {fn}")
        print("-" * 64)
        print(f"Overall Accuracy          : {accuracy:.2f}%")
        print(f"Precision Index           : {precision:.2f}%")
        print(f"Recall (Sensitivity)      : {recall:.2f}%")
        print(f"F1-Score                  : {f1_score:.2f}")
        print(f"Average Inference Latency : {avg_latency:.3f} seconds/sample")
        print("================================================================")

    except FileNotFoundError:
        print(f"[-] Error: '{dataset_path}' not found.")

if __name__ == "__main__":
    evaluate_large_dataset()