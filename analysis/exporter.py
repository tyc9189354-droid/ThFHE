import os
import json
import csv
from typing import List
from core.metrics import BenchmarkResult

class ResultExporter:
    """將實驗數據匯出為 JSON 與 CSV 格式，方便整理與直接放入論文表格"""

    @staticmethod
    def export_json(results: List[BenchmarkResult], output_path: str):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        data = [r.to_dict() for r in results]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[✓] Saved JSON results to: {output_path}")

    @staticmethod
    def export_csv(results: List[BenchmarkResult], output_path: str):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        if not results:
            return

        headers = [
            "scheme_name", "mode", "security_param", "threshold_t", "total_n",
            "stage_name", "mean_time_ms", "std_time_ms", "min_time_ms", "max_time_ms",
            "comm_sent_bytes", "comm_recv_bytes", "memory_peak_kb",
            "ciphertext_size_bytes", "share_size_bytes", "correctness"
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for r in results:
                for stage_name, s in r.stages.items():
                    writer.writerow([
                        r.scheme_name, r.mode, r.security_param, r.threshold_t, r.total_n,
                        stage_name, s.mean_time_ms, s.std_time_ms, s.min_time_ms, s.max_time_ms,
                        s.comm_sent_bytes, s.comm_recv_bytes, s.memory_peak_kb,
                        r.ciphertext_size_bytes, r.share_size_bytes, r.correctness_verified
                    ])
        print(f"[✓] Saved CSV results to: {output_path}")
