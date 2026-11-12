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
            "scheme_name", "mode", "k", "m",
            # Offline Metrics
            "offline_prep_time_ms", "offline_mults", "offline_rand_bits",
            "gate_storage_bits", "gate_storage_bytes",
            # Online Metrics
            "online_latency_ms", "online_std_latency_ms", "online_throughput_dec_per_sec",
            "online_rounds", "online_opens", "online_opened_bits", "online_mults",
            "comm_sent_bytes", "comm_recv_bytes", "correctness_verified"
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for r in results:
                writer.writerow([
                    r.scheme_name, r.mode, r.k, r.m,
                    r.offline.prep_time_ms, r.offline.num_mults, r.offline.num_rand_bits,
                    r.offline.gate_storage_bits, r.offline.gate_storage_bytes,
                    r.online.latency_ms, r.online.std_latency_ms, r.online.throughput_dec_per_sec,
                    r.online.num_rounds, r.online.num_opens, r.online.opened_bits, r.online.online_mults,
                    r.online.comm_sent_bytes, r.online.comm_recv_bytes, r.correctness_verified
                ])
        print(f"[✓] Saved CSV results to: {output_path}")
