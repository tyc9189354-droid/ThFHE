import time
import math
import datetime
from typing import Dict, Any, List, Optional
from core.base_scheme import BaseThFHEScheme
from core.metrics import BenchmarkResult, OfflineMetric, OnlineMetric
from client import ThresholdFHEClient
from tool import encode_ciphertext

class BenchmarkRunner:
    """
    統一評測執行核心：
    可同時評測與比較多個 Scheme（例如 CCS25 vs 其他論文實作），
    精確量測離線預處理成本 (Offline) 與線上解密效能 (Online)。
    """

    def __init__(self, iterations: int = 5, warmup: int = 1):
        self.iterations = iterations
        self.warmup = warmup

    def run_local(self, scheme: BaseThFHEScheme, k: int, m: int, **kwargs) -> BenchmarkResult:
        """本地模式：量測純演算法與 MPC 協議的運算複雜度與指標"""
        print(f"\n[+] Running LOCAL Benchmark: Scheme='{scheme.name}' (k={k}, m={m})")

        # 1. Setup
        scheme.setup(k=k, m=m, **kwargs)

        # 2. Offline Preprocessing Benchmark
        # Warmup
        for _ in range(self.warmup):
            scheme.preprocess()

        prep_times_ms = []
        last_gates = None
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            last_gates = scheme.preprocess()
            prep_times_ms.append((time.perf_counter() - t0) * 1000.0)

        mean_prep_time = sum(prep_times_ms) / len(prep_times_ms)
        off_info = scheme.get_offline_metrics(last_gates)

        offline_metric = OfflineMetric(
            prep_time_ms=round(mean_prep_time, 3),
            num_mults=off_info.get("num_mults", 0),
            num_rand_bits=off_info.get("num_rand_bits", 0),
            gate_storage_bits=off_info.get("gate_storage_bits", 0),
            gate_storage_bytes=off_info.get("gate_storage_bytes", 0),
            details={"raw_prep_times_ms": prep_times_ms}
        )

        # 3. Online Decryption Benchmark
        test_messages = [0, 1]
        ciphertexts = [scheme.encrypt(msg) for msg in test_messages]
        ct_sample = ciphertexts[0][0]
        ct_size_bytes = len(scheme.serialize_ciphertext(ct_sample))

        # Measure online latency
        online_times_ms = []
        correctness_verified = True

        for _ in range(self.iterations):
            for i, msg in enumerate(test_messages):
                ct, _ = ciphertexts[i]
                # Prepare fresh gate
                fresh_gate = scheme.preprocess()

                t0 = time.perf_counter()
                recovered = scheme.decrypt(ct, fresh_gate)
                lat = (time.perf_counter() - t0) * 1000.0
                online_times_ms.append(lat)

                if recovered != msg:
                    correctness_verified = False

        mean_lat = sum(online_times_ms) / len(online_times_ms)
        variance = sum((x - mean_lat) ** 2 for x in online_times_ms) / len(online_times_ms) if len(online_times_ms) > 1 else 0.0
        std_lat = math.sqrt(variance)

        # Throughput estimation: 1000 / mean_lat_ms
        throughput = 1000.0 / mean_lat if mean_lat > 0 else 0.0

        on_info = scheme.get_online_metrics()

        online_metric = OnlineMetric(
            latency_ms=round(mean_lat, 3),
            std_latency_ms=round(std_lat, 3),
            throughput_dec_per_sec=round(throughput, 1),
            num_rounds=on_info.get("num_rounds", 3),
            num_opens=on_info.get("num_opens", 3),
            opened_bits=on_info.get("opened_bits", 0),
            online_mults=on_info.get("online_mults", 0),
            details={"raw_online_latencies_ms": online_times_ms}
        )

        print(f"  -> Offline: Prep={offline_metric.prep_time_ms} ms, Mults={offline_metric.num_mults}, Gates={offline_metric.gate_storage_bytes} B")
        print(f"  -> Online:  Latency={online_metric.latency_ms} ms (±{online_metric.std_latency_ms}), Throughput={online_metric.throughput_dec_per_sec} Dec/s")
        print(f"  -> Correctness: {correctness_verified}")

        return BenchmarkResult(
            scheme_name=scheme.name,
            k=k,
            m=m,
            mode="local",
            timestamp=datetime.datetime.now().isoformat(),
            offline=offline_metric,
            online=online_metric,
            ciphertext_size_bytes=ct_size_bytes,
            correctness_verified=correctness_verified,
            metadata={"params": scheme.params}
        )

    def run_remote(self, server_url: str, k: int = 64, m: int = 1, b: int = 8, n_dim: int = 16) -> BenchmarkResult:
        """遠端雲端模式：透過 HTTP API 與 server.py 進行端到端評測"""
        print(f"\n[+] Running REMOTE Benchmark against server {server_url} (k={k}, m={m})...")
        client = ThresholdFHEClient(server_url=server_url)

        # Health & setup
        client.check_health()
        client.setup_server(k=k, m=m, b=b, n_dim=n_dim, pool_size=self.iterations * 2)

        latencies_ms = []
        correctness = True

        for msg in [0, 1]:
            c_b64 = client.get_demo_ciphertext(msg)
            for _ in range(self.iterations):
                recovered, info = client.decrypt_interactive(c_b64)
                latencies_ms.append(info["total_rtt_ms"])
                if recovered != msg:
                    correctness = False

        mean_lat = sum(latencies_ms) / len(latencies_ms)
        std_lat = math.sqrt(sum((x - mean_lat)**2 for x in latencies_ms) / len(latencies_ms))
        throughput = 1000.0 / mean_lat if mean_lat > 0 else 0.0

        online_metric = OnlineMetric(
            latency_ms=round(mean_lat, 3),
            std_latency_ms=round(std_lat, 3),
            throughput_dec_per_sec=round(throughput, 1),
            num_rounds=3,
            num_opens=3,
            opened_bits=k - m + (math.ceil((k - m)/b) + 1) + k,
            online_mults=0,
            comm_sent_bytes=client.stats.bytes_sent,
            comm_recv_bytes=client.stats.bytes_recv
        )

        return BenchmarkResult(
            scheme_name="CCS25_Remote_Server",
            k=k,
            m=m,
            mode="remote",
            timestamp=datetime.datetime.now().isoformat(),
            offline=OfflineMetric(),
            online=online_metric,
            correctness_verified=correctness,
            metadata={"server_url": server_url}
        )
