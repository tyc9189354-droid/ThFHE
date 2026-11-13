import time
import math
import datetime
from typing import Dict, Any, List, Optional
from core.base_scheme import BaseThFHEScheme
from core.metrics import BenchmarkResult, OfflineMetric, OnlineMetric
from CCS25.client import ThresholdFHEClient
from tool import encode_ciphertext
from network.distributed_engine import run_scheme_distributed

class BenchmarkRunner:
    """
    統一評測執行核心：
    同時評測與比較多個 Scheme（CCS 2025 vs Noah's Ark Baseline vs PELTA），
    精確量測完整 7 個階段的實際執行時間：
      1. Setup (系統參數初始化)
      2. KeyGen (分散式金鑰份額與重線性化金鑰生成)
      3. Offline Prep (離線門預處理 / 承諾生成)
      4. Homo Add (同態加法評估)
      5. Homo Mul (同態乘法評估 + 重線性化)
      6. Partial Dec (部分解密 / MPC 捨入 / ZK 驗證)
      7. Aggregation (份額聚合與明文重構)
    """

    def __init__(self, iterations: int = 3, warmup: int = 1):
        self.iterations = iterations
        self.warmup = warmup

    def run_local(
        self,
        scheme: BaseThFHEScheme,
        k: int = 64,
        m: int = 1,
        num_parties: int = 10,
        **kwargs
    ) -> BenchmarkResult:
        """本地模式：實際執行所有階段並量測高精度耗時 (ms)"""
        num_parties = max(10, min(1000, int(num_parties)))
        print(f"\n[+] Running LOCAL Benchmark: Scheme='{scheme.name}' (k={k}, m={m}, parties={num_parties})")

        # 1. Stage 1: Setup Benchmark
        setup_times_ms = []
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            scheme.setup(k=k, m=m, num_parties=num_parties, **kwargs)
            setup_times_ms.append((time.perf_counter() - t0) * 1000.0)
        mean_setup_ms = sum(setup_times_ms) / len(setup_times_ms)

        # 2. Stage 2: KeyGen Benchmark (Distributed Shares + Gadget RelinKey)
        keygen_times_ms = []
        for _ in range(self.iterations):
            t0 = time.perf_counter()
            scheme.keygen()
            keygen_times_ms.append((time.perf_counter() - t0) * 1000.0)
        mean_keygen_ms = sum(keygen_times_ms) / len(keygen_times_ms)

        # 3. Stage 3: Offline Preprocessing Benchmark
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
            setup_time_ms=round(mean_setup_ms, 3),
            keygen_time_ms=round(mean_keygen_ms, 3),
            prep_time_ms=round(mean_prep_time, 3),
            num_mults=off_info.get("num_mults", 0),
            num_rand_bits=off_info.get("num_rand_bits", 0),
            gate_storage_bits=off_info.get("gate_storage_bits", 0),
            gate_storage_bytes=off_info.get("gate_storage_bytes", 0),
            details={
                "raw_setup_times_ms": setup_times_ms,
                "raw_keygen_times_ms": keygen_times_ms,
                "raw_prep_times_ms": prep_times_ms
            }
        )

        # 4. Stage 4: Homomorphic Evaluation (Add & Multiply) + Stage 5 & 6: Partial Dec & Aggregation
        ct0, _ = scheme.encrypt(0)
        ct1, _ = scheme.encrypt(1)
        ct_size_bytes = len(scheme.serialize_ciphertext(ct1))

        eval_add_times_ms = []
        eval_mul_times_ms = []
        partial_dec_times_ms = []
        agg_times_ms = []
        online_times_ms = []
        correctness_verified = True
        p_mod = 1 << m

        for _ in range(self.iterations):
            # Measure Homomorphic Addition: Enc(1) (+) Enc(0) -> Enc(1)
            t_add = time.perf_counter()
            ct_add = scheme.eval_add(ct1, ct0)
            eval_add_times_ms.append((time.perf_counter() - t_add) * 1000.0)

            # Measure Homomorphic Multiplication: Enc(1) (x) Enc(1) -> Enc(1)
            t_mul = time.perf_counter()
            ct_mul = scheme.eval_mul(ct1, ct1)
            eval_mul_times_ms.append((time.perf_counter() - t_mul) * 1000.0)

            # Decrypt Homomorphic Addition result
            fresh_gate_add = scheme.preprocess()
            dec_add, pdec_ms_1, agg_ms_1 = scheme.decrypt_with_stages(ct_add, fresh_gate_add)
            if dec_add != (1 + 0) % p_mod:
                correctness_verified = False

            # Decrypt Homomorphic Multiplication result
            fresh_gate_mul = scheme.preprocess()
            dec_mul, pdec_ms_2, agg_ms_2 = scheme.decrypt_with_stages(ct_mul, fresh_gate_mul)
            if dec_mul != (1 * 1) % p_mod:
                correctness_verified = False

            partial_dec_times_ms.extend([pdec_ms_1, pdec_ms_2])
            agg_times_ms.extend([agg_ms_1, agg_ms_2])
            online_times_ms.extend([pdec_ms_1 + agg_ms_1, pdec_ms_2 + agg_ms_2])

        mean_add = sum(eval_add_times_ms) / len(eval_add_times_ms)
        mean_mul = sum(eval_mul_times_ms) / len(eval_mul_times_ms)
        mean_pdec = sum(partial_dec_times_ms) / len(partial_dec_times_ms)
        mean_agg = sum(agg_times_ms) / len(agg_times_ms)
        mean_lat = sum(online_times_ms) / len(online_times_ms)
        variance = sum((x - mean_lat) ** 2 for x in online_times_ms) / len(online_times_ms) if len(online_times_ms) > 1 else 0.0
        std_lat = math.sqrt(variance)

        throughput = 1000.0 / mean_lat if mean_lat > 0 else 0.0
        on_info = scheme.get_online_metrics()

        online_metric = OnlineMetric(
            eval_add_time_ms=round(mean_add, 4),
            eval_mul_time_ms=round(mean_mul, 4),
            partial_dec_time_ms=round(mean_pdec, 3),
            agg_time_ms=round(mean_agg, 3),
            latency_ms=round(mean_lat, 3),
            std_latency_ms=round(std_lat, 3),
            throughput_dec_per_sec=round(throughput, 1),
            num_rounds=on_info.get("num_rounds", 3),
            num_opens=on_info.get("num_opens", 3),
            opened_bits=on_info.get("opened_bits", 0),
            online_mults=on_info.get("num_mults", 0),
            details={"raw_online_latencies_ms": online_times_ms}
        )

        print(f"  -> Setup: {offline_metric.setup_time_ms} ms | KeyGen: {offline_metric.keygen_time_ms} ms | Offline Prep: {offline_metric.prep_time_ms} ms")
        print(f"  -> Homo Add: {online_metric.eval_add_time_ms} ms | Homo Mul: {online_metric.eval_mul_time_ms} ms")
        print(f"  -> Partial Dec: {online_metric.partial_dec_time_ms} ms | Aggregation: {online_metric.agg_time_ms} ms | Total Online: {online_metric.latency_ms} ms")
        print(f"  -> Correctness (Add & Mul): {correctness_verified}")

        return BenchmarkResult(
            scheme_name=scheme.name,
            k=k,
            m=m,
            mode="local",
            timestamp=datetime.datetime.now().isoformat(),
            num_parties=num_parties,
            offline=offline_metric,
            online=online_metric,
            ciphertext_size_bytes=ct_size_bytes,
            correctness_verified=correctness_verified,
            metadata={"params": scheme.params}
        )

    def run_remote(self, server_url: str, k: int = 64, m: int = 1, b: int = 8, n_dim: int = 16, num_parties: int = 10) -> BenchmarkResult:
        """遠端雲端模式：透過 HTTP API 與 server.py 進行端到端評測"""
        print(f"\n[+] Running REMOTE Benchmark against server {server_url} (k={k}, m={m}, parties={num_parties})...")
        client = ThresholdFHEClient(server_url=server_url)

        client.check_health()
        setup_resp = client.setup_server(k=k, m=m, b=b, n_dim=n_dim, num_parties=num_parties, pool_size=self.iterations * 2)
        setup_ms = setup_resp.get("setup_time_ms", 0.0)

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
            num_parties=num_parties,
            offline=OfflineMetric(setup_time_ms=setup_ms),
            online=online_metric,
            correctness_verified=correctness,
            metadata={"server_url": server_url}
        )

    def run_distributed(
        self,
        scheme_name: str,
        k: int = 64,
        m: int = 1,
        b: int = 8,
        num_parties: int = 10,
        base_port: Optional[int] = None,
        **kwargs
    ) -> BenchmarkResult:
        """實體分散式多埠 Socket 模式：為 N 個節點綁定專屬 Socket Ports 執行真實網路評測"""
        port_offsets = {
            "ccs25": 14100,
            "noah": 14200,
            "baseline_noise_flooding": 14200,
            "pelta": 14300,
            "hqfs": 14400,
            "ot25": 14500,
            "ajax": 14600
        }
        bp = base_port or port_offsets.get(scheme_name.lower(), 14500)
        return run_scheme_distributed(
            scheme_name=scheme_name,
            num_parties=num_parties,
            k=k,
            m=m,
            b=b,
            base_port=bp,
            iterations=self.iterations,
            **kwargs
        )
