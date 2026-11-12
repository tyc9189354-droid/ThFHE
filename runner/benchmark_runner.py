import datetime
from typing import Dict, Any, List, Optional
from core.base_scheme import BaseThFHEScheme
from core.metrics import BenchmarkResult, StageMetric
from core.profiler import Profiler
from network.client import BenchmarkClient

class BenchmarkRunner:
    """
    評測管線執行器：自動化測試各階段效能、量測通訊量並驗證正確性。
    """

    def __init__(self, iterations: int = 5, warmup: int = 1):
        self.iterations = iterations
        self.warmup = warmup

    def run_local(
        self,
        scheme: BaseThFHEScheme,
        security_param: int,
        threshold_t: int,
        total_n: int,
        plain_m1: int = 15,
        plain_m2: int = 27
    ) -> BenchmarkResult:
        """
        本地端模擬評測：單機評測演算法各階段的計算耗時、記憶體與物件大小。
        """
        print(f"\n[+] Running LOCAL Benchmark: Scheme='{scheme.name}', (t={threshold_t}, n={total_n}, sec={security_param})")

        # 1. Setup
        scheme.setup(security_param=security_param, threshold_t=threshold_t, total_n=total_n)

        # 2. KeyGen
        keys, metric_keygen = Profiler.measure_execution(
            func=lambda: scheme.keygen(),
            iterations=self.iterations,
            warmup=self.warmup,
            stage_name="keygen"
        )
        pk = keys["pk"]
        eval_key = keys.get("eval_key")
        sk_shares = keys["sk_shares"]

        # 量測 Key 大小
        pk_size = len(scheme.serialize_key(pk))
        eval_key_size = len(scheme.serialize_key(eval_key)) if eval_key else 0
        sk_share_sample = next(iter(sk_shares.values())) if isinstance(sk_shares, dict) else sk_shares[0]
        sk_share_size = len(scheme.serialize_key(sk_share_sample))

        # 3. Encrypt
        ct1, metric_enc1 = Profiler.measure_execution(
            func=lambda: scheme.encrypt(plain_m1, pk),
            iterations=self.iterations,
            warmup=self.warmup,
            stage_name="encrypt"
        )
        ct2 = scheme.encrypt(plain_m2, pk)
        ct_size = len(scheme.serialize_ciphertext(ct1))

        # 4. Homomorphic Eval Add
        ct_add, metric_eval_add = Profiler.measure_execution(
            func=lambda: scheme.eval_add(ct1, ct2, eval_key),
            iterations=self.iterations,
            warmup=self.warmup,
            stage_name="eval_add"
        )

        # 5. Homomorphic Eval Mult
        ct_mult, metric_eval_mult = Profiler.measure_execution(
            func=lambda: scheme.eval_mult(ct1, ct2, eval_key),
            iterations=self.iterations,
            warmup=self.warmup,
            stage_name="eval_mult"
        )

        # 6. Partial Decrypt (模擬 t 個參與方計算份額)
        sample_parties = list(sk_shares.keys())[:threshold_t] if isinstance(sk_shares, dict) else list(range(1, threshold_t + 1))
        
        def run_all_partial_decrypts():
            shares = []
            for pid in sample_parties:
                sk_s = sk_shares[pid] if isinstance(sk_shares, dict) else sk_shares[pid - 1]
                shares.append(scheme.partial_decrypt(pid, ct_add, sk_s))
            return shares

        shares_list, metric_p_dec = Profiler.measure_execution(
            func=run_all_partial_decrypts,
            iterations=self.iterations,
            warmup=self.warmup,
            stage_name="partial_decrypt"
        )
        share_size = len(scheme.serialize_share(shares_list[0]))

        # 7. Combine Decryption
        dec_result, metric_combine = Profiler.measure_execution(
            func=lambda: scheme.combine_decryption(shares_list, ct_add, pk),
            iterations=self.iterations,
            warmup=self.warmup,
            stage_name="combine_decryption"
        )

        # 正確性檢查 (加法: m1 + m2)
        expected_add = plain_m1 + plain_m2
        correct = (dec_result == expected_add)

        result = BenchmarkResult(
            scheme_name=scheme.name,
            security_param=security_param,
            threshold_t=threshold_t,
            total_n=total_n,
            mode="local",
            timestamp=datetime.datetime.now().isoformat(),
            stages={
                "keygen": metric_keygen,
                "encrypt": metric_enc1,
                "eval_add": metric_eval_add,
                "eval_mult": metric_eval_mult,
                "partial_decrypt": metric_p_dec,
                "combine_decryption": metric_combine
            },
            key_sizes_bytes={
                "pk_bytes": pk_size,
                "eval_key_bytes": eval_key_size,
                "sk_share_bytes": sk_share_size
            },
            ciphertext_size_bytes=ct_size,
            share_size_bytes=share_size,
            correctness_verified=correct
        )

        print(f"  -> Correctness Verified: {correct} (Got: {dec_result}, Expected: {expected_add})")
        return result

    def run_remote(
        self,
        scheme: BaseThFHEScheme,
        server_url: str,
        security_param: int,
        threshold_t: int,
        total_n: int,
        plain_m1: int = 15,
        plain_m2: int = 27
    ) -> BenchmarkResult:
        """
        雲端伺服器評測模式：將運算發送至伺服器，測量網路通訊大小 (Upload/Download) 與端到端延遲。
        """
        print(f"\n[+] Running REMOTE Benchmark against server {server_url}...")
        client = BenchmarkClient(server_url)

        if not client.check_health():
            raise ConnectionError(f"Cannot connect to Cloud Server at {server_url}. Please ensure server is running.")

        # Local setup & keygen
        scheme.setup(security_param=security_param, threshold_t=threshold_t, total_n=total_n)
        client.setup_remote(scheme.name, security_param, threshold_t, total_n)

        keys = scheme.keygen()
        pk = keys["pk"]
        eval_key = keys.get("eval_key")
        sk_shares = keys["sk_shares"]

        ct1 = scheme.encrypt(plain_m1, pk)
        ct2 = scheme.encrypt(plain_m2, pk)

        # 測量遠端同態運算與通訊量
        client.comm_stats.reset()
        ct_res, metric_remote_eval = Profiler.measure_execution(
            func=lambda: client.eval_remote(scheme.name, "add", ct1, ct2, eval_key),
            iterations=self.iterations,
            warmup=self.warmup,
            stage_name="remote_eval_add"
        )
        metric_remote_eval.comm_sent_bytes = client.comm_stats.total_bytes_sent
        metric_remote_eval.comm_recv_bytes = client.comm_stats.total_bytes_received

        # 本地各方計算份額
        sample_parties = list(sk_shares.keys())[:threshold_t] if isinstance(sk_shares, dict) else list(range(1, threshold_t + 1))
        shares = [scheme.partial_decrypt(pid, ct_res, sk_shares[pid]) for pid in sample_parties]

        # 測量伺服器聚合重構與通訊量
        client.comm_stats.reset()
        recovered, metric_remote_combine = Profiler.measure_execution(
            func=lambda: client.combine_remote(scheme.name, shares, ct_res, pk),
            iterations=self.iterations,
            warmup=self.warmup,
            stage_name="remote_combine"
        )
        metric_remote_combine.comm_sent_bytes = client.comm_stats.total_bytes_sent
        metric_remote_combine.comm_recv_bytes = client.comm_stats.total_bytes_received

        correct = (recovered == (plain_m1 + plain_m2))

        return BenchmarkResult(
            scheme_name=scheme.name,
            security_param=security_param,
            threshold_t=threshold_t,
            total_n=total_n,
            mode="remote",
            timestamp=datetime.datetime.now().isoformat(),
            stages={
                "remote_eval_add": metric_remote_eval,
                "remote_combine": metric_remote_combine
            },
            correctness_verified=correct,
            metadata={"server_url": server_url}
        )
