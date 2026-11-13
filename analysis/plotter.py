import os
from typing import List
from core.metrics import BenchmarkResult

class ResultPlotter:
    """自動繪製符合論文規格之專業比較圖表"""

    @staticmethod
    def plot_latency_comparison(results: List[BenchmarkResult], output_image_path: str):
        """線上解密延遲比較圖 (Online Latency with Error Bars)"""
        try:
            import matplotlib.pyplot as plt
            import numpy as np
        except ImportError:
            print("[!] Note: matplotlib not installed. Skipping plot generation.")
            return

        os.makedirs(os.path.dirname(output_image_path), exist_ok=True)
        schemes = [r.scheme_name for r in results]
        means = [r.online.latency_ms for r in results]
        stds = [r.online.std_latency_ms for r in results]

        fig, ax = plt.subplots(figsize=(8, 5))
        bars = ax.bar(schemes, means, yerr=stds, capsize=5, color=["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728"][:len(schemes)], alpha=0.85)

        # 數值標籤
        for bar in bars:
            yval = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2.0, yval, f"{yval:.2f} ms", ha="center", va="bottom", fontsize=10, fontweight="bold")

        ax.set_ylabel("Online Latency (ms)", fontsize=12)
        ax.set_title("Online Threshold Decryption Latency", fontsize=14, fontweight="bold")
        ax.grid(axis="y", linestyle="--", alpha=0.6)
        plt.xticks(rotation=15, ha="right")
        plt.tight_layout()
        plt.savefig(output_image_path, dpi=300)
        plt.close()
        print(f"[✓] Saved latency comparison chart to: {output_image_path}")

    @staticmethod
    def plot_throughput_comparison(results: List[BenchmarkResult], output_image_path: str):
        """吞吐量比較 (Throughput Dec/sec in Log Scale)"""
        try:
            import matplotlib.pyplot as plt
            import numpy as np
        except ImportError:
            return

        os.makedirs(os.path.dirname(output_image_path), exist_ok=True)
        schemes = [r.scheme_name for r in results]
        throughputs = [max(0.1, r.online.throughput_dec_per_sec) for r in results]

        fig, ax = plt.subplots(figsize=(8, 5))
        bars = ax.bar(schemes, throughputs, color=["#2ca02c", "#1f77b4", "#9467bd", "#f59e0b"][:len(schemes)], alpha=0.85)
        ax.set_yscale("log")
        ax.set_ylabel("Throughput (Decryptions / sec) [Log Scale]", fontsize=12)
        ax.set_title("Threshold Decryption Throughput Comparison", fontsize=14, fontweight="bold")
        ax.grid(axis="y", linestyle="--", alpha=0.6)

        for bar in bars:
            yval = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2.0, yval * 1.1, f"{int(yval)}", ha="center", va="bottom", fontsize=10, fontweight="bold")

        plt.xticks(rotation=15, ha="right")
        plt.tight_layout()
        plt.savefig(output_image_path, dpi=300)
        plt.close()
        print(f"[✓] Saved throughput comparison chart to: {output_image_path}")
