import os
from typing import List
from core.metrics import BenchmarkResult

class ResultPlotter:
    """自動繪製符合論文發表情境的專業比較圖表 (支援純乾淨樣式與 Error bars)"""

    @staticmethod
    def plot_stages_bar_chart(results: List[BenchmarkResult], output_image_path: str):
        """繪製各方案在各階段之執行時間比較長條圖"""
        try:
            import matplotlib.pyplot as plt
            import numpy as np
        except ImportError:
            print("[!] Warning: matplotlib/numpy not installed. Skipping plot generation.")
            return

        os.makedirs(os.path.dirname(output_image_path), exist_ok=True)

        # 整理方案與階段
        schemes = list({r.scheme_name for r in results})
        stages = ["keygen", "encrypt", "eval_add", "eval_mult", "partial_decrypt", "combine_decryption"]
        
        # 篩選存在的 stage
        available_stages = []
        for stage in stages:
            if any(stage in r.stages for r in results):
                available_stages.append(stage)

        if not available_stages:
            return

        x = np.arange(len(available_stages))
        width = 0.8 / len(schemes)

        fig, ax = plt.subplots(figsize=(10, 6))

        for idx, scheme_name in enumerate(schemes):
            # 取該 scheme 第一筆結果
            r = next((item for item in results if item.scheme_name == scheme_name), None)
            if not r:
                continue

            means = [r.stages[st].mean_time_ms if st in r.stages else 0 for st in available_stages]
            stds = [r.stages[st].std_time_ms if st in r.stages else 0 for st in available_stages]

            offset = (idx - len(schemes) / 2 + 0.5) * width
            ax.bar(x + offset, means, width, yerr=stds, label=scheme_name, capsize=4, alpha=0.85)

        ax.set_ylabel("Execution Time (ms)", fontsize=12)
        ax.set_title("Computational Cost Across Stages", fontsize=14, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels(available_stages, rotation=15, ha="right", fontsize=11)
        ax.legend(fontsize=11)
        ax.grid(axis="y", linestyle="--", alpha=0.6)

        plt.tight_layout()
        plt.savefig(output_image_path, dpi=300)
        plt.close()
        print(f"[✓] Saved stage comparison chart to: {output_image_path}")

    @staticmethod
    def plot_scalability(results: List[BenchmarkResult], output_image_path: str, stage_name: str = "combine_decryption"):
        """繪製隨參與方數量 (N) 或門檻 (T) 增長之擴展性折線圖"""
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            return

        os.makedirs(os.path.dirname(output_image_path), exist_ok=True)
        schemes = list({r.scheme_name for r in results})

        fig, ax = plt.subplots(figsize=(8, 5))

        for scheme_name in schemes:
            scheme_results = [r for r in results if r.scheme_name == scheme_name and stage_name in r.stages]
            scheme_results.sort(key=lambda item: item.total_n)

            if not scheme_results:
                continue

            ns = [r.total_n for r in scheme_results]
            times = [r.stages[stage_name].mean_time_ms for r in scheme_results]
            errors = [r.stages[stage_name].std_time_ms for r in scheme_results]

            ax.errorbar(ns, times, yerr=errors, marker="o", capsize=4, label=scheme_name, linewidth=2)

        ax.set_xlabel("Number of Parties (N)", fontsize=12)
        ax.set_ylabel(f"{stage_name} Latency (ms)", fontsize=12)
        ax.set_title(f"Scalability Analysis: {stage_name}", fontsize=14, fontweight="bold")
        ax.legend(fontsize=11)
        ax.grid(True, linestyle="--", alpha=0.6)

        plt.tight_layout()
        plt.savefig(output_image_path, dpi=300)
        plt.close()
        print(f"[✓] Saved scalability chart to: {output_image_path}")
