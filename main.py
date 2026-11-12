#!/usr/bin/env python3
import os
import sys
import argparse
from typing import Dict, Any, List

# 確保專案根目錄在 sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from runner.benchmark_runner import BenchmarkRunner
from schemes.dummy_scheme import DummyThFHEScheme
from analysis.exporter import ResultExporter
from analysis.plotter import ResultPlotter
from network.server import run_server

def load_yaml_config(path: str) -> Dict[str, Any]:
    """讀取 YAML 設定，若 pyyaml 未安裝則提供預設值"""
    if not os.path.exists(path):
        return {}
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        print("[!] Note: pyyaml not installed, using default configurations.")
        return {}

def run_benchmark_cmd(args):
    config_path = args.config
    cfg = load_yaml_config(config_path)

    mode = args.mode or cfg.get("mode", "local")
    iterations = cfg.get("iterations", 5)
    warmup = cfg.get("warmup", 1)
    output_dir = cfg.get("output_dir", "./results")
    threshold_configs = cfg.get("threshold_configs", [
        {"threshold_t": 2, "total_n": 3},
        {"threshold_t": 3, "total_n": 5}
    ])
    sec_params = cfg.get("security_params", [128])
    server_url = args.server_url or cfg.get("remote_server", {}).get("url", "http://127.0.0.1:8000")

    runner = BenchmarkRunner(iterations=iterations, warmup=warmup)

    # 註冊欲比較的方案 (稍後使用者可在此加入 CustomThFHEScheme)
    schemes_to_test = [
        DummyThFHEScheme(name="Dummy-Baseline")
    ]

    all_results = []

    print(f"============================================================")
    print(f"  Starting ThFHE Benchmark Suite (Mode: {mode.upper()})")
    print(f"============================================================")

    for scheme in schemes_to_test:
        for sec in sec_params:
            for tc in threshold_configs:
                t = tc["threshold_t"]
                n = tc["total_n"]
                try:
                    if mode == "local":
                        res = runner.run_local(scheme=scheme, security_param=sec, threshold_t=t, total_n=n)
                    else:
                        res = runner.run_remote(scheme=scheme, server_url=server_url, security_param=sec, threshold_t=t, total_n=n)
                    all_results.append(res)
                except Exception as e:
                    print(f"[-] Error evaluating {scheme.name} at (t={t}, n={n}): {e}")

    # 匯出結果
    json_path = os.path.join(output_dir, "benchmark_summary.json")
    csv_path = os.path.join(output_dir, "benchmark_summary.csv")
    ResultExporter.export_json(all_results, json_path)
    ResultExporter.export_csv(all_results, csv_path)

    # 自動繪製圖表
    bar_img = os.path.join(output_dir, "stages_comparison.png")
    scalability_img = os.path.join(output_dir, "scalability_combine.png")
    ResultPlotter.plot_stages_bar_chart(all_results, bar_img)
    ResultPlotter.plot_scalability(all_results, scalability_img, stage_name="combine_decryption" if mode == "local" else "remote_combine")

    print("\n[✓] Benchmark execution completed successfully!")

def main():
    parser = argparse.ArgumentParser(description="ThFHE通用型論文評測框架 (Benchmark Framework)")
    subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

    # benchmark 子命令
    bench_parser = subparsers.add_parser("benchmark", help="Run benchmark suite")
    bench_parser.add_argument("--config", default="./configs/benchmark_config.yaml", help="Path to config file")
    bench_parser.add_argument("--mode", choices=["local", "remote"], help="Override benchmark mode")
    bench_parser.add_argument("--server-url", help="Override remote server URL")

    # server 子命令
    server_parser = subparsers.add_parser("server", help="Launch Cloud Benchmark Server")
    server_parser.add_argument("--host", default="0.0.0.0", help="Host address")
    server_parser.add_argument("--port", type=int, default=8000, help="Port number")

    args = parser.parse_args()

    if args.command == "benchmark":
        run_benchmark_cmd(args)
    elif args.command == "server":
        run_server(args.host, args.port)
    else:
        # 預設直接跑自我測試評測
        parser.print_help()

if __name__ == "__main__":
    main()
