#!/usr/bin/env python3
"""
================================================================================
Main Entry Point: Threshold FHE Unified Benchmark Framework
================================================================================
Usage:
  # 執行本地跨論文基準評測 (CCS25 vs Baseline Noise Flooding)
  python3 main.py benchmark --mode local

  # 啟動雲端伺服器 (供分散式/遠端評測使用)
  python3 main.py server --port 8000

  # 透過網路評測遠端伺服器
  python3 main.py benchmark --mode remote --server-url http://127.0.0.1:8000
"""

import os
import sys
import argparse
from typing import Dict, Any, List

# 確保專案根目錄在 sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from runner.benchmark_runner import BenchmarkRunner
from schemes.ccs25_scheme import CCS25ThFHEScheme
from schemes.baseline_noise_flooding import BaselineNoiseFloodingScheme
from analysis.exporter import ResultExporter
from analysis.plotter import ResultPlotter
import server

SCHEME_REGISTRY = {
    "ccs25": CCS25ThFHEScheme,
    "baseline_noise_flooding": BaselineNoiseFloodingScheme
}

def load_yaml_config(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        return {}

def run_benchmark_cmd(args):
    config_path = args.config
    cfg = load_yaml_config(config_path)

    mode = args.mode or cfg.get("mode", "local")
    iterations = cfg.get("iterations", 5)
    warmup = cfg.get("warmup", 1)
    output_dir = cfg.get("output_dir", "./results")
    param_list = cfg.get("test_params", [
        {"k": 16, "m": 1, "b": 4},
        {"k": 64, "m": 1, "b": 8}
    ])
    scheme_names = cfg.get("schemes", ["ccs25", "baseline_noise_flooding"])
    server_url = args.server_url or cfg.get("remote_server", {}).get("url", "http://127.0.0.1:8000")

    runner = BenchmarkRunner(iterations=iterations, warmup=warmup)
    all_results = []

    print(f"============================================================")
    print(f"  Starting Threshold FHE Benchmark Suite (Mode: {mode.upper()})")
    print(f"  Comparing Schemes: {scheme_names}")
    print(f"============================================================")

    if mode == "local":
        for params in param_list:
            k = params["k"]
            m = params["m"]
            b = params.get("b", 4)
            print(f"\n>>> Parameter Set: k={k}, m={m}, b={b}")

            for s_name in scheme_names:
                scheme_cls = SCHEME_REGISTRY.get(s_name)
                if not scheme_cls:
                    print(f"[-] Unknown scheme: {s_name}")
                    continue

                scheme_inst = scheme_cls()
                try:
                    res = runner.run_local(scheme=scheme_inst, k=k, m=m, b=b)
                    all_results.append(res)
                except Exception as e:
                    print(f"[-] Error evaluating {s_name}: {e}")
    else:
        # Remote mode
        res = runner.run_remote(server_url=server_url, k=64, m=1, b=8)
        all_results.append(res)

    # 匯出結果
    json_path = os.path.join(output_dir, "benchmark_summary.json")
    csv_path = os.path.join(output_dir, "benchmark_summary.csv")
    ResultExporter.export_json(all_results, json_path)
    ResultExporter.export_csv(all_results, csv_path)

    # 自動繪圖
    lat_chart = os.path.join(output_dir, "online_latency_comparison.png")
    thru_chart = os.path.join(output_dir, "throughput_comparison.png")
    ResultPlotter.plot_latency_comparison(all_results, lat_chart)
    ResultPlotter.plot_throughput_comparison(all_results, thru_chart)

    print("\n[✓] Benchmark execution completed successfully!")

def main():
    parser = argparse.ArgumentParser(description="Threshold FHE Benchmark Framework")
    subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

    # benchmark
    b_parser = subparsers.add_parser("benchmark", help="Run benchmark suite")
    b_parser.add_argument("--config", default="./configs/benchmark_config.yaml", help="Path to config file")
    b_parser.add_argument("--mode", choices=["local", "remote"], help="Override benchmark mode")
    b_parser.add_argument("--server-url", help="Override remote server URL")

    # server
    s_parser = subparsers.add_parser("server", help="Launch Cloud Server")
    s_parser.add_argument("--host", default="0.0.0.0", help="Host address")
    s_parser.add_argument("--port", type=int, default=8000, help="Port number")
    s_parser.add_argument("--k", type=int, default=64, help="k")
    s_parser.add_argument("--m", type=int, default=1, help="m")
    s_parser.add_argument("--b", type=int, default=8, help="b")

    args = parser.parse_args()

    if args.command == "benchmark":
        run_benchmark_cmd(args)
    elif args.command == "server":
        server.run(host=args.host, port=args.port, k=args.k, m=args.m, b=args.b)
    else:
        # 預設執行 benchmark
        args.config = "./configs/benchmark_config.yaml"
        args.mode = "local"
        args.server_url = None
        run_benchmark_cmd(args)

if __name__ == "__main__":
    main()
