# Threshold FHE 統一論文評測與基準測試框架

本專案為門檻全同態加密（Threshold Fully Homomorphic Encryption, ThFHE）量身打造之**通用學術評測與基準測試框架**。
支援與多篇論文/基準方案（Baselines）在完全相同的硬體與參數條件下，進行公平且精確的**離線成本 (Offline Preprocessing)** 與 **線上效能 (Online Decryption)** 比較。

---

## 專案架構概覽

```text
.
├── tool.py                        # 核心工具庫 (F_ABB 抽象、門生成、MPC 快速變換、ToyLWE)
├── server.py                      # 雲端協調伺服器 (支援 REST API, 門池管理, 多輪交互)
├── client.py                      # 客戶端 (支援 One-Shot 與 3-Round Interactive MPC 解密)
├── core/
│   ├── base_scheme.py             # 統一抽象介面 (BaseThFHEScheme: Setup / Preprocess / Decrypt)
│   ├── metrics.py                 # 指標數據結構 (Offline 與 Online 雙維度評測)
│   └── profiler.py                # 高精確度計時器 (ns 級別)
├── schemes/
│   ├── ccs25_scheme.py            # CCS 2025 論文頂會方案 Adapter (無需雜訊淹沒)
│   ├── baseline_noise_flooding.py # 傳統 Noise Flooding (SOTA Dahl et al. 2023) Baseline
│   └── custom_scheme_template.py  # 未來新論文的代碼對接模板
├── runner/
│   └── benchmark_runner.py        # 自動化評測執行核心 (支援 Local 與 Remote Server 雙模式)
├── analysis/
│   ├── exporter.py                # 匯出結構化 CSV / JSON 數據 (利於 LaTeX 論文製表)
│   └── plotter.py                 # 自動繪製論文比較圖形 (延遲與吞吐量長條圖)
├── configs/
│   └── benchmark_config.yaml      # 實驗配置 (安全參數、模數 k/m/b、方案清單)
├── results/                       # 存放評測數據 (CSV, JSON, 圖表)
└── main.py                        # 統一命令列主入口 (CLI)
```

---

## 評測維度 (Metrics)

本框架針對門檻 FHE 解密特點，劃分兩大評測維度：

1. **離線預處理成本 (Offline Phase)**：
   - 預處理執行時間（`prep_time_ms`）
   - Beaver Triples / 乘法消耗次數（`offline_mults`）
   - 隨機位元生成量（`offline_rand_bits`）
   - 門儲存大小（`gate_storage_bits` / `gate_storage_bytes`，精確符合論文公式 5）
2. **線上解密效能 (Online Phase)**：
   - 單次解密端到端延遲（`online_latency_ms`，含 Mean 與 Std dev）
   - 每秒解密吞吐量（`online_throughput_dec_per_sec`）
   - 交互輪數（`online_rounds`，如 CCS25 為 3 輪）
   - 揭示次數與位元數（`online_opens`, `online_opened_bits`）
   - 線上通訊流量（`comm_sent_bytes`, `comm_recv_bytes`）
   - 正確性驗證（`correctness_verified`）

---

## 快速使用

### 1. 執行本地跨論文基準比較 (Local Benchmark)
```bash
python3 main.py benchmark --mode local
```
> 將自動遍歷所有配置（如 $k=16, 64$），橫向對比 CCS25 與傳統 Baseline，結果自動儲存於 `results/benchmark_summary.csv` 與 `results/benchmark_summary.json`。

### 2. 啟動雲端伺服器 (Cloud Server)
```bash
python3 server.py --host 0.0.0.0 --port 8000 --k 64 --m 1 --b 8
```

### 3. 客戶端發起解密 (Client)
```bash
# 執行 3-Round Interactive MPC 解密
python3 client.py --server-url http://127.0.0.1:8000
```

---

## 如何接入未來的新論文程式碼？

1. 參考 `schemes/custom_scheme_template.py`。
2. 繼承 `BaseThFHEScheme`，實作 `setup()`, `preprocess()`, `encrypt()`, `decrypt()`, `get_offline_metrics()`, `get_online_metrics()`。
3. 在 `main.py` 的 `SCHEME_REGISTRY` 註冊你的方案名稱，即可一鍵納入自動化比較！
