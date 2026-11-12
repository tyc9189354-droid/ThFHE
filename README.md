# ThFHE 論文通用評測與雲端 Benchmark 框架

本專案為門檻全同態加密（Threshold Fully Homomorphic Encryption, ThFHE）量身打造之**通用學術評測框架**。
支援與多篇論文/基準方案（Baselines）在相同硬體與參數條件下進行公平且精確的效能與通訊量比較。

---

## 專案目錄結構

```text
.
├── configs/
│   └── benchmark_config.yaml      # 實驗參數設定（安全參數、(t, n) 矩陣、重複次數）
├── core/
│   ├── base_scheme.py             # 統一抽象介面 (Adapter Pattern 基底類別)
│   ├── metrics.py                 # 實驗指標數據結構 (Latency, Memory, Comm bytes)
│   └── profiler.py                # 高精確度計時與記憶體追蹤工具
├── schemes/
│   ├── dummy_scheme.py            # 示範方案 (流程測試與驗證)
│   └── custom_scheme_template.py  # 你的程式碼對接模板 (填入你的邏輯即可)
├── network/
│   ├── server.py                  # 雲端伺服器 (支援獨立部署至雲端 VM)
│   ├── client.py                  # 客戶端通訊層 (自動攔截並計算通訊流量)
│   └── comm_tracker.py            # 通訊統計器
├── runner/
│   └── benchmark_runner.py        # 自動化評測執行核心 (支援 Local 與 Remote 雙模式)
├── analysis/
│   ├── exporter.py                # 匯出結構化數據 (CSV / JSON，利於 LaTeX 論文製表)
│   └── plotter.py                 # 自動繪製論文標準圖形 (含誤差槓之長條圖與折線圖)
├── results/                       # 存放評測產生的數據與圖表
├── main.py                        # 框架主命令列入口 (CLI)
└── requirements.txt               # 依賴套件清單
```

---

## 核心評測維度 (Metrics)

1. **計算耗時 (Latency, ms)**：
   - 密鑰生成（KeyGen / DKG）
   - 加密（Encryption）
   - 同態運算（Eval Add / Eval Mult / Bootstrapping）
   - 部分解密（Partial Decryption）
   - 份額聚合與明文重構（Combine Decryption）
2. **通訊成本 (Communication Overhead, Bytes)**：
   - 上傳與下載位元組數（Upload / Download bytes）
   - 各參與方訊息輪數（Interaction rounds）
3. **儲存空間 (Sizes, Bytes)**：
   - 公鑰 (PK)、評估鑰 (EvalKey)、私鑰份額 (SK Share)、密文大小 (Ciphertext)
4. **記憶體峰值 (Peak RAM, KB)**
5. **正確性檢驗 (Correctness Verification)**：自動比對運算結果與明文真實值。

---

## 快速使用方式

### 1. 安裝可選繪圖與進階套件
```bash
pip install -r requirements.txt
```
*(注意：本框架核心具備零依賴回退設計，即使未安裝第三方套件，亦可原生執行本地評測與 CSV/JSON 匯出)*

### 2. 本地模擬評測 (Local Mode)
單機模擬各參與方與運算，量測純演算法與計算複雜度效能：
```bash
python3 main.py benchmark --mode local
```
結果將自動儲存於 `results/benchmark_summary.csv` 與 `results/benchmark_summary.json`。

### 3. 雲端伺服器評測 (Remote Server Mode)
#### [A] 在雲端伺服器上啟動 Server：
```bash
python3 main.py server --host 0.0.0.0 --port 8000
```
#### [B] 在客戶端執行遠端評測：
```bash
python3 main.py benchmark --mode remote --server-url http://<YOUR_CLOUD_SERVER_IP>:8000
```
框架將自動將密文發送至雲端伺服器進行同態運算與解密聚合，並精確計算傳輸位元組與網路端到端延遲。

---

## 如何接入你的程式碼？

1. 打開 `schemes/custom_scheme_template.py`。
2. 將你的函式引入並填入對應生命週期：
   - `setup(...)`
   - `keygen(...)`
   - `encrypt(...)`
   - `eval_add(...)` / `eval_mult(...)`
   - `partial_decrypt(...)`
   - `combine_decryption(...)`
3. 在 `main.py` 的 `schemes_to_test` 加入你的類別實例，即可一鍵與後續其他論文的實作進行全方位橫向對比！
