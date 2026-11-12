# Threshold FHE 統一論文評測與基準測試框架

本專案為門檻全同態加密（Threshold Fully Homomorphic Encryption, ThFHE）量身打造之**通用學術評測與基準測試框架**。
支援多篇頂會論文實作與基準方案在完全相同的硬體與參數條件下，進行公平且精確的 **7 大階段（Setup、KeyGen、Offline Prep、同態加法、同態乘法、部分解密/捨入、份額聚合）** 實際效能評測與比較。

---

## 專案目錄架構

```text
ThFHE/
├── tool.py                        # ⭐ 通用核心工具庫 (含同態加法、同態乘法與 Gadget 重線性化、MPC 捨入、ZK 證明)
│
├── CCS25/                         # 論文 1: CCS 2025 (Zyskind et al.)
│   ├── server.py                  # 雲端協調伺服器 (Setup, KeyGen, 同態加/乘法評估, 3 輪 MPC 解密)
│   └── client.py                  # 客戶端 (同態加/乘法與門檻解密測試)
│
├── PELTA/                         # 論文 2: PELTA (Chatel et al., EPFL)
│   ├── server.py                  # 聚合者與驗證者 (ZK 惡意檢查、可驗證聚合、RLWE 同態乘法)
│   └── client.py                  # 參與方 (Prover，支援誠實份額提交、惡意攻擊攔截與 RLWE 測試)
│
├── web/                           # 🌐 互動式可視化 Web 實驗室與實測 API 伺服器
│   ├── index.html                 # 前端主頁面 (雙密文輸入、同態加/乘法、解密結果 Output Box、7 階段實測直方圖)
│   └── serve.py                   # 本地 Web 與實測後端 API 伺服器 (預設 port 3000)
│
├── core/                          # 框架抽象基底類別 (BaseThFHEScheme) 與指標 (Metrics)
├── schemes/                       # 評測轉接器 Adapters (CCS25, Noah's Ark Noise Flooding, PELTA)
├── runner/                        # 自動化 7 階段實測執行核心 (BenchmarkRunner)
├── analysis/                      # CSV/JSON 數據匯出器與圖表繪製模組
├── configs/                       # 實驗配置檔
├── results/                       # 實驗輸出數據
└── main.py                        # 框架主命令列入口 (CLI，支援 --parties 10..1000)
```

---

## 互動式 Web 視覺化儀表板 (Dashboard)
本專案內建美觀現代的 Web 視覺化控制台，連接實測後端 API：
- **雙密文輸入框 (`c₁`, `c₂`) 與解密結果輸出框 (`Output Box`)**：支援明文加密生成密文、**同態乘法 $\text{Dec}(c_1 \otimes c_2)$（含張量積縮放與 Gadget 重線性化）**、**同態加法 $\text{Dec}(c_1 \oplus c_2)$** 以及單獨門檻解密，並將解密明文、運算後密文與實測耗時顯示於專屬 Output Box。
- **參與方數量選單 ($10 \le N \le 1000$)**：可選擇或自訂 `10` 至 `1000` 個 Parties。
- **7 階段實測直方圖 (Live Benchmark Arena)**：在實際執行測試前保持空白無預設假數據，點擊「執行跨論文實際基準評測」後即時執行 Python 實測並繪製包含 **1. Setup、2. KeyGen、3. Offline Prep、4. Homo Add、5. Homo Mul、6. Partial Dec、7. Aggregation** 的真實執行時間直方圖。

```bash
# 啟動 Web 與實測 API 伺服器
python3 ThFHE/web/serve.py
# 瀏覽器開啟: http://localhost:3000
```

---

## 統一跨論文基準評測 (CLI Benchmark)
```bash
# 指定參與方數量 (10 ~ 1000) 執行本地實測
cd ThFHE && python3 main.py benchmark --mode local --parties 100
```
自動橫向對比 CCS 2025、Noah's Ark (Noise Flooding) 與 PELTA 的完整 7 階段耗時與吞吐量，並產出 CSV/JSON 報表！
