# Threshold FHE (ThFHE) 統一論文評測與基準測試框架

本專案為門檻全同態加密（Threshold Fully Homomorphic Encryption, ThFHE）量身打造之**通用學術評測與基準測試框架**。
支援多篇頂會論文實作與基準方案在完全相同的硬體與參數條件下，進行公平且精確的 **7 大階段（Setup、KeyGen、Offline Prep、同態加法、同態乘法、部分解密/捨入、份額聚合）** 實際效能評測與互動式視覺化驗證。

---

## 專案目錄架構

```text
.
├── README.md                      # 專案說明文件 (最上層入口)
├── tool.py                        # ⭐ 通用核心工具庫 (含 LWE/RLWE 同態加乘法、Gadget 重線性化、SIMD 平行運算、MPC 捨入、ZK 證明)
│
├── CCS25/                         # 論文 1: CCS 2025 (Zyskind et al.)
│   ├── server.py                  # 雲端協調伺服器 (Setup, KeyGen, 同態加/乘法評估, 3 輪 MPC 解密)
│   └── client.py                  # 客戶端 (同態加/乘法與門檻解密測試)
│
├── PELTA/                         # 論文 2: PELTA (Chatel et al., EPFL)
│   ├── server.py                  # 聚合者與驗證者 (Commit-then-Prove ZK 惡意檢查、可驗證聚合、RLWE 同態乘法)
│   └── client.py                  # 參與方 (Prover，支援誠實份額提交、惡意攻擊攔截與 RLWE 測試)
│
├── HQFS/                          # 論文 3 (Our Work): Actively Secure and CPA^D-Resistant Threshold FHE via Homomorphic Quotient Proofs
│   ├── server.py                  # 雲端服務商 (CSP) 與資料接收者 (DR) (Alg 1 Setup, Alg 6 BFS 批次過濾解密, Alg 7/8 同態運算與零密文疊加)
│   ├── client.py                  # 資料擁有者 (DO) 與分散式節點 (DCN) (Alg 2 KeyGen, Alg 3 RLKGen, Alg 4 iNTT 加密, Alg 5 HQ-FS ZKP 部分解密)
│   └── tool.py                    # 專屬工具橋接模組 (整合至頂層 tool.py)
│
├── web/                           # 🌐 互動式可視化 Web 實驗室與實測 API 伺服器
│   ├── index.html                 # 前端主頁面 (支援 T=1024 明文空間、Scalar/SIMD 多槽平行運算、7 階段獨立按鈕與實測直方圖)
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

本專案內建互動式 Web 視覺化實驗室，直接連接實測後端 API：
- **明文空間標示与切換（預設 `T = 1024`）**：在每個明文輸入框旁清楚標示明文空間（如 `T=1024 (0~1023)`），並支援於頂部選單切換 `T = 1024`、`256`、`16`、`2`。
- **Scalar 單一純量與 ⚡ SIMD 多槽平行模式**：
  - **CCS 2025**：支援 SWAR 64-bit 暫存器位元打包同態加法與多槽平行同態乘法。
  - **PELTA**：支援基於負循環 NTT / CRT 槽位打包之單一 RLWE 密文多槽平行同態加法與乘法。
- **7 階段獨立執行按鈕與右側即時 Log 視窗**：左側解密輸出框僅乾淨顯示最終解密結果（純量或 SIMD 向量），按下各階段按鈕（`1. Setup` ~ `7. Aggregate`）時於右側終端機即時顯示完整密碼學執行細節。
- **隨機惡意節點抽樣與攻擊模擬 ($0\% \sim 49\%$)**：每次抽樣皆隨機選擇惡意參與方（非固定順序），並支援 4 種惡意攻擊模式與即時攔截驗證。
- **跨論文 7 階段實測直方圖 (Live Benchmark Arena)**：支援 $10 \le N \le 1000$ 參與方規模之實際測試與直方圖對比。

```bash
# 啟動 Web 與實測 API 伺服器
python3 web/serve.py
# 瀏覽器開啟: http://localhost:3000
```

---

## 統一跨論文基準評測 (CLI Benchmark)

```bash
# 驗證核心密碼學原語、同態乘法與 SIMD 正確性
python3 tool.py

# 指定參與方數量 (10 ~ 1000) 執行本地 7 階段跨論文實測
python3 main.py benchmark --mode local --parties 100
```
自動橫向對比 CCS 2025、Noah's Ark (Noise Flooding) 與 PELTA 的完整 7 階段耗時與吞吐量，並產出 CSV/JSON 報表。
