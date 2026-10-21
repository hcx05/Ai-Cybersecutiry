# SETUP — 環境建置

本文件說明在**研究機**上重現實驗環境的完整步驟：雙 GPU 分卡、Ollama 設定、
模型下載、`.env` 設定。所有實驗僅在本機、完全隔離的模擬環境中進行。

---

## 1. 硬體與 GPU

實驗設計為**雙 GPU 分卡**，兩個角色各用一張卡、各自一個 Ollama server：

| 角色 | GPU | Ollama port |
|---|---|---|
| Victim Agent | GPU 0 | `127.0.0.1:11435` |
| Attack Agent（planner + payload generator） | GPU 1 | `127.0.0.1:11436` |

> **目前 GPU 狀態（2026-10-21）**
>
> 本機 NVIDIA 驅動處於**版本不一致**狀態，重開機前無法使用 GPU：
>
> - 執行中的 kernel module：`580.173.02`（`/proc/driver/nvidia/version`）
> - 已安裝的使用者空間函式庫 / DKMS：`580.178.04`
> - `nvidia-smi` 會回報 `Failed to initialize NVML: Driver/library version mismatch`。
>
> 成因是驅動套件被 `apt` 升級後尚未重開機套用新模組。**修法：重開機**（線上
> 卸載 `nvidia` 模組不可行，模組正被佔用）。重開機後請確認 `nvidia-smi` 正常、
> `dkms status` 顯示 `580.178` 已為目前 kernel 建置。
>
> 在 GPU 修復前，下方的啟動指令仍可運作，但 Ollama 會自動**退回 CPU**；
> `qwen3:32b` 在 CPU 上會非常慢，僅適合煙霧測試，不適合正式計時實驗。

---

## 2. 模型存放位置

模型以環境變數 `OLLAMA_MODELS` 指定存放目錄。本機設定為：

```
OLLAMA_MODELS=/mnt/ubuntu_data/shelleyhsu/ollama-models
```

> **為何是這個路徑**：早期設定指向外接碟 `/media/shelleyhsu/Seagate/ollama-models`，
> 該碟目前未接上/未掛載；系統碟 `/`（home）僅餘約 16 GB，不足以容納模型。
> 曾先試用 `/mnt/shared_ssd`（sdb1），但該碟在下載期間掉線、ext4 進入
> `emergency_ro`（見下方「已知問題」），故最終改置於 `/mnt/ubuntu_data`
> （sdc1，ext4，約 1.1 TB 可用，讀寫正常）。
> 兩個 Ollama server 共用同一個模型庫目錄（唯讀共享 blob，彼此不衝突）。

---

## 3. 模型清單

三個角色、三個模型，Phase 1 至 Phase 2 全程一致：

| 角色 | 模型 | 取樣設定 |
|---|---|---|
| 攻擊方 · planner（規劃策略） | `qwen3:8b` | temperature 0.7 |
| 攻擊方 · payload generator（寫注入內容） | `dolphin3:latest` | temperature 0.9 |
| 被害方 · victim（受測 IT 客服 Agent） | `qwen3:32b` | temperature 0.0、`num_ctx` 16384 |

下載模型（server 啟動後，對任一 server 下載即可，因共用同一個模型庫）：

```bash
export OLLAMA_MODELS=/mnt/ubuntu_data/shelleyhsu/ollama-models
export OLLAMA_HOST=127.0.0.1:11435
ollama pull qwen3:8b
ollama pull dolphin3:latest
ollama pull qwen3:32b
```

---

## 4. 啟動兩個 Ollama server

兩個 server 共用同一個模型庫，分別綁定不同 GPU 與 port。

**Victim（GPU 0，port 11435）**

```bash
export CUDA_VISIBLE_DEVICES=0
export OLLAMA_VULKAN=false
export OLLAMA_MODELS=/mnt/ubuntu_data/shelleyhsu/ollama-models
export OLLAMA_HOST=127.0.0.1:11435
ollama serve
```

**Attack（GPU 1，port 11436）**

```bash
export CUDA_VISIBLE_DEVICES=1
export OLLAMA_VULKAN=false
export OLLAMA_MODELS=/mnt/ubuntu_data/shelleyhsu/ollama-models
export OLLAMA_HOST=127.0.0.1:11436
ollama serve
```

> GPU 修復前，`CUDA_VISIBLE_DEVICES` 會被忽略並退回 CPU；兩個 server 仍可
> 同時啟動，只是共用 CPU、速度較慢。

確認 server 已就緒：

```bash
ss -ltn | grep -E '11435|11436'
OLLAMA_HOST=127.0.0.1:11435 ollama list
```

---

## 5. `.env` 對應設定

`.env` 的連線邊界需與上述拓撲一致（以下為關鍵項，完整模板見 `.env.example`）：

```ini
# 被害方 → 11435
VICTIM_MODEL=qwen3:32b
OLLAMA_BASE_URL=http://127.0.0.1:11435
OLLAMA_ALLOWED_PORTS=11435
VICTIM_TEMPERATURE=0
VICTIM_NUM_CTX=16384

# 攻擊方 → 11436
ATTACK_PLANNER_MODEL=qwen3:8b
ATTACK_PAYLOAD_GENERATOR_MODEL=dolphin3
ATTACK_OLLAMA_BASE_URL=http://127.0.0.1:11436
ATTACK_OLLAMA_ALLOWED_PORTS=11436
```

> 若要將攻擊方也改到單一 server（例如只有一張可用 GPU 時全走 11435），
> 將 `ATTACK_OLLAMA_BASE_URL` 與 `ATTACK_OLLAMA_ALLOWED_PORTS` 一併改為
> `11435`，並只啟動 11435 這個 server 即可。

Python 不會自動讀取 `.env`，直接在主機執行時需先匯出：

```bash
set -a; source .env; set +a
```

---

## 6. 驗證與執行

```bash
# 單元測試
pytest tests/ -q

# Phase 2 exp3 控制組（只用到 victim，11435）
python3 experiments/phase2_data_attack/run_control_static_article.py
```

---

## 7. 已知問題（2026-10-21）

兩項環境問題，正式計時實驗前需先解決：

1. **GPU 驅動版本不一致** — 見第 1 節。重開機套用 `580.178` 模組即可，修復前只能 CPU。
2. **`/mnt/shared_ssd`（`/dev/sdb`）掉線** — 下載模型期間該 SATA 碟從匯流排消失
   （`/sys/block` 已無 `sdb`），ext4 進入 `emergency_ro/shutdown`，其上資料不可讀。
   目前模型已改放健康的 `/mnt/ubuntu_data`（`sdc1`），不受影響。若要查修 `sdb`，
   請管理員以 root 檢查：

   ```bash
   lsblk                                              # 確認 sdb 是否仍缺席
   sudo dmesg | grep -iE 'sdb|ata[0-9]|I/O error|EXT4-fs' | tail -50
   sudo smartctl -a /dev/sdb                          # 裝置回來後查 SMART 健康度
   sudo umount /mnt/shared_ssd && sudo fsck.ext4 -f /dev/sdb1
   ```

   `ata link reset` 類訊息多為線材/供電接觸問題；`medium error`、SMART 不 PASSED
   則為磁碟本身故障，資料不應再信任。
