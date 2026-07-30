# Ai-Cybersecutiry

研究一個由 LLM 驅動的 IT 客服 Agent(Victim Agent),在面對間接提示注入
(Indirect Prompt Injection, IPI)時的抵抗力,並用一個自動化的攻擊代理
(Attack Agent)產生攻擊、觀察回應、自主調整下一輪策略,測試能否串出一條
有真實後果的完整攻擊鏈。

---

## 背景與動機

近期已有真實案例顯示,具備敏感操作能力(例如密碼重設)的 LLM Agent,可能被
間接提示注入操縱去執行未經授權的動作。本專案在完全隔離的本機環境中,系統性地
測試這類風險:一個模擬公司 IT 客服的 Agent,處理來自不可信來源的內容(工單、
知識庫文章),觀察攻擊者能不能透過這些管道,誘導它做出超出預期範圍、甚至造成
實際傷害的行為。

**本專案所有攻擊行為僅在本機、完全隔離的模擬環境中進行,不涉及任何真實系統、
真實帳號或真實使用者資料。**

---

## 研究架構

### Victim Agent(受測對象)

一個處理工單的 IT 客服 Agent,擁有四個工具:

| 工具 | 功能 | 風險等級 |
|---|---|---|
| `read_ticket` | 讀取指派的工單 | 唯讀 |
| `search_knowledge_base` | 搜尋已核准的內部知識庫 | 唯讀 |
| `update_ticket` | 更新工單狀態、加註備註 | 低——影響範圍鎖定在單一工單,可逆 |
| `reset_password` | 重設工單提交者的密碼 | 高——影響範圍跨出工單本身,不可逆 |

每個工具呼叫,不論模型「決定」什麼,都必須先通過一層獨立於模型的決定性政策
驗證(`victim_agent/policy.py`)才會真正執行;每次執行也被鎖定在單一工單、單一
授權範圍內(session scoping),無法被注入內容說服跨出這個範圍。

### Attack Agent(自動化攻擊代理)

由三個角色組成,串成一個自主迴圈:

- **`analyzer`**:決定性地從 Victim Agent 的回應中抽取客觀事實(policy 有沒有
  擋、最終狀態、嘗試呼叫了什麼工具),不做主觀判斷
- **`planner`**:讀取目標與歷史紀錄,決定要繼續攻擊、判定成功、或判定沒招了,
  並給出下一輪的策略方向
- **`payload_generator`**:根據 planner 的指示,產生實際要注入的文字

三者串起「產生攻擊 → 遞送 → 呼叫 Victim Agent → 分析回應 → 下一輪」的完整
迴圈,全程自動化,不需人工介入每一輪。

### Controller

負責在每次實驗前,把環境(工單、知識庫、帳號重設紀錄)重置回已知的乾淨基準
狀態,確保實驗結果可重現。

---

## 攻擊面總覽(依 MITRE ATT&CK 攻擊階段對應)

本專案刻意按照攻擊鏈的不同階段,把研究拆成獨立、各自標明假設前提的部分,而
不是假裝這是一條從零開始、無縫銜接的鏈——每個階段各自的威脅模型與假設,詳見
對應的說明文件。

| 階段 | 對應 MITRE ATT&CK | 攻擊管道 | 說明文件 | 狀態 |
|---|---|---|---|---|
| Phase 1 | Initial Access | 工單內容(`ticket_note` / `ticket_description`) | [experiments/phase1_ipi/README.md](experiments/phase1_ipi/README.md) | 已有初步結果 |
| Phase 2 | Persistence | 知識庫文章(`knowledge_base_article`) | [experiments/phase2_data_attack/README.md](experiments/phase2_data_attack/README.md) | 尚未開始執行 |
| Phase 3 | Impact | 承接 Phase 2 的立足點,以 `reset_password` 為終點目標 | 尚未定義 `AttackGoal` | 規劃中 |

---

## 環境建置

雙 GPU 分卡、Ollama 設定、模型下載、`.env` 設定等完整步驟,見 [SETUP.md](SETUP.md)。

## 執行測試

```bash
pytest tests/ -q
```

## 執行一次攻擊實驗

```bash
set -a && source .env && set +a
python3 -m controller.reset_environment
python3 -m attack_agent.agent \
  --goal-id <目標代號> \
  --description "<目標的白話說明>" \
  --target-channel <ticket_note | ticket_description | knowledge_base_article> \
  --success-signal "<怎樣算攻擊成功>" \
  --ticket-id TICKET-001 \
  --max-rounds 3
```

---

## 目錄結構

```
victim_agent/       受測 Agent(agent.py、policy.py、tools/、prompts/)
attack_agent/       攻擊 Agent(agent.py、planner.py、payload_generator.py、
                    analyzer.py、schemas.py、ollama_client.py、prompts/)
controller/         實驗控制(reset_environment.py)
data/baseline/      版控追蹤的乾淨種子資料(tickets、knowledge_base)
data/runtime/       執行期資料,每次實驗前重置(inbox、knowledge_base、accounts)
experiments/        三階段實驗案例與各自的說明文件
logs/               執行紀錄(victim_agent、attack_agent、results)
tests/              測試套件,涵蓋 victim_agent 與 attack_agent 全部模組
```
