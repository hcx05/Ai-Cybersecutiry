# Phase 1 各實驗 prompt 存底說明

為確保每一輪實驗都能獨立重現,每個 `expN/` 資料夾都存有該次執行實際使用的
三份 prompt:

| 檔案 | 角色 | 說明 |
|---|---|---|
| `planner*.txt` | 攻擊 planner | 各實驗版本不同(見各資料夾檔名),是該輪的主要變因 |
| `payload_generator_v1.txt` | payload 產生器 | **全程未變**,sha256 `2e0a01a9…`,與 `attack_agent/prompts/payload_generator.txt` 一致 |
| `system_v3_intake_channel.txt` / `system_v4_verify_credential.txt` | Victim system prompt | 依實驗階段不同(見下表) |

## Victim system prompt 版本

| 版本檔 | sha256(condition fingerprint) | 內容差異 | 使用實驗 |
|---|---|---|---|
| `system_v3_intake_channel.txt` | `cf6b22cc…` | 只有 `intake_channel` 硬規則,無 `verify_credential` 例外 | persuasive_atk exp1-5 |
| `system_v4_verify_credential.txt` | `4b1f182d…` | 在 v3 基礎上新增 `verify_credential` 例外工具與對應規則 | persuasive_atk exp6、credential_forgery exp1-5、context_overflow exp1-2 |

兩份版本檔在本目錄根層各留一份母本(`system_v3_intake_channel.txt`、
`system_v4_verify_credential.txt`),各 `expN/` 資料夾內的同名檔即由母本複製,
內容位元組完全相同。

## 重要註記:兩個 sha256 的差異

同一份 system prompt 在紀錄裡會出現兩個不同的 sha256,兩者意義不同:

- **condition fingerprint 的 `victim_system_prompt_sha256`**(`cf6b22cc…` /
  `4b1f182d…`):由攻擊框架對 committed 的 system prompt **檔案本身**取雜湊,
  是實驗重現分組的依據。本目錄存底的即是這個版本,與 repo 內的
  `victim_agent/prompts/system.txt`(v4)、`system_v3_intake_channel.txt`(v3)
  位元組一致。
- **victim 執行期 log 的 `execution_configuration.system_prompt_sha256`**
  (persuasive `8c6a74a5…`、其餘 `67a93f09…`):由 Victim Agent 在執行當下
  記錄。這個值與上面的檔案雜湊**不相等**,且差異不只換行;完整原文未被寫進
  log(log 只保留 path 與 sha),因此無法從既有紀錄逐位元組還原執行期當下
  載入的那份。合理推測是 Victim Agent 在載入基底 system prompt 後,還會動態
  併入工具定義/輸出格式等內容再一起計算雜湊,但這點尚未逐一驗證。

因此本目錄存底的 system prompt,應理解為**與 condition fingerprint 對應的
基底版本**(重現實驗分組的權威依據),而非「執行期當下位元組完全相同的
擷取檔」。planner 與 payload_generator 兩份不受此註記影響:它們的 committed
檔案雜湊與 condition fingerprint 記錄的 sha 完全一致。
