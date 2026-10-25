# Phase 3:綜合(對比 + 延伸)實作規劃書

狀態:**待核可的實作規劃**。本文件取代已移除的空殼 `phase3_attack_chain/`
(commit 394effc)。本文不跑任何實驗、不改既有結果與 raw log;待拍板後才依本文實作。

## 0. 定位

Phase 3 **不是第四種新攻擊**,而是把 Phase 1、Phase 2 兩個實驗主體收束成一個可
一般化貢獻的**綜合章**:

- **Part 1 對比**:把各攻擊放到同一組座標,論證共同罩門(多為既有資料再分析)。
- **Part 2 延伸**:泛化到更廣條件(跨模型 / 成分消融 / 黑箱),需少量新跑。

原 `phase3_attack_chain/` 的「實戰攻擊鏈」定位已廢棄(太實戰、非論文型)。
原 provenance 已改列為 **Phase 2.1**(assumed-breach 資料完整性攻擊,與 Phase 2
KB 投毒同族),目錄 `git mv` 改名為 `experiments/phase2_1_provenance/`,**不再屬於
Phase 3**。

## 1. 依賴

Part 1 對比需要 **Phase 2 新攻擊面 reasoning_hijack-via-KB** 的結果當其中一臂
(見 `experiments/phase2_data_attack/reasoning_hijack_via_kb_proposal.md`)。
因此執行順序:**先補 Ph2 那一臂 → 再做 Phase 3**。

## 2. 全篇 thesis

兩個主體在**兩個管道、兩個權限基準**下指向同一結論:

> **真正決定成敗的是 victim 的「推理 / 判斷層完整性」,管道只是外殼;決定性硬閘
> (intake_channel、verify_credential)只在判斷層先起疑時才作用。**

判斷層一旦被劫持,硬閘不是被**跳過**(Ph1 F3:`verify_credential` 根本沒被呼叫)
就是被**繞過**(Ph2 exp9:`intake_channel` 被「可信例行政策」說服)。

## 3. Part 1 — 跨 phase 對比(多為再分析,少量新跑)

把各攻擊放到同一組座標,用**同一 victim、同一 oracle、同一指標**比較:

| | Ph1 F3 | Ph2 reasoning_hijack-via-KB(待補) | Ph2 exp9 anti-suspicion |
|---|---|---|---|
| 管道 | 工單 free-text | KB 文章(RAG) | KB 文章(RAG) |
| 權限 | PR:N | PR:H | PR:H |
| 持久性 | 單發 | 持久 | 持久 |
| 致勝機制 | mocked-execution 記憶 | 同(測跨管道轉移) | 可信例行政策 |
| 被打穿的硬閘 | `verify_credential` 被跳過 | 待測 | `intake_channel` 被繞過 |

- 素材:現有 Ph1 F3(exp1/exp2)+ Ph2 exp9 + 待補的 Ph2 reasoning_hijack-via-KB。
- 產出:對照表 + thesis 論證;除整併既有資料外,不需新跑。
- 交付:`experiments/phase3_synthesis/comparison.md`(或併入本目錄報告)。

## 4. Part 2 — 延伸 / 泛化(需新跑,皆為既有基建小改)

1. **跨模型轉移(必做,補最大的洞)**:目前只有 qwen3:32b 一個 victim,外部效度最弱。
   凍結 payload 策略,只換 victim 模型(qwen3:8b、dolphin3 現成;有更多再加)。
   產出模型 × 成功率 + Wilson 表。
2. **成分消融**:逐一拔掉 payload 各成分(第一人稱 / 過去完成式 / `data.valid==true`
   具體宣稱 /「跳過」框架),找 load-bearing 成分 → 機制性結論。**這同時回答「凍結
   指令給得多具體才算數」——把 F3 的 coached-autonomy 但書從弱點轉成可量化發現**
   (量化「人給了多少戰術、agent 自己收斂多少」)。
3. **黑箱觀測**:`observability_mode="black_box"` → 貼近真實外部攻擊者效度。

交付:各子實驗各一 runner + `results/` + 分析。

## 5. 收尾 gate(封板前)

- [ ] Phase 2 reasoning_hijack-via-KB(自主臂,選配靜態臂)
- [ ] Phase 3 Part 1 對比章(再分析 + 對照表)
- [ ] Phase 3 Part 2 延伸:跨模型(必要)/ 成分消融 / 黑箱
- [ ] 防禦討論一段 —— **需你決定是否為論文放寬「報告不放防禦建議」的既有約束**
- [ ] 關鍵實驗拉大 n(便宜,提升統計強度)
- [ ] provenance 論文降附錄;實際 `git mv` 改名待核可
- [ ] 更新各 summary / AIVSS / 專案總 README / 論文大綱

## 6. 物理結構

- 本目錄 `experiments/phase3_synthesis/` 放 Part 1 對比 + Part 2 延伸的 runner /
  results / 報告。目錄名為暫定,如要改名於收尾時統一處理。
- provenance 已獨立為 Phase 2.1(`experiments/phase2_1_provenance/`),不在 Phase 3 範圍內。

## 7. 明確不做

- 不開第四種全新攻擊;不做 attack_chain。
- 不動 `victim_agent/`、`data/baseline/`、既有結果與 raw log;不 `git push`。
- 不在未核可前搬動 / 改名 / 刪除任何既有 phase 目錄。
- 任何新跑前先 `nvidia-smi` 確認 GPU 無非 ollama 佔用,並取得你的 go-ahead。
