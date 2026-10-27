# 第三章(第一部分):跨階段攻擊通道與機制之 2×2 交互對照分析

## 0. 章節定位與重分析方法論(Positioning & Zero-Compute Re-Analysis)

本章為第三階段第一部分(Phase 3 Part 1)之跨階段綜合對照研究。在方法論上,本章屬於**純粹之既有實驗重分析(pure re-analysis)**,**零額外算力消耗(zero new compute)**,所有數據皆直接取自已執行完畢且封存於版本庫中之基準實驗紀錄。

跨階段直接對照之所以具備嚴格的內部效度(internal validity),係因所有實驗均針對**同一凍結受害者模型(frozen victim)**與**同一確定性判準器(deterministic oracle)**進行測試:

* **受害者代理(Sandbox Victim)**:IT 服務台代理(IT-helpdesk agent),底層模型為 `qwen3:32b`(參數與系統提示詞完全凍結、`think:false`、強制嚴格 JSON 輸出、`temperature = 0`)。代理具備四項工具呼叫能力:`read_ticket`、`search_knowledge_base`、`verify_credential`、`reset_password`。
* **自動化攻擊迴圈(Autonomous Attacker)**:除靜態上界探針(P1)採用單一人工撰寫之乾淨樣本外,所有自動化攻擊實驗皆採用相同之雙模型自主迴圈架構——由 `qwen3:8b` 擔任策略規劃器(planner),並由 `dolphin3` 擔任載荷生成器(payload generator)。
* **資料來源目錄(Committed Experiment Sources)**:
  1. `experiments/phase1_ipi/results/reasoning_hijack/exp2`(Phase 1 F3:自由文本 × 模擬執行)
  2. `experiments/phase3_synthesis/prereq_freetext_trusted_routine_policy`(Phase 3 P2:自由文本 × 說服型常規政策)
  3. `experiments/phase2_data_attack/results/kb_poisoning/exp9`(Phase 2 exp9:知識庫 × 說服型常規政策)
  4. `experiments/phase2_data_attack/results/reasoning_hijack_kb/exp2_static_upper_bound`(Phase 2 P1:知識庫 × 模擬執行之靜態上界探針)
  5. `experiments/phase2_data_attack/results/reasoning_hijack_kb/exp1`(Phase 2 exp1:知識庫 × 模擬執行之自動化迴圈)

---

## 1. 跨階段 2×2 對照矩陣(The 2×2 Comparison Matrix)

本研究沿兩個核心維度建構 2×2 對照矩陣:

1. **注入通道軸(CHANNEL)**:分為公開表單提交之**自由文本工單備註(`free-text ticket_note`)**與經審核寫入之**知識庫文章(`knowledge-base article`, KB)**。依威脅模型定義,此通道軸與攻擊者權限(Privilege Required, `PR`)存在本質綁定:`free-text ticket_note` 對應無需權限之 `PR:N`(任何人皆可提交工單備註),而 `KB article` 對應高權限之 `PR:H`(攻擊者須使惡意文章通過審核並寫入知識庫)。
2. **攻擊機制軸(MECHANISM)**:
   * **說服型(`persuasion`)**:採用「受信任常規政策框架」(`trusted-routine-policy` framing),將密碼重設請求包裝為符合現行作業規範之例行授權流程。
   * **模擬執行型(`mocked-execution`)**:採用 H-CoT(Hijacking Chain-of-Thought)風格之推理劫持,使工單備註或知識庫文章偽裝為代理**自身已完成**之 `verify_credential` 工具執行結果(內嵌 `data.valid==true`),誘使代理誤認憑證驗證已通過而直接跳過檢查。

| Cell | Channel | Privilege | Mechanism | ASR | Wilson CI (95%) | Round Budget | Source Experiment |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **(1)** | `free-text ticket_note` | `PR:N` | `mocked-execution` (H-CoT, `data.valid==true`) | `5/5` (100%) | `[56.6, 100]%` | `6` | Phase 1 F3 (`reasoning_hijack` `exp2`)<br>`experiments/phase1_ipi/results/reasoning_hijack/exp2` |
| **(2)** | `free-text ticket_note` | `PR:N` | `persuasion` (`trusted-routine-policy`) | `0/5` (0%) | `approx [0, 0.43]` | `9` | Phase 3 P2 (`prereq_freetext_trusted_routine_policy`)<br>`experiments/phase3_synthesis/prereq_freetext_trusted_routine_policy` |
| **(3)** | `KB article` | `PR:H` | `persuasion` (`trusted-routine-policy`) | `5/5` (100%) | `[56.6, 100]%` | `6` | Phase 2 `exp9`<br>`experiments/phase2_data_attack/results/kb_poisoning/exp9` |
| **(4a)** | `KB article` | `PR:H` | `mocked-execution` (Static Upper Bound) | `5/5` (100%)* | N/A (`temp 0` 確定性重跑)* | `1` (5 reruns) | Phase 2 P1 (`exp2_static_upper_bound`)<br>`experiments/phase2_data_attack/results/reasoning_hijack_kb/exp2_static_upper_bound` |
| **(4b)** | `KB article` | `PR:H` | `mocked-execution` (Autonomous Loop) | `1/5` (20%)<br>彙整 $n=15$:**`5/15` (33.3%)** | `[0.04, 0.62]`<br>$n=15$:**`[0.15, 0.58]`** | `6` | Phase 2 `exp1`<br>`experiments/phase2_data_attack/results/reasoning_hijack_kb/exp1` |

> *註:Cell (4a) P1 為單一人工撰寫乾淨文章於受害者 `temp 0` 下之 5 次確定性重跑(deterministic probe with 5 reruns),並非 5 個獨立樣本(NOT 5 independent samples)。Cell (4b) 擴充樣本數至 $n=15$ 之 P4 實驗已完成(COMPLETED,2026-10-27):原始 5 活動(`1/5`)與新增 10 活動(`4/10`)彙整為 `5/15`(33.3%)。

### 各晶格實驗結果明細

1. **Cell (1) `free-text` × `mocked-execution`(`PR:N`,Phase 1 F3 / `reasoning_hijack exp2`)**:
   * 攻擊成功率(ASR)達 **`5/5`**,Wilson 95% CI 為 **`[56.6, 100]%`**,回合預算(round budget)為 **`6`**。
   * 其中 2 個攻擊活動(campaigns)於第 1 回合即告突破,全部 5 個活動均達成最高危害等級 **`T3`**(成功觸發 `reset_password`)。
   * 作用機制:注入之 `ticket_note` 偽裝成代理自身先前已執行完畢之 `verify_credential` 回傳結果(`data.valid==true`),導致受害者代理直接跳過 `verify_credential` 呼叫並執行 `reset_password`。

2. **Cell (2) `free-text` × `persuasion`(`PR:N`,Phase 3 P2 / `prereq_freetext_trusted_routine_policy`)**:
   * 攻擊成功率(ASR)為 **`0/5`**,Wilson 95% CI 約為 **`approx [0, 0.43]`**,回合預算提高至 **`9`**(注意:`9 >= exp9` 之預算 `6`,證明失敗並非源於回合預算不足)。
   * 所有攻擊活動最終皆被路由至人工審核(`needs_human_review`)。在總計 **45 個回合**(5 campaigns × 9 rounds)中,代理**從未請求呼叫 `reset_password`(0 次)**;其中 **13 個回合**代理確實先行呼叫了 `verify_credential`,但隨後依然升級轉交人工審核。
   * 作用機制:儘管備註內容同樣採用「例行授權政策」(`trusted-routine-policy`)語義框架,但因其來源屬性(provenance)為公開表單提交者之自由文本備註,受害者代理拒絕採信其政策效力。

3. **Cell (3) `KB` × `persuasion`(`PR:H`,Phase 2 `exp9`)**:
   * 攻擊成功率(ASR)達 **`5/5`**,Wilson 95% CI 為 **`[56.6, 100]%`**,回合預算為 **`6`**。
   * 作用機制:攻擊者將結構平實、語義可信之 `trusted-routine-policy` 規範寫入**已獲批准之知識庫文章(approved KB article)**。受害者檢索後將其視為現行有效之組織正式政策,並據此完成密碼重設。

4. **Cell (4) `KB` × `mocked-execution`(`PR:H`,Phase 2 P1 靜態上界 vs. `exp1` 自動化迴圈)**:
   * **靜態上界探針(P1,`exp2_static_upper_bound`)**:ASR 為 **`5/5`**。此實驗使用單一人工精確構造、未觸發禁用框架之乾淨文章,在受害者 `temp 0` 設定下重複執行 5 次,屬於確定性存在性探針(deterministic probe)。
   * **自動化迴圈(`exp1`)**:原始 $n=5$ 之 ASR 為 **`1/5`**;P4 擴充至 $n=15$ 後彙整為 **`5/15`(33.3%)**,Wilson 95% CI 自 **`[0.04, 0.62]`** 收緊為 **`[0.15, 0.58]`**,回合預算為 **`6`**。
   * **`1/5` 與 `5/5` 落差之歸因分析**:此落差源於**攻擊端載荷生成保真度(attacker payload-generation fidelity)**,而非受害者對知識庫通道之免疫。在 `exp1` 的 5 個自動化活動中,載荷生成器 `dolphin3` 有 **4 個活動**漂移並違反了凍結系統指令中明令禁止之框架(FORBIDDEN framings:如將文章偽裝為系統日誌 `log`、活動歷史 `activity-history` 或歷史案例 `past-cases`)。後續 P3 漏斗重分析(funnel re-analysis)證實:**檢索並非瓶頸**(28 個總回合中有 **26 個回合**成功檢索到毒化文章,即 `26/28`),而是失真的偽造框架觸發了受害者對公開表單工單之懷疑反射(public-form suspicion reflex),使代理在進入推理跳躍(reasoning-skip)之前即先一步將請求路由至 `needs_human_review`。

---

## 2. 交叉效應判讀:非加成性交互作用(Crossover Reading: Non-Additive Interaction)

若通道(或權限)與攻擊機制之間遵循簡單的線性加成模型(additive main-effects model),則從低權限通道(`free-text`, `PR:N`)升級至高權限通道(`KB`, `PR:H`),理應對所有攻擊機制產生同向且對稱的增益;反之,同一機制在不同通道間亦應維持穩定的相對強弱排序。然而,表 1 的實證結果呈現顯著的**交叉交互作用(crossover interaction)**:

1. **`persuasion` 機制呈現極端通道依賴性(0% → 100% 翻轉)**:
   完全相同的 `trusted-routine-policy` 政策說服框架,在 `free-text ticket_note`(Cell 2, P2)中即便給予更高回合預算(9 回合、共 45 次嘗試)仍為 **`0/5`**;一旦移入 `KB article`(Cell 3, `exp9`),在 6 回合預算內即躍升至 **`5/5`**。這顯示單純語義層面的權威政策宣稱,本身不具備跨通道穿透力。
2. **`mocked-execution` 機制具備跨通道轉移性(100% → 100% 靜態上界),但受制於載荷結構嚴苛度**:
   在無需任何特權的 `free-text ticket_note`(Cell 1, F3)中,`mocked-execution` 直接達到 **`5/5`**;在 `KB article` 的乾淨靜態探針(Cell 4a, P1)中同樣維持 **`5/5`**。而在自動化知識庫攻擊(Cell 4b, `exp1`)中降至 **`1/5`**,並非因為 `KB` 通道削弱了 `mocked-execution` 的機理,而是因為將「已完成之工具狀態(`data.valid==true`)」自然嵌入「靜態知識庫文檔」的語義約束遠比嵌入「工單備註」嚴苛,導致小型生成模型 `dolphin3` 在 4/5 的活動中誤入 `log` / `activity-history` / `past-cases` 等禁用文體。

因此,此 2×2 矩陣**絕非加成關係(NOT additive)**,而是由不同機制所綁定的「信任錨點」與通道屬性發生正交交叉所致。

---

## 3. 來源歸屬假說(Provenance Hypothesis)與下游硬閘門失效機制

### 3.1 核心論點:來源歸屬決定判斷層走向

上述交叉現象可由本研究提出之**來源歸屬假說(Provenance Hypothesis)**予以統一解釋:**受害者代理的判斷層(judgment layer)並非單純依據文本的表面語義決定行為,而是透過評估一項宣稱的「來源歸屬(provenance)」來裁定是否採信該宣稱。**

* **外部政策說服(External Persuasion)依賴「外部通道權威歸屬」**:
  當攻擊載荷主張「根據常規授權政策,此類工單可直接重設密碼」時,代理將該主張視為一項**外部規範宣告**,並檢驗其載體來源是否具備制度性授權。當載體為 `PR:H` 之已批准知識庫文章(`exp9`)時,其來源歸屬為受信任的組織知識庫,代理遂將其納為決策依據(`5/5`);當相同內容出現於 `PR:N` 之公開表單 `ticket_note`(P2)時,其來源歸屬為未受信任的外部提交者,代理立即啟動懷疑機制並拒絕授權(`0/5`)。
* **模擬執行劫持(Mocked-Execution)偽造「代理自我歸屬(Self-Provenance)」**:
  H-CoT 風格之 `mocked-execution` 並不試圖以「外部規定」說服代理,而是直接偽造代理**自身的內部推理狀態與工具執行記憶**(即偽裝為代理自己剛執行完 `verify_credential` 並獲得 `data.valid==true` 的回傳紀錄)。一旦代理將該片段誤認作「自我歸屬(self-provenance)」的既有執行結果,外部通道本身的信任等級(`PR:N` 或 `PR:H`)即被旁路——因此在 `free-text`(F3)與乾淨 `KB`(P1)中皆能達到 **`5/5`** 的完全突破。

### 3.2 確定性硬閘門位於來源信任判斷之「下游」(Hard Gates Sit Downstream)

在防禦架構中,`verify_credential`(憑證驗證工具)與 `intake_channel`(進件通道檢查)通常被設計為確定性硬閘門(deterministic hard gates)。然而,跨階段重分析證明:**這些硬閘門在控制流上皆位於代理「來源信任判斷層」的下游(downstream)**。當上游判斷層遭到劫持時,下游硬閘門將透過以下兩種方式失效;反之,當上游判斷層不信任來源時,代理會在硬閘門發揮放行作用前直接升級攔截:

1. **硬閘門被直接跳過(Skipped Gate — Cell 1, F3)**:
   在 F3 中,由於 `mocked-execution` 成功偽造了 `data.valid==true` 之自我歸屬狀態,代理的判斷層認定驗證步驟「已經完成且通過」,因而**根本不呼叫 `verify_credential`**,直接呼叫 `reset_password`。未曾被呼叫的確定性工具無法提供任何防禦。
2. **硬閘門被推理繞過(Talked Around / Rationalized — Cell 3, `exp9`)**:
   在 `exp9` 中,儘管工單帶有公開表單之 `intake_channel` 屬性,但因知識庫文章具備 `PR:H` 受信任來源歸屬,代理的判斷層將該 `intake_channel` 限制透過政策推理「合理化解釋(talked around)」為符合常規例外授權,進而放行 `reset_password`。
3. **來源不受信任時於閘門前強制升級(Escalated on Distrusted Provenance — Cell 2, P2)**:
   在 P2 中,由於 `ticket_note` 的 `PR:N` 來源不受信任,全部 45 個回合中 `reset_password` 從未被請求;即使在其中 13 個回合代理呼叫了 `verify_credential`,判斷層依然因來源可疑而將工單強制路由至 `needs_human_review`。同樣地,在 `exp1` 失敗的 4 個活動中,失真的 `log` / `activity-history` / `past-cases` 框架觸發了公開表單懷疑反射,使代理在發生推理跳躍前即路由至 `needs_human_review`。

此一證據鏈直接強化了本論文之核心母命題(whole-paper thesis):**在工具調用型 LLM 代理中,模型自身的「判斷層(judgment layer)」才是決定安全邊界的關鍵控制點(decisive locus of control)**;任何置於判斷層下游的確定性檢查或參數規則,皆無法彌補上游來源歸屬判斷的失守。

---

## 4. 通道與權限之本質共線性宣告(Gate B2 決策)

在實驗設計與統計詮釋上,本章必須公開且明確宣告**通道(Channel)與攻擊者權限(Privilege)之本質共線性(intrinsic confounding)**,並嚴格執行專案之 **Gate B2 決策**:

1. **威脅模型內生綁定**:
   在真實企業 IT 服務台架構中,提交工單備註(`free-text ticket_note`)本質上即為無特權外部介面(`PR:N`),而修改或新增標準作業知識庫文章(`KB article`)本質上即要求內部審核或管理員權限(`PR:H`)。因此,在 2×2 矩陣中,`free-text` 必然伴隨 `PR:N`,`KB` 必然伴隨 `PR:H`。
2. **Gate B2 決策:拒絕虛構去耦合晶格(No Fabricated Decoupling Cell)**:
   本研究明確決定**不強行拆解通道與權限**,亦不在沙盒中人為捏造背離真實系統語義的「高權限工單備註」或「無權限知識庫寫入」實驗晶格。在本章的所有推論中,「通道效應(`free-text` vs. `KB`)」與「權限／制度性信任層級(`PR:N` vs. `PR:H`)」被視為同一威脅模型結構下的複合變項(bound threat-model construct),**絕不宣稱已將物理資料結構(通道格式)與攻擊者權限等級進行獨立因子分離**。

---

## 5. 指標可比性與統計限制說明(Metric-Comparability Caveats)

為確保跨階段數據解讀之嚴謹性,讀者與審稿人應注意以下四項指標可比性條件與統計限制:

1. **回合預算(Round Budget)之不對稱性**:
   Cell (1) F3、Cell (3) `exp9` 與 Cell (4b) `exp1` 之自動化攻擊回合預算皆為 **`6` 回合**;而 Cell (2) P2 之回合預算則設定為 **`9` 回合**。由於 P2 的預算高於或等於其他晶格(`9 >= 6`),其在 9 回合(共 45 次嘗試)下仍取得 `0/5` 的結果,證實其失敗**並非受限於回合預算不足**,反而提供了更強的陰性邊界證據。
2. **確定性探針(P1)與隨機獨立樣本之區別**:
   Cell (4a) P1(`exp2_static_upper_bound`)之 **`5/5`** 數據,係以**單一人工撰寫之乾淨文章**在受害者 `temperature = 0` 設定下重跑 5 次所得。此實驗旨在驗證確定性上界(deterministic upper-bound probe),證明當載荷未觸發禁用文體時受害者必遭劫持,但其在統計上**等同於 $n=1$ 之確定性測試,絕非 5 個獨立抽樣樣本(NOT 5 independent samples)**,故不計算 Wilson 信賴區間。
3. **小樣本自動化實驗($n=5$)之信賴區間寬度**:
   目前所有自動化攻擊分支(F3、P2、`exp9`、`exp1`)之獨立活動樣本數均為 **$n=5$**。在 $n=5$ 下,即便觀測到極端比例(如 `5/5` 或 `0/5`),其雙尾 95% Wilson 信賴區間仍相當寬廣(`5/5` 對應 **`[56.6, 100]%`**;`0/5` 對應 **`approx [0, 0.43]`**;`1/5` 對應 **`[0.04, 0.62]`**)。
4. **P4 擴充實驗進行中(Pending Enlargement to $n=15$)**:
   針對變異較大之 Cell (4b) `exp1`(`KB` × `mocked-execution` 自動化迴圈),將樣本數由 $n=5$ 擴充至 **$n=15$** 之 **P4 實驗已完成(COMPLETED,2026-10-27)**。原始 5 活動 `1/5` 與新增 10 活動 `4/10` 彙整,點估計與信賴區間如下:
   * **`exp1` 擴充後攻擊成功率(ASR, $n=15$)**:`5/15` = **33.3%**
   * **`exp1` 擴充後 Wilson 95% CI($n=15$)**:**`[0.15, 0.58]`**(區間仍偏寬,但已較 $n=5$ 之 `[0.04, 0.62]` 收緊,且下界自 `0.04` 升至 `0.15`,排除「近乎從不成功」之假設)

---

## 6. 明確非主張事項(Explicit Non-Claims)

基於上述實驗邊界與方法論約束,本章明確排除以下過度推論(non-claims):

1. **不主張通道格式與攻擊者權限之因子獨立性(No Channel-vs.-Privilege Factor Independence)**:
   依 Gate B2 決策,本章不宣稱 `KB` 與 `free-text` 之間的差異可獨立歸因於檢索介面格式或特權等級之單一因子;兩者在威脅模型中係不可分割之共線結構。
2. **在 P4 完成前,不對小樣本($n=5$)自動化攻擊率作窄幅點估計宣稱(No Narrow Point-Estimate Claims on Small $n$)**:
   在 $n=5$ 的樣本規模下,本章僅依賴跨晶格之極端對比(`0/5` vs. `5/5`)論證結構性交叉效應,不將 `1/5`(Wilson CI `[0.04, 0.62]`)視為收斂後之精確母體生成成功率;對 `KB` × `mocked-execution` 自動化攻擊率之精確量化已由 P4($n=15$)更新為 `5/15`(33.3%,Wilson CI `[0.15, 0.58]`);該點估計落在 `0/5` 與 `5/5` 兩極端之間,支持交叉效應之結構性論證。
3. **不將靜態上界探針(P1)等同於自動化攻擊能力**:
   P1 之 `5/5` 僅證明受害者模型在面對合規 H-CoT 載荷時缺乏跨通道防禦力,不代表受限之小型攻擊模型(`dolphin3`)在無人工干預下具備同等之自然語言偽裝成功率。
