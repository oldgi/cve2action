# Day 2 修訂包與手動更新 SOP

日期：2026-09-16。依使用者提供的 `day-02-assets_1.csv` 與 `day-02-findings_1.csv` 修訂；正式檔名不含 `_1`。本包是工作區檔案更新，不是 Git 歷史匯入，也不代表已推送 GitHub。

## 檔案清單

ZIP 根目錄直接對應 `C:\Users\lisp_\github\cve2action`，不含 `.git`、Day 1 或原始上傳檔。

| 檔案 | 內容 |
|---|---|
| README.md | 目前進度與文件入口 |
| CHANGELOG.md | 本次修訂摘要，維持 Unreleased |
| data/synthetic/day-02-assets.csv | 5 筆資產，保留責任團隊及共用跳板 |
| data/synthetic/day-02-findings.csv | 2 筆 finding，33 欄；分離核准、緩解與修補 |
| data/synthetic/day-02-scenario.json | 固定歷史時點及未知值規則 |
| docs/articles/day-02.md | 修訂後完整文章，主圖連結保留 |
| docs/research/day-02-case-design.md | 事實、假設、欄位與推論邊界 |
| docs/CVE2Action-30天總體施工藍圖.md | 新增第 20 節，不改 CRPS 權重 |
| docs/decisions/ADR-0003-條件式行動決策.md | 保存設計變更原因 |
| docs/images/day-02-cvss-context-web.jpg | 原有文章用 JPEG，未重新繪製 |
| docs/images/day-02-cvss-context.png | 原有高畫質 PNG，未重新繪製 |
| docs/images/day-02-cover-v2.png | 新版 16:9 封面，文章已改用此圖 |
| docs/images/day-02-rerank-styleB-r2.png | 使用者提供的內文排序圖，原樣保留；文章附條件說明 |
| scripts/validate_day02.py | 無額外套件、唯讀的 CSV 一致性檢查 |
| docs/releases/day-02-revision-MANIFEST.md | 本說明 |

## 1. 確認目前變更已保存

```powershell
cd C:\Users\lisp_\github\cve2action
git status --short
```

**若有輸出，先停止。** 先檢查並提交你自己的變更，或另存備份；不要直接覆蓋，也不要在未提交狀態下執行 pull --rebase。

確認乾淨後，逐條執行：

```powershell
git pull --rebase
git status --short
git rev-parse HEAD
```

任何命令出錯、出現衝突或第二次 status 不乾淨，都先停止。記下 HEAD 作為更新前基線；若 pull 已帶回其他新增內容，本包不一定包含那些更新，必須合併而非盲目覆蓋。

## 2. 先解壓到獨立目錄

```powershell
$day02Stage = Join-Path $env:TEMP ("cve2action-day02-" + [guid]::NewGuid().ToString("N"))
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\cve2action-day02-revised.zip" -DestinationPath $day02Stage
```

解壓失敗即停止。先閱讀暫存目錄中的文章與本說明；必要時比較現有檔案，例如：

```powershell
git diff --no-index -- .\docs\articles\day-02.md (Join-Path $day02Stage "docs\articles\day-02.md")
```

此處 diff 回傳 1 通常只是表示有差異，不是失敗；2 等其他錯誤須先處理。新版藍圖、README 與 CHANGELOG 都是完整檔案：若你在 GitHub／本機另有後續變更，請用編輯器合併，不要用整檔覆蓋。

## 3. 確認差異後套用

只有確認本包沒有蓋掉你要保留的內容後，才使用以下複製；否則逐檔手動合併。

```powershell
Get-ChildItem -LiteralPath $day02Stage -Force | Copy-Item -Destination . -Recurse -Force
git status --short
git diff --stat
git diff --check
python .\scripts\validate_day02.py
```

沒有 Python 可嘗試 `py -3 .\scripts\validate_day02.py`；本包已在交付環境通過檢查，但不能把未執行的本機檢查寫成成功。任何檢查失敗先停止；`git diff` 不顯示尚未追蹤檔案的內容，下一步暫存後仍要完整檢視。

## 4. 暫存、檢查、提交及推送

```powershell
git add -- README.md CHANGELOG.md
git add -- data/synthetic/day-02-assets.csv data/synthetic/day-02-findings.csv data/synthetic/day-02-scenario.json
git add -- docs/articles/day-02.md docs/research/day-02-case-design.md
git add -- "docs/CVE2Action-30天總體施工藍圖.md" "docs/decisions/ADR-0003-條件式行動決策.md"
git add -- docs/images/day-02-cvss-context-web.jpg docs/images/day-02-cvss-context.png
git add -- docs/images/day-02-cover-v2.png docs/images/day-02-rerank-styleB-r2.png
git add -- scripts/validate_day02.py docs/releases/day-02-revision-MANIFEST.md
git diff --cached --check
git diff --cached --stat
git diff --cached
```

確認只有預期檔案，沒有你希望保留的內容被刪除，再執行：

```powershell
git commit -m "docs(day-02): align cases with conditional remediation decisions"
git push origin main
git status --short
```

提交失敗就不要推送。若推送被拒絕，停止並確認原因；不要使用 force push。這份 SOP 不會自動處理 Git 衝突，也不需要複製任何 `.git` 目錄。

## 發文前兩件事

1. 上傳 `docs/images/day-02-cover-v2.png` 作為封面，並將 `docs/images/day-02-rerank-styleB-r2.png` 放在「今晚的答案」段落，保留其條件式圖說。
2. 將文章最後的相對檔案連結改成你的 GitHub 實際 URL。公開主張是「B 先緩解、A 同步審查」，不是宣告暫緩已被批准。原有主視覺留存於包內，但文章已不再引用。

## 驗證範圍

已檢查資料形狀、主鍵與外鍵、情境日期、決策狀態、未知值、核准必填條件及拒絕不一致資料的測試；另檢查 Markdown 本地連結與 ZIP 內容。本包沒有真實網路測試、正式核准、動態風險引擎或發布動作。
