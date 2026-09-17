# Day 3｜審稿、發文與 Git 交付清單

日期：2026-09-17。版本：merged-2（三把尺、圖說與全文合併）。

目前可確認：Day 1、Day 2 已由作者發布；Day 2 推送成功且當時工作目錄乾淨。Day 3 本包可審稿，尚未發布或推送。

## 檔案清單

ZIP：`cve2action-day03-merged.zip`。路徑以儲存庫根目錄為起點，沒有外層資料夾，不含 `.git`。本包可獨立使用，不必先解壓先前兩個 Day 3 包。

| 路徑 | 用途 |
|---|---|
| `docs/articles/day-03.md` | 完整文章草稿 |
| `docs/articles/day-03-visual-captions.md` | 已合併的圖說與編輯備忘 |
| `docs/images/day-03-lock-analogy.png` | 封面兼開場比喻圖 |
| `docs/images/day-03-three-rulers.png` | 前段三把尺記憶圖 |
| `docs/images/day-03-three-rulers.svg` | 記憶圖向量原稿 |
| `docs/images/day-03-meeting-rulers.png` | 中段會議辨認圖 |
| `docs/images/day-03-meeting-rulers.svg` | 會議圖向量原稿 |
| `docs/images/day-03-severity-threat-risk.png` | 可上傳的概念關係圖 |
| `docs/images/day-03-severity-threat-risk.svg` | 可編修向量原稿 |
| `docs/images/day-03-severity-threat-risk.mmd` | Mermaid 邏輯原稿 |
| `docs/research/day-03-concepts-and-boundaries.md` | 官方來源、假設與推論邊界 |
| `docs/releases/day-03-publish-MANIFEST.md` | 本清單 |

本包不覆蓋 README、CHANGELOG、藍圖、Day 2 或既有決策紀錄。若已有同名 Day 3 檔案，先比較、合併，不直接覆蓋。

## iPad 審稿／發文

1. 解壓 ZIP，閱讀 `docs/articles/day-03.md`。
2. 依文章順序上傳四張 PNG：壞鎖、三把尺、會議辨認、延伸閱讀流程圖；SVG 與 Mermaid 保留做版控。
3. 將文中四個相對圖片路徑替換成平台產生的圖片網址；保留圖說與官方來源連結。
4. 預覽標題、表格與圖片。確認「延伸案例是虛構分支」、「控制須驗證」、「延後不是不修」。
5. 發布後保存 Day 3 網址，再更新專案索引與發布紀錄。

## 筆電手動匯入

以下假設筆電已 clone 儲存庫。先檢查狀態：

```powershell
cd "$env:USERPROFILE\github\cve2action"
git status --short
```

只有沒有輸出時才繼續；有變更就先檢查並保存，不要 reset 或直接覆蓋。

```powershell
git pull --rebase origin main
```

下載本包到 Downloads，先解壓到獨立暫存目錄：

```powershell
$stage = Join-Path $env:TEMP ("cve2action-day03-" + [guid]::NewGuid().ToString("N"))
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\cve2action-day03-merged.zip" -DestinationPath $stage
$files = @(
  'docs/articles/day-03.md'
  'docs/articles/day-03-visual-captions.md'
  'docs/images/day-03-lock-analogy.png'
  'docs/images/day-03-three-rulers.png'
  'docs/images/day-03-three-rulers.svg'
  'docs/images/day-03-meeting-rulers.png'
  'docs/images/day-03-meeting-rulers.svg'
  'docs/images/day-03-severity-threat-risk.png'
  'docs/images/day-03-severity-threat-risk.svg'
  'docs/images/day-03-severity-threat-risk.mmd'
  'docs/research/day-03-concepts-and-boundaries.md'
  'docs/releases/day-03-publish-MANIFEST.md'
)
$existing = @($files | Where-Object { Test-Path -LiteralPath $_ })
$existing
```

上面只解壓到暫存目錄，尚未覆蓋儲存庫。若列出同名檔案，先比較並保留你在地端新增的內容；確認要採用本包版本後，才執行以下匯入。可先用 `git diff --no-index -- docs/articles/day-03.md (Join-Path $stage 'docs/articles/day-03.md')` 比較兩稿；有差異時退出碼 1 是正常的。

```powershell
foreach ($file in $files) {
  $parent = Split-Path -Parent $file
  New-Item -ItemType Directory -Path $parent -Force | Out-Null
  Copy-Item -LiteralPath (Join-Path $stage $file) -Destination $file -Force
}
git status --short
```

若任何指令報錯，先停止，不接著提交。完成文章調整後，在同一個 PowerShell 視窗：

```powershell
git add -- $files
git diff --cached --check
git diff --cached --stat
git diff --cached -- docs/articles/day-03.md
```

確認暫存區只有預期的 Day 3 內容，再提交、同步與推送；每一步成功才進行下一步：

```powershell
git commit -m "docs(day-03): merge three-ruler article and illustrations"
git pull --rebase origin main
git push origin main
git status
```

若 rebase 衝突，先處理，不執行 push，也不要 force push。完成後應與 `origin/main` 同步且工作目錄乾淨。

## 發布前檢查

- [ ] Day 2 線上版若有後續修訂，已比對本篇開場。
- [ ] 對話與案例保留虛構聲明，沒有可識別企業的資訊。
- [ ] 區分利用條件、威脅訊號與企業剩餘風險。
- [ ] 沒把管理連線當成必然成功入侵。
- [ ] 暫緩有條件，不暗示永久不修；例外／豁免另留治理章。
- [ ] 四張圖正常顯示，官方來源可點擊。
- [ ] 發布後補記實際網址；Day 4 接企業情境資料來源。
