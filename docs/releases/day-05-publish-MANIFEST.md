# Day 5 Publish Manifest

- Date: 2026-09-19
- Article: `docs/articles/day-05.md`
- Theme: Less Is More — The Minimum Context for a Better Decision
- Next day: Decision Engine v0.1 Vertical Slice

## Images

1. `docs/images/day-05-cover.png` — 封面：Scanner Result + Minimum Context → Decision Engine → Priority + Explanation
2. `docs/images/day-05-minimum-context.png` — Minimum Context v0.1
3. `docs/images/day-05-effective-exposure.png` — Reachability × Control Effectiveness；UNKNOWN 不降分
4. `docs/images/day-05-priority-model.png` — 三把尺 → 正規化 → 加權 → Priority
5. `docs/images/day-05-case-ab.png` — Case A / B Before vs After

## Architecture / Decision records

- `docs/decisions/ADR-day-05-decision-engine-v01.md`
- `CVE2Action-30天總體施工藍圖.md` updated:
  - Day 5 scope fixed
  - Day 6 changed to Decision Engine v0.1 vertical slice
  - Day 7–18 sequencing adjusted
  - v0.1 scoring baseline documented

## Day 6 fixed I/O

Inputs:
- `scanner.csv`
- `asset_context.csv`
- `risk_rules.yaml`

Output:
- `ranked_result.csv`

Required behavior:
- CVSS severity is never overwritten.
- Contextual Priority is calculated separately.
- Missing required context → `NEEDS_CONTEXT`.
- UNKNOWN control effectiveness must not lower risk.

## Suggested commit

```text
docs(day-05): define minimum context and decision engine v0.1
```

## Local packaging workflow

Extract this ZIP at repository root, then:

```bash
git add -A
git diff --cached --check
git diff --cached --stat
git commit -m "docs(day-05): define minimum context and decision engine v0.1"
git pull --rebase origin main
git push origin main
```
