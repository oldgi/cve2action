# CVE2Action：一鍵重現（藍圖 §12、§16 Day 30 發表門檻）
#
#   docker build -t cve2action .
#   docker run --rm -p 8501:8501 cve2action                         # 儀表板 http://localhost:8501
#   docker run --rm cve2action uv run --no-sync pytest -q           # 全部測試
#   docker run --rm cve2action uv run --no-sync python scripts/scenario_report.py   # 四情境報告
#
# 全部離線：NVD／EPSS／KEV 是 repo 裡的固定快照，建置之後不需要網路。
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.17 /uv /uvx /bin/

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONIOENCODING=utf-8

# 先裝相依（uv.lock 鎖版本），程式碼改動時這一層可以重用
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --extra dashboard --no-install-project

COPY . .
RUN uv sync --frozen --extra dashboard

EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')"

CMD ["uv", "run", "--no-sync", "streamlit", "run", "app/dashboard.py", \
     "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
