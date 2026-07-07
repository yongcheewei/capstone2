@echo off
setlocal
cd /d "%~dp0\.."

echo [run_pipeline.cmd] generating sample log if missing
python scripts\generate_sample_log.py --out data\processed\sample_auth.log || exit /b 1

echo [run_pipeline.cmd] running end-to-end pipeline
python scripts\run_pipeline.py || exit /b 1

echo [run_pipeline.cmd] running tests
python -m pytest -q || exit /b 1
