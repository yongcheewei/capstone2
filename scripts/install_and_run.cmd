@echo off
REM One-shot, no-extras setup + launch for the Streamlit dashboard (Windows).
REM
REM Usage (from an elevated PowerShell or cmd):
REM     scripts\install_and_run.cmd
REM
REM What it does
REM ------------
REM 1. Creates a project-local virtual environment in .venv (skipped if
REM    it already exists).
REM 2. Installs dependencies from requirements.txt.
REM 3. Launches the Streamlit demo dashboard on port 8501.
REM
REM The release zip ships with a sample data\processed\sample_auth.log
REM and a pre-trained model at src\models\artifacts\latest.joblib so
REM the dashboard works immediately on first run.
setlocal

cd /d "%~dp0\.."

set PY=python
where py >nul 2>&1
if %errorlevel%==0 set PY=py

if not exist ".venv" (
    echo [install_and_run.cmd] creating virtual environment .venv
    %PY% -m venv .venv
) else (
    echo [install_and_run.cmd] .venv already exists, reusing
)

call ".venv\Scripts\activate.bat"

echo [install_and_run.cmd] upgrading pip and installing requirements
python -m pip install --quiet --upgrade pip
if errorlevel 1 goto :err
python -m pip install --quiet -r requirements.txt
if errorlevel 1 goto :err

echo.
echo [install_and_run.cmd] launching Streamlit dashboard on port 8501
echo [install_and_run.cmd] (Ctrl-C to stop)
echo.

python -m streamlit run dashboard\app.py --server.port 8501 --server.address 0.0.0.0
goto :eof

:err
echo [install_and_run.cmd] failed. See messages above.
exit /b 1
