@echo off
title PhishGuard AI — Launcher
color 0A

echo.
echo  =========================================================
echo    PhishGuard AI — Phishing URL Detector
echo  =========================================================
echo.

:: Step 1: Install dependencies
echo  [1/3] Installing Python dependencies...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo  ERROR: pip install failed. Please check your Python installation.
    pause
    exit /b 1
)
echo       Done.

:: Step 2: Train model if not already trained
echo.
echo  [2/3] Checking for trained model...
if not exist "models\ensemble_model.joblib" (
    echo       No model found. Starting training pipeline...
    echo       This may take a few minutes on first run.
    echo.
    python train_model.py
    if errorlevel 1 (
        echo  ERROR: Training failed. Check output above.
        pause
        exit /b 1
    )
) else (
    echo       Model found. Skipping training.
)

:: Step 3: Launch Flask server
echo.
echo  [3/3] Launching web server...
echo.
echo  =========================================================
echo    Open your browser at:  http://localhost:5000
echo    Press Ctrl+C to stop the server
echo  =========================================================
echo.
start "" http://localhost:5000
python app.py

pause
