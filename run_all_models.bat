@echo off
setlocal

:: Check if required arguments were provided
if "%~1"=="" (
    echo Usage: run_all_models.bat ^<snapshot_path^> ^<threshold^>
    echo Example: run_all_models.bat .\data\snapshots\snapshot_20260408_113157\20260408 0.05
    exit /b 1
)

if "%~2"=="" (
    echo Usage: run_all_models.bat ^<snapshot_path^> ^<threshold^>
    echo Example: run_all_models.bat .\data\snapshots\snapshot_20260408_113157\20260408 0.05
    exit /b 1
)

set SNAPSHOT_PATH=%~1
set THRESHOLD=%~2

echo Using snapshot path: %SNAPSHOT_PATH%
echo Using threshold: %THRESHOLD%
echo Starting model creation pipeline...
echo.

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources chatgpt --direction incoming --output .\packet-analysis\chatgpt\%THRESHOLD%\incoming_models --model-weights .\packet-analysis\chatgpt\%THRESHOLD%\incoming_pkl
if errorlevel 1 goto :error

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources gemini --direction incoming --output .\packet-analysis\gemini\%THRESHOLD%\incoming_models --model-weights .\packet-analysis\gemini\%THRESHOLD%\incoming_pkl
if errorlevel 1 goto :error

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources claude --direction incoming --output .\packet-analysis\claude\%THRESHOLD%\incoming_models --model-weights .\packet-analysis\claude\%THRESHOLD%\incoming_pkl
if errorlevel 1 goto :error

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources * --direction incoming --output .\packet-analysis\3providers\%THRESHOLD%\incoming_models --model-weights .\packet-analysis\3providers\%THRESHOLD%\incoming_pkl
if errorlevel 1 goto :error

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources chatgpt --direction outgoing --output .\packet-analysis\chatgpt\%THRESHOLD%\outgoing_models --model-weights .\packet-analysis\chatgpt\%THRESHOLD%\outgoing_pkl
if errorlevel 1 goto :error

@REM python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources gemini --direction outgoing --output .\packet-analysis\gemini\%THRESHOLD%\outgoing_models --model-weights .\packet-analysis\gemini\%THRESHOLD%\outgoing_pkl
@REM if errorlevel 1 goto :error

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources claude --direction outgoing --output .\packet-analysis\claude\%THRESHOLD%\outgoing_models --model-weights .\packet-analysis\claude\%THRESHOLD%\outgoing_pkl
if errorlevel 1 goto :error

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources * --direction outgoing --output .\packet-analysis\3providers\%THRESHOLD%\outgoing_models --model-weights .\packet-analysis\3providers\%THRESHOLD%\outgoing_pkl
if errorlevel 1 goto :error

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources chatgpt --direction both --output .\packet-analysis\chatgpt\%THRESHOLD%\bidirectional_models --model-weights .\packet-analysis\chatgpt\%THRESHOLD%\bidirectional_pkl
if errorlevel 1 goto :error

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources gemini --direction both --output .\packet-analysis\gemini\%THRESHOLD%\bidirectional_models --model-weights .\packet-analysis\gemini\%THRESHOLD%\bidirectional_pkl
if errorlevel 1 goto :error

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources claude --direction both --output .\packet-analysis\claude\%THRESHOLD%\bidirectional_models --model-weights .\packet-analysis\claude\%THRESHOLD%\bidirectional_pkl
if errorlevel 1 goto :error

python .\packet-analysis\modular_model_creator.py %SNAPSHOT_PATH% --llm-sources * --direction both --output .\packet-analysis\3providers\%THRESHOLD%\bidirectional_models --model-weights .\packet-analysis\3providers\%THRESHOLD%\bidirectional_pkl
if errorlevel 1 goto :error

echo.
echo All scripts completed successfully.
goto :end

:error
echo.
echo A command failed. Stopping the script.
exit /b 1

:end
endlocal
pause