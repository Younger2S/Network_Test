@echo off
chcp 65001 >nul
title ES弱口令检测工具 - 启动器
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [错误] 未检测到 Python，请先安装 Python 3 并勾选 "Add to PATH"。
    echo 安装后重新双击本文件即可。
    pause
    exit /b 1
)

echo 检查依赖中...
python -c "import flask, requests, openpyxl" >nul 2>nul
if errorlevel 1 (
    echo 缺少依赖，正在安装，请稍候...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [错误] 依赖安装失败，请检查网络后重试。
        pause
        exit /b 1
    )
)

REM 端口 5000 已被占用则视为服务已在运行
powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }" >nul 2>nul
if not errorlevel 1 (
    echo 服务已在运行（端口 5000），直接打开页面。
) else (
    echo 启动服务中...
    start "ES弱口令检测工具 - 服务" python app.py
)

echo 等待服务就绪，稍后自动打开页面...
start "" /min powershell -NoProfile -Command "$u='http://127.0.0.1:5000'; for($i=0;$i -lt 60;$i++){ try{ $c=New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1',5000); $c.Close(); Start-Process $u; exit } catch { Start-Sleep -Milliseconds 500 } }"

echo.
echo 浏览器将自动打开 http://127.0.0.1:5000
echo 如需停止服务，直接关闭 "ES弱口令检测工具 - 服务" 窗口即可。
pause
