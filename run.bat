@echo off
setlocal
if not exist run.exe (
  echo 未找到 run.exe，请先执行 build-release.ps1
  pause
  exit /b 1
)
run.exe -f config\example.yaml
pause
