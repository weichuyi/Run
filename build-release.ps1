Param(
  [string]$Out = "run.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  Write-Host "未检测到 Go。请先安装 Go 1.21+ 并重开终端。" -ForegroundColor Red
  exit 1
}

Write-Host "构建可执行文件..."
go mod tidy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

go build -o $Out .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "构建完成: $Out"
