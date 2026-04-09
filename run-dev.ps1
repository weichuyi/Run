Param(
  [string]$Config = "config\example.yaml"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  Write-Host "未检测到 Go。请先安装 Go 1.21+ 并重开终端。" -ForegroundColor Red
  exit 1
}

Write-Host "拉取依赖..."
go mod tidy
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "启动 Run..."
go run . -f $Config
exit $LASTEXITCODE
