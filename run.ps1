[CmdletBinding()]
param(
    # Default mode starts the service in the background. Use -Foreground to
    # keep Uvicorn attached to the current shell for troubleshooting.
    [switch]$Foreground
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "未找到 .venv，请先执行：python -m venv .venv；.venv\Scripts\python -m pip install -r requirements.txt"
}

$hostName = if ([string]::IsNullOrWhiteSpace($env:APP_HOST)) { "127.0.0.1" } else { $env:APP_HOST.Trim() }
$portNumber = 10717
if (-not [string]::IsNullOrWhiteSpace($env:APP_PORT)) {
    $parsedPort = 0
    if (-not [int]::TryParse($env:APP_PORT, [ref]$parsedPort) -or $parsedPort -lt 1 -or $parsedPort -gt 65535) {
        throw "APP_PORT 必须是 1 到 65535 的整数"
    }
    $portNumber = $parsedPort
}

$runtimeDir = Join-Path $PSScriptRoot "runtime"
New-Item -ItemType Directory -Path $runtimeDir -Force | Out-Null
$stdoutLog = Join-Path $runtimeDir "server.stdout.log"
$stderrLog = Join-Path $runtimeDir "server.stderr.log"
$pidFile = Join-Path $runtimeDir "server.pid"

function Get-ListeningProcess {
    $connections = @(Get-NetTCPConnection -LocalPort $portNumber -State Listen -ErrorAction SilentlyContinue)
    foreach ($connection in $connections) {
        $servicePid = [int]$connection.OwningProcess
        $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $servicePid" -ErrorAction SilentlyContinue
        if ($processInfo) {
            return $processInfo
        }
    }
    return $null
}

function Test-ProjectService($processInfo) {
    if (-not $processInfo) {
        return $false
    }
    $commandLine = [string]$processInfo.CommandLine
    # Do not terminate or reuse an unrelated process that happens to occupy
    # the configured port.
    return $commandLine -match '(?i)uvicorn(?:\.exe)?\s+app\.main:app'
}

# A named mutex prevents two nearly simultaneous launches from both passing
# the port check before either newly started process begins listening.
$mutex = New-Object System.Threading.Mutex($false, "Local\CodexAccountToolStartup")
$hasMutex = $false
try {
    $hasMutex = $mutex.WaitOne(0)
    if (-not $hasMutex) {
        Write-Host "启动脚本正在执行，请稍后再试。"
        exit 0
    }

    $existing = Get-ListeningProcess
    if ($existing) {
        if (Test-ProjectService $existing) {
            Set-Content -LiteralPath $pidFile -Value ([string]$existing.ProcessId) -Encoding ascii
            Write-Host "服务已在运行，本次不重复启动。"
            Write-Host ("地址：http://{0}:{1}    PID：{2}" -f $hostName, $portNumber, $existing.ProcessId)
            exit 0
        }
        throw ("端口 {0} 已被其他进程占用（PID {1}），未启动新服务。" -f $portNumber, $existing.ProcessId)
    }

    # The working directory is already the project root, so avoid passing the
    # path as an unquoted command-line argument (important when the project is
    # cloned into a directory whose name contains spaces).
    $arguments = @("-m", "uvicorn", "app.main:app", "--host", $hostName, "--port", [string]$portNumber)
    if ($Foreground) {
        & $python @arguments
        exit $LASTEXITCODE
    }

    $process = Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru
    $deadline = (Get-Date).AddSeconds(15)
    $listener = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 300
        $listener = Get-ListeningProcess
        if ($listener) {
            break
        }
        if ($process.HasExited) {
            break
        }
    }
    if (-not $listener) {
        $errorTail = if (Test-Path -LiteralPath $stderrLog) { (Get-Content -LiteralPath $stderrLog -Tail 8 -ErrorAction SilentlyContinue) -join " `n" } else { "" }
        if ($errorTail) {
            throw ("服务启动失败：{0}" -f $errorTail.Trim())
        }
        throw "服务启动失败，15 秒内未监听端口 $portNumber"
    }
    if (-not (Test-ProjectService $listener)) {
        throw ("端口 {0} 被其他进程占用，未启动新服务。" -f $portNumber)
    }
    Set-Content -LiteralPath $pidFile -Value ([string]$listener.ProcessId) -Encoding ascii
    Write-Host "服务启动成功。"
    Write-Host ("地址：http://{0}:{1}    PID：{2}" -f $hostName, $portNumber, $listener.ProcessId)
    Write-Host "可重复运行此脚本；服务已运行时不会重复启动。"
}
finally {
    if ($hasMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
