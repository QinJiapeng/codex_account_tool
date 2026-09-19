[CmdletBinding()]
param(
    # -Launch opens the single visible console on the first invocation and
    # sends later restart requests to that console. -Foreground runs the
    # console supervisor itself. Default mode keeps background compatibility.
    [switch]$Foreground,
    [switch]$Launch
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$restartEventName = "Local\CodexAccountToolRestart"
$supervisorMutexName = "Local\CodexAccountToolSupervisor"
$launchMutexName = "Local\CodexAccountToolConsoleLaunch"

function Open-RestartEvent {
    try {
        return [System.Threading.EventWaitHandle]::OpenExisting($restartEventName)
    }
    catch [System.Threading.WaitHandleCannotBeOpenedException] {
        return $null
    }
    catch [System.UnauthorizedAccessException] {
        return $null
    }
}

function Send-RestartSignal {
    param(
        [int]$TimeoutMilliseconds = 0
    )

    $deadline = (Get-Date).AddMilliseconds($TimeoutMilliseconds)
    do {
        $eventHandle = Open-RestartEvent
        if ($eventHandle) {
            try {
                $null = $eventHandle.Set()
                return $true
            }
            finally {
                $eventHandle.Dispose()
            }
        }
        if ($TimeoutMilliseconds -le 0) {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Wait-ForRestartEvent {
    param([int]$TimeoutMilliseconds = 10000)

    $deadline = (Get-Date).AddMilliseconds($TimeoutMilliseconds)
    do {
        $eventHandle = Open-RestartEvent
        if ($eventHandle) {
            $eventHandle.Dispose()
            return $true
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Send-RestartSignalWithRetry {
    param([int]$TimeoutMilliseconds = 10000)

    $deadline = (Get-Date).AddMilliseconds($TimeoutMilliseconds)
    do {
        if (Send-RestartSignal) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    return $false
}

if ($Launch) {
    if ($Foreground) {
        throw "Launch 和 Foreground 不能同时使用"
    }

    # Serialize the small gap between opening the console and the supervisor
    # publishing its restart event, so rapid double-clicks still open once.
    $launchMutex = New-Object System.Threading.Mutex($false, $launchMutexName)
    $hasLaunchMutex = $false
    try {
        try {
            $hasLaunchMutex = $launchMutex.WaitOne(10000)
        }
        catch [System.Threading.AbandonedMutexException] {
            $hasLaunchMutex = $true
        }
        if (-not $hasLaunchMutex) {
            throw "等待现有启动请求超时"
        }

        if (Send-RestartSignalWithRetry) {
            exit 0
        }

        $batchPath = Join-Path $PSScriptRoot "start.bat"
        $cmdPath = Join-Path $env:SystemRoot "System32\cmd.exe"
        $cmdArguments = '/d /c ""{0}""' -f $batchPath
        $consoleProcess = Start-Process -FilePath $cmdPath -ArgumentList $cmdArguments -WorkingDirectory $PSScriptRoot -WindowStyle Normal -PassThru

        $deadline = (Get-Date).AddSeconds(10)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 100
            if (Wait-ForRestartEvent) {
                exit 0
            }
            if ($consoleProcess.HasExited) {
                exit $consoleProcess.ExitCode
            }
        }
        throw "服务控制台未能在 10 秒内完成初始化"
    }
    finally {
        if ($hasLaunchMutex) {
            $launchMutex.ReleaseMutex()
        }
        $launchMutex.Dispose()
    }
}

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

function Stop-ProjectService($processInfo) {
    if (-not $processInfo) {
        return
    }
    $servicePid = [int]$processInfo.ProcessId
    Write-Host ("检测到已有服务（PID {0}），正在停止旧服务并重新启动。" -f $servicePid)
    Stop-Process -Id $servicePid -Force -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 200
        if (-not (Get-ListeningProcess)) {
            return
        }
    }
    throw ("旧服务（PID {0}）未能在 10 秒内退出，未启动新服务。" -f $servicePid)
}

function Start-ForegroundSupervisor {
    $supervisorMutex = New-Object System.Threading.Mutex($false, $supervisorMutexName)
    $hasSupervisorMutex = $false
    $restartEvent = $null
    $startedProcess = $null
    try {
        try {
            $hasSupervisorMutex = $supervisorMutex.WaitOne(0)
        }
        catch [System.Threading.AbandonedMutexException] {
            $hasSupervisorMutex = $true
        }
        if (-not $hasSupervisorMutex) {
            # The existing console may be between acquiring the mutex and
            # creating its event. Wait through that short initialization gap
            # instead of reporting a false startup failure.
            if (Send-RestartSignalWithRetry) {
                Write-Host "已通知原服务窗口重新启动。"
                return 0
            }
            throw "服务窗口正在初始化，请稍后再试"
        }

        $createdNew = $false
        $restartEvent = [System.Threading.EventWaitHandle]::new(
            $false,
            [System.Threading.EventResetMode]::AutoReset,
            $restartEventName,
            [ref]$createdNew
        )
        if (-not $createdNew) {
            throw "无法创建服务窗口重启事件"
        }

        Write-Host "此窗口负责运行 Codex Account Tool，请保持窗口开启。"
        Write-Host "以后再次运行桌面快捷方式，服务会在本窗口中重新启动。"

        while ($true) {
            $existing = Get-ListeningProcess
            if ($existing) {
                if (Test-ProjectService $existing) {
                    Stop-ProjectService $existing
                }
                else {
                    throw ("端口 {0} 已被其他进程占用（PID {1}），未启动新服务。" -f $portNumber, $existing.ProcessId)
                }
            }

            Write-Host "正在启动服务……"
            $startedProcess = Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $PSScriptRoot -NoNewWindow -PassThru
            $deadline = (Get-Date).AddSeconds(15)
            $listener = $null
            $restartPending = $false
            while ((Get-Date) -lt $deadline) {
                if ($restartEvent.WaitOne(0)) {
                    $restartPending = $true
                }
                Start-Sleep -Milliseconds 200
                $listener = Get-ListeningProcess
                if ($listener -or $startedProcess.HasExited) {
                    break
                }
            }
            if (-not $listener) {
                if ($startedProcess.HasExited) {
                    $processExitCode = $startedProcess.ExitCode
                    if ($processExitCode -eq 0) {
                        return 0
                    }
                    throw ("服务进程已退出，退出代码：{0}" -f $processExitCode)
                }
                throw "服务启动失败，15 秒内未监听端口 $portNumber"
            }
            if (-not (Test-ProjectService $listener)) {
                throw ("端口 {0} 被其他进程占用，未启动新服务。" -f $portNumber)
            }

            Set-Content -LiteralPath $pidFile -Value ([string]$listener.ProcessId) -Encoding ascii
            Write-Host ("服务已启动：http://{0}:{1}    PID：{2}" -f $hostName, $portNumber, $listener.ProcessId)

            if ($restartPending) {
                Write-Host "收到新的启动请求，正在本窗口中重新启动。"
                Stop-ProjectService $listener
                continue
            }

            $restartRequested = $false
            while (-not $startedProcess.HasExited) {
                if ($restartEvent.WaitOne(250)) {
                    $restartRequested = $true
                    break
                }
            }
            if (-not $restartRequested) {
                $processExitCode = $startedProcess.ExitCode
                if ($processExitCode -eq 0) {
                    return 0
                }
                throw ("服务进程已退出，退出代码：{0}" -f $processExitCode)
            }

            Write-Host "收到新的启动请求，正在本窗口中重新启动。"
            $listener = Get-ListeningProcess
            if ($listener -and (Test-ProjectService $listener)) {
                Stop-ProjectService $listener
            }
        }
    }
    finally {
        if ($startedProcess -and -not $startedProcess.HasExited) {
            Stop-Process -Id $startedProcess.Id -Force -ErrorAction SilentlyContinue
        }
        if ($restartEvent) {
            $restartEvent.Dispose()
        }
        if ($hasSupervisorMutex) {
            $supervisorMutex.ReleaseMutex()
        }
        $supervisorMutex.Dispose()
    }
}

# The working directory is already the project root, so avoid passing the
# path as an unquoted command-line argument (important when the project is
# cloned into a directory whose name contains spaces).
$arguments = @("-m", "uvicorn", "app.main:app", "--host", $hostName, "--port", [string]$portNumber, "--no-access-log")

if ($Foreground) {
    exit (Start-ForegroundSupervisor)
}

# Keep command-line launches compatible with the single-console behavior when
# the supervisor is already active.
if (Send-RestartSignalWithRetry) {
    Write-Host "已通知原服务窗口重新启动。"
    exit 0
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
            Stop-ProjectService $existing
        } else {
            throw ("端口 {0} 已被其他进程占用（PID {1}），未启动新服务。" -f $portNumber, $existing.ProcessId)
        }
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
    Write-Host "可重复运行此脚本；再次运行会先停止旧服务，再启动新服务。"
}
finally {
    if ($hasMutex) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
