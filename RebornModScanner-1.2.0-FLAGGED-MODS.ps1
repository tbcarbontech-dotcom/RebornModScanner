# Reborn Mod + Injection Scanner
# Defensive/offline scanner for Minecraft Java on Windows.
# Does NOT upload, delete, kill, inject, or modify files/processes.
# It reports indicators only. "Low flags" is NOT a guarantee that a file/process is safe.

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$ScriptVersion = "1.2.0"
$MinecraftDir = Join-Path $env:APPDATA ".minecraft"

function Get-MinecraftModFolders {
    $found = New-Object System.Collections.Generic.List[string]

    function Add-ModFolder([string]$Path) {
        if ([string]::IsNullOrWhiteSpace($Path)) { return }
        try {
            $full = [IO.Path]::GetFullPath($Path)
        } catch {
            return
        }
        if ((Test-Path -LiteralPath $full -PathType Container) -and -not $found.Contains($full)) {
            $found.Add($full)
        }
    }

    # 1) Best source: inspect currently running Java/Minecraft command lines.
    # Most launchers pass --gameDir <folder>.
    try {
        $javaProcesses = Get-CimInstance Win32_Process | Where-Object {
            $_.Name -match '^(java|javaw)\.exe$'
        }

        foreach ($proc in $javaProcesses) {
            $cmd = [string]$proc.CommandLine
            if ([string]::IsNullOrWhiteSpace($cmd)) { continue }

            $patterns = @(
                '(?i)--gameDir\s+"([^"]+)"',
                "(?i)--gameDir\s+'([^']+)'",
                '(?i)--gameDir\s+([^\s]+)',
                '(?i)--game-dir\s+"([^"]+)"',
                "(?i)--game-dir\s+'([^']+)'",
                '(?i)--game-dir\s+([^\s]+)'
            )

            foreach ($pattern in $patterns) {
                $m = [regex]::Match($cmd, $pattern)
                if ($m.Success) {
                    Add-ModFolder (Join-Path $m.Groups[1].Value "mods")
                    break
                }
            }
        }
    } catch {}

    # 2) Official / normal launcher.
    Add-ModFolder (Join-Path $env:APPDATA ".minecraft\mods")

    # 3) Modrinth App: detect every installed profile automatically.
    $modrinthProfiles = Join-Path $env:APPDATA "ModrinthApp\profiles"
    if (Test-Path -LiteralPath $modrinthProfiles) {
        Get-ChildItem -LiteralPath $modrinthProfiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            Add-ModFolder (Join-Path $_.FullName "mods")
        }
    }

    # 4) Prism Launcher common locations.
    $prismRoots = @(
        (Join-Path $env:APPDATA "PrismLauncher\instances"),
        (Join-Path $env:LOCALAPPDATA "Programs\PrismLauncher\instances")
    )
    foreach ($root in $prismRoots) {
        if (Test-Path -LiteralPath $root) {
            Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                Add-ModFolder (Join-Path $_.FullName ".minecraft\mods")
                Add-ModFolder (Join-Path $_.FullName "minecraft\mods")
            }
        }
    }

    # 5) CurseForge common locations.
    $curseRoots = @(
        (Join-Path $env:USERPROFILE "curseforge\minecraft\Instances"),
        (Join-Path $env:APPDATA "CurseForge\minecraft\Instances")
    )
    foreach ($root in $curseRoots) {
        if (Test-Path -LiteralPath $root) {
            Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                Add-ModFolder (Join-Path $_.FullName "mods")
            }
        }
    }

    # 6) ATLauncher common location.
    $atRoot = Join-Path $env:APPDATA "ATLauncher\instances"
    if (Test-Path -LiteralPath $atRoot) {
        Get-ChildItem -LiteralPath $atRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            Add-ModFolder (Join-Path $_.FullName "mods")
        }
    }

    return @($found)
}

$ModsDirs = @(Get-MinecraftModFolders)

$ReportDir = Join-Path $env:USERPROFILE "Desktop"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$ReportPath = Join-Path $ReportDir "RebornScanner_$Timestamp.txt"

# --- Indicators ---
$CheatTerms = @(
    "prestige","liquidbounce","meteor","wurst","impact","aristois","vape","raven",
    "killaura","kill_aura","aura","aimassist","aim_assist","triggerbot","reach",
    "velocity","antikb","anti_knockback","autototem","auto_totem","crystalaura",
    "crystal_aura","anchor_aura","anchoraura","freecam","xray","esp","tracers",
    "scaffold","packetfly","packet_fly","phase","blink","clickgui","click_gui",
    "autoclicker","auto_clicker","nametags","chams","nofall","speedhack",
    "inventorymove","inv_move","fastplace","fastbreak","baritone"
)

$InjectionTerms = @(
    "javaagent","agentlib","agentpath","instrumentation","attachprovider",
    "virtualmachine.attach","loadlibrary","loadlibrarya","loadlibraryw",
    "getprocaddress","openprocess","writeprocessmemory","virtualallocex",
    "createremotethread","ntcreatethreadex","setwindowshookex","jvmti",
    "jni_onload","dllinject","injector","manualmap","manual_map"
)

$SuspiciousExtensions = @(".dll",".exe",".bat",".cmd",".ps1",".vbs",".js",".scr",".sys")
$TextExtensions = @(".json",".toml",".cfg",".conf",".properties",".txt",".yml",".yaml",".xml",".mf",".mixins")
$KnownMetadataNames = @(
    "fabric.mod.json","quilt.mod.json","mods.toml","neoforge.mods.toml",
    "mcmod.info","manifest.mf"
)

$Findings = New-Object System.Collections.Generic.List[object]
$JarRows = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [string]$Category,
        [string]$Target,
        [string]$Detail,
        [int]$Score
    )
    $Findings.Add([PSCustomObject]@{
        Category = $Category
        Target   = $Target
        Detail   = $Detail
        Score    = $Score
    })
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkGray
}

function Get-RiskLabel {
    param([int]$Score)
    if ($Score -ge 14) { return "HIGH REVIEW" }
    elseif ($Score -ge 6) { return "REVIEW" }
    else { return "LOW FLAGS" }
}

function Find-Terms {
    param(
        [string]$Text,
        [string[]]$Terms
    )
    $matches = New-Object System.Collections.Generic.HashSet[string]
    $lower = $Text.ToLowerInvariant()
    foreach ($term in $Terms) {
        if ($lower.Contains($term.ToLowerInvariant())) {
            [void]$matches.Add($term)
        }
    }
    return @($matches)
}

function Read-EntryBytes {
    param($Entry, [int]$MaxBytes = 4194304)
    try {
        if ($Entry.Length -gt $MaxBytes) { return $null }
        $stream = $Entry.Open()
        try {
            $ms = New-Object System.IO.MemoryStream
            $stream.CopyTo($ms)
            return $ms.ToArray()
        } finally {
            if ($stream) { $stream.Dispose() }
        }
    } catch {
        return $null
    }
}

function Scan-Jar {
    param([System.IO.FileInfo]$File)

    $score = 0
    $details = New-Object System.Collections.Generic.List[string]
    $sha = "ERROR"

    try {
        $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $File.FullName).Hash
    } catch {}

    $fileNameTerms = Find-Terms -Text $File.Name -Terms $CheatTerms
    if ($fileNameTerms.Count -gt 0) {
        $score += 10
        $details.Add("Filename matched terms: " + ($fileNameTerms -join ", "))
        Add-Finding "JAR filename" $File.FullName ("Matched: " + ($fileNameTerms -join ", ")) 10
    }

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($File.FullName)
        try {
            $entryNames = @($zip.Entries | ForEach-Object { $_.FullName })
            $joinedNames = ($entryNames -join "`n")

            $nameCheatTerms = Find-Terms -Text $joinedNames -Terms $CheatTerms
            if ($nameCheatTerms.Count -gt 0) {
                $score += [Math]::Min(12, 3 + $nameCheatTerms.Count)
                $details.Add("Archive paths matched: " + ($nameCheatTerms -join ", "))
                Add-Finding "JAR paths" $File.FullName ("Matched: " + ($nameCheatTerms -join ", ")) ([Math]::Min(12, 3 + $nameCheatTerms.Count))
            }

            $nativeEntries = @($zip.Entries | Where-Object {
                $ext = [IO.Path]::GetExtension($_.FullName).ToLowerInvariant()
                $SuspiciousExtensions -contains $ext
            })

            if ($nativeEntries.Count -gt 0) {
                $score += [Math]::Min(10, 3 + $nativeEntries.Count)
                $sample = ($nativeEntries | Select-Object -First 8 | ForEach-Object { $_.FullName }) -join ", "
                $details.Add("Bundled executable/native files: $sample")
                Add-Finding "Bundled native/executable" $File.FullName $sample ([Math]::Min(10, 3 + $nativeEntries.Count))
            }

            $metadataFound = @()
            foreach ($entry in $zip.Entries) {
                $leaf = [IO.Path]::GetFileName($entry.FullName).ToLowerInvariant()
                if ($KnownMetadataNames -contains $leaf) {
                    $metadataFound += $entry.FullName
                }
            }
            if ($metadataFound.Count -eq 0) {
                $score += 1
                $details.Add("No common Fabric/Forge/NeoForge/Quilt metadata file found")
            }

            # Scan decompressed text-ish entries and class constant strings.
            # Entry size is capped to keep the scan responsive.
            $classScanned = 0
            $textScanned = 0
            $foundCheat = New-Object System.Collections.Generic.HashSet[string]
            $foundInject = New-Object System.Collections.Generic.HashSet[string]

            foreach ($entry in $zip.Entries) {
                if ($entry.Length -le 0) { continue }
                $ext = [IO.Path]::GetExtension($entry.FullName).ToLowerInvariant()

                $shouldScan = $false
                if ($ext -eq ".class" -and $classScanned -lt 3500) {
                    $shouldScan = $true
                    $classScanned++
                } elseif (($TextExtensions -contains $ext) -and $textScanned -lt 1000) {
                    $shouldScan = $true
                    $textScanned++
                }

                if (-not $shouldScan) { continue }

                $bytes = Read-EntryBytes -Entry $entry
                if ($null -eq $bytes) { continue }

                $ascii = [Text.Encoding]::ASCII.GetString($bytes)
                foreach ($m in (Find-Terms -Text $ascii -Terms $CheatTerms)) {
                    [void]$foundCheat.Add($m)
                }
                foreach ($m in (Find-Terms -Text $ascii -Terms $InjectionTerms)) {
                    [void]$foundInject.Add($m)
                }
            }

            if ($foundCheat.Count -gt 0) {
                $pts = [Math]::Min(15, 4 + ($foundCheat.Count * 2))
                $score += $pts
                $details.Add("Decompressed content matched cheat terms: " + (@($foundCheat) -join ", "))
                Add-Finding "JAR content" $File.FullName ("Matched: " + (@($foundCheat) -join ", ")) $pts
            }

            if ($foundInject.Count -gt 0) {
                $pts = [Math]::Min(12, 3 + ($foundInject.Count * 2))
                $score += $pts
                $details.Add("Injection/native API terms: " + (@($foundInject) -join ", "))
                Add-Finding "Injection strings" $File.FullName ("Matched: " + (@($foundInject) -join ", ")) $pts
            }

            # Very rough obfuscation indicator: many tiny/random-looking class paths.
            $classes = @($zip.Entries | Where-Object { $_.FullName.ToLowerInvariant().EndsWith(".class") })
            if ($classes.Count -gt 80) {
                $shortNames = 0
                $checked = 0
                foreach ($c in ($classes | Select-Object -First 1000)) {
                    $base = [IO.Path]::GetFileNameWithoutExtension($c.FullName)
                    if ($base.Length -le 2 -and $base -match '^[a-zA-Z0-9_$]+$') { $shortNames++ }
                    $checked++
                }
                if ($checked -gt 0 -and ($shortNames / $checked) -gt 0.35) {
                    $score += 3
                    $details.Add("Possible heavy obfuscation pattern")
                    Add-Finding "Obfuscation" $File.FullName "Large proportion of very short class names" 3
                }
            }
        } finally {
            if ($zip) { $zip.Dispose() }
        }
    } catch {
        $score += 2
        $details.Add("Could not fully inspect JAR as ZIP: $($_.Exception.Message)")
        Add-Finding "Unreadable JAR" $File.FullName $_.Exception.Message 2
    }

    $JarRows.Add([PSCustomObject]@{
        File  = $File.Name
        SizeMB = [Math]::Round($File.Length / 1MB, 2)
        SHA256 = $sha
        Score = $score
        Result = Get-RiskLabel $score
        Details = if ($details.Count) { $details -join " | " } else { "No obvious indicators found" }
    })
}

function Scan-JavaProcesses {
    Write-Section "LIVE JAVA / MINECRAFT PROCESS CHECK"

    $javaProcs = Get-CimInstance Win32_Process | Where-Object {
        $_.Name -match '^(java|javaw)\.exe$'
    }

    if (-not $javaProcs) {
        Write-Host "No running Java process found. Live injection checks are limited." -ForegroundColor Yellow
        return
    }

    foreach ($jp in $javaProcs) {
        Write-Host ("PID {0}  {1}" -f $jp.ProcessId, $jp.Name) -ForegroundColor White
        $cmd = [string]$jp.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmd)) { $cmd = "(command line unavailable)" }

        $agentMatches = @("-javaagent","-agentlib","-agentpath","-Xbootclasspath") | Where-Object {
            $cmd.ToLowerInvariant().Contains($_.ToLowerInvariant())
        }
        if ($agentMatches.Count -gt 0) {
            Add-Finding "Java launch args" ("PID " + $jp.ProcessId) ("Agent/boot args: " + ($agentMatches -join ", ")) 8
            Write-Host ("  [REVIEW] Java agent/boot argument: " + ($agentMatches -join ", ")) -ForegroundColor Red
        }

        $cmdCheats = Find-Terms -Text $cmd -Terms $CheatTerms
        if ($cmdCheats.Count -gt 0) {
            Add-Finding "Java command line" ("PID " + $jp.ProcessId) ("Matched: " + ($cmdCheats -join ", ")) 8
            Write-Host ("  [REVIEW] Command line term: " + ($cmdCheats -join ", ")) -ForegroundColor Red
        }

        try {
            $proc = Get-Process -Id $jp.ProcessId -ErrorAction Stop
            $mods = @($proc.Modules)
            foreach ($m in $mods) {
                $path = [string]$m.FileName
                if ([string]::IsNullOrWhiteSpace($path)) { continue }

                $lowerPath = $path.ToLowerInvariant()
                $userWritable = (
                    $lowerPath.Contains("\appdata\") -or
                    $lowerPath.Contains("\temp\") -or
                    $lowerPath.Contains("\downloads\") -or
                    $lowerPath.Contains("\desktop\")
                )

                $dllTerms = Find-Terms -Text $path -Terms ($CheatTerms + $InjectionTerms)
                if ($dllTerms.Count -gt 0) {
                    Add-Finding "Loaded Java module" ("PID " + $jp.ProcessId) ("$path | matched: " + ($dllTerms -join ", ")) 12
                    Write-Host ("  [HIGH REVIEW] Loaded module matched indicator: " + $path) -ForegroundColor Red
                } elseif ($userWritable -and $path.ToLowerInvariant().EndsWith(".dll")) {
                    Add-Finding "Loaded Java module" ("PID " + $jp.ProcessId) ("DLL loaded from user-writable location: " + $path) 4
                    Write-Host ("  [REVIEW] DLL from user-writable folder: " + $path) -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "  Could not enumerate loaded modules (Windows may block access)." -ForegroundColor DarkYellow
        }
    }
}

function Scan-SuspiciousProcesses {
    Write-Section "RUNNING PROCESS NAME / PATH CHECK"

    $procs = Get-CimInstance Win32_Process
    foreach ($p in $procs) {
        $combined = (($p.Name + " " + $p.ExecutablePath + " " + $p.CommandLine))
        $matches = Find-Terms -Text $combined -Terms ($CheatTerms + @("injector","loader"))
        if ($matches.Count -gt 0) {
            Add-Finding "Running process" ($p.Name + " PID " + $p.ProcessId) ("Matched: " + ($matches -join ", ") + " | " + $p.ExecutablePath) 7
            Write-Host ("[REVIEW] {0} (PID {1}) -> {2}" -f $p.Name, $p.ProcessId, ($matches -join ", ")) -ForegroundColor Yellow
        }
    }
}

function Scan-RecentFiles {
    Write-Section "RECENT INJECTOR-LIKE FILE CHECK"

    $roots = @(
        $env:TEMP,
        $env:LOCALAPPDATA,
        $env:APPDATA,
        (Join-Path $env:USERPROFILE "Downloads")
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    $cutoff = (Get-Date).AddDays(-7)
    $checked = 0
    foreach ($root in $roots) {
        Write-Host ("Checking recent executable/native files under: " + $root) -ForegroundColor DarkGray
        try {
            Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.LastWriteTime -ge $cutoff -and
                    ($SuspiciousExtensions -contains $_.Extension.ToLowerInvariant())
                } |
                Select-Object -First 2500 |
                ForEach-Object {
                    $checked++
                    $matches = Find-Terms -Text ($_.Name + " " + $_.FullName) -Terms ($CheatTerms + @("injector","manualmap","loader"))
                    if ($matches.Count -gt 0) {
                        Add-Finding "Recent file" $_.FullName ("Matched: " + ($matches -join ", ")) 6
                    }
                }
        } catch {}
    }
    Write-Host ("Recent executable/native files considered: " + $checked) -ForegroundColor DarkGray
}

function Scan-JavaAgentsAndStartup {
    Write-Section "JAVA ENVIRONMENT / STARTUP CHECK"

    $envVars = @("_JAVA_OPTIONS","JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS")
    foreach ($name in $envVars) {
        $val = [Environment]::GetEnvironmentVariable($name, "Process")
        if (-not $val) { $val = [Environment]::GetEnvironmentVariable($name, "User") }
        if (-not $val) { $val = [Environment]::GetEnvironmentVariable($name, "Machine") }
        if ($val) {
            Write-Host ("{0} = {1}" -f $name, $val) -ForegroundColor Yellow
            if ($val -match '(?i)-javaagent|-agentpath|-agentlib|-Xbootclasspath') {
                Add-Finding "Java environment" $name ("Agent/boot option present: " + $val) 9
            }
        }
    }

    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($rk in $runKeys) {
        if (Test-Path $rk) {
            $props = Get-ItemProperty $rk
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -like "PS*") { continue }
                $text = [string]$prop.Value
                $matches = Find-Terms -Text ($prop.Name + " " + $text) -Terms ($CheatTerms + @("injector","loader"))
                if ($matches.Count -gt 0) {
                    Add-Finding "Startup entry" $prop.Name ("Matched: " + ($matches -join ", ") + " | " + $text) 7
                }
            }
        }
    }
}

function Export-Report {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("REBORN MOD + INJECTION SCANNER")
    $lines.Add("Version: $ScriptVersion")
    $lines.Add("Time: " + (Get-Date))
    $lines.Add("Computer: " + $env:COMPUTERNAME)
    $lines.Add("")
    $lines.Add("IMPORTANT: This is an indicator scanner, not proof of guilt or a 100% safety guarantee.")
    $lines.Add("It performs no uploads, deletions, process killing, or injection.")
    $lines.Add("")
    $lines.Add("=== DETECTED MOD FOLDERS ===")
    if ($ModsDirs.Count -eq 0) {
        $lines.Add("None automatically detected.")
    } else {
        foreach ($d in $ModsDirs) { $lines.Add($d) }
    }
    $lines.Add("")
    $lines.Add("=== JAR RESULTS ===")

    foreach ($r in ($JarRows | Sort-Object Score -Descending)) {
        $lines.Add(("[{0}] {1}" -f $r.Result, $r.File))
        $lines.Add(("  Score: {0} | Size: {1} MB" -f $r.Score, $r.SizeMB))
        $lines.Add(("  SHA256: {0}" -f $r.SHA256))
        $lines.Add(("  Details: {0}" -f $r.Details))
        $lines.Add("")
    }

    $lines.Add("=== FLAGGED MODS ===")
    $flaggedForReport = @($JarRows | Where-Object { $_.Result -eq "HIGH REVIEW" -or $_.Result -eq "REVIEW" } | Sort-Object Score -Descending)
    if ($flaggedForReport.Count -eq 0) {
        $lines.Add("No mods flagged by the current rules.")
    } else {
        foreach ($fm in $flaggedForReport) {
            $lines.Add(("[{0}] {1} | score {2}" -f $fm.Result, $fm.File, $fm.Score))
            $lines.Add(("  " + $fm.Details))
        }
    }
    $lines.Add("")
    $lines.Add("=== ALL FINDINGS ===")
    if ($Findings.Count -eq 0) {
        $lines.Add("No obvious indicators were found by these checks.")
    } else {
        foreach ($f in ($Findings | Sort-Object Score -Descending)) {
            $lines.Add(("[{0} pts] {1} | {2}" -f $f.Score, $f.Category, $f.Target))
            $lines.Add(("  " + $f.Detail))
        }
    }

    $lines.Add("")
    $lines.Add("=== LIMITATIONS ===")
    $lines.Add("- A clean report does NOT prove a mod/client is safe.")
    $lines.Add("- Kernel/driver-level or stealth injection may evade ordinary PowerShell checks.")
    $lines.Add("- Keywords can create false positives; review context before deciding.")
    $lines.Add("- Legitimate mods may use Mixins, JNI, native libraries, or Java agents.")

    $lines | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

Clear-Host
Write-Host "REBORN MOD + INJECTION SCANNER" -ForegroundColor Cyan
Write-Host "Version $ScriptVersion" -ForegroundColor DarkGray
Write-Host "Offline defensive scan - nothing is uploaded or deleted." -ForegroundColor Gray
Write-Host "Launcher/profile folders are detected automatically." -ForegroundColor Gray

Write-Section "MINECRAFT MOD JAR SCAN"

if ($ModsDirs.Count -eq 0) {
    Write-Host "No Minecraft mods folders were found automatically." -ForegroundColor Yellow
    Write-Host "Start Minecraft first, then run the scanner again for the best detection." -ForegroundColor Yellow
} else {
    Write-Host "Detected mods folder(s):" -ForegroundColor White
    foreach ($dir in $ModsDirs) {
        Write-Host ("  " + $dir) -ForegroundColor Cyan
    }

    $allJars = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $seenJarPaths = New-Object System.Collections.Generic.HashSet[string]

    foreach ($dir in $ModsDirs) {
        try {
            Get-ChildItem -LiteralPath $dir -Filter "*.jar" -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                if ($seenJarPaths.Add($_.FullName)) {
                    $allJars.Add($_)
                }
            }
        } catch {}
    }

    Write-Host ("Found {0} unique JAR(s) across detected launcher/profile folders." -f $allJars.Count) -ForegroundColor White

    $n = 0
    foreach ($jar in $allJars) {
        $n++
        Write-Host ("[{0}/{1}] {2}" -f $n, $allJars.Count, $jar.FullName) -ForegroundColor DarkGray
        Scan-Jar $jar
    }

    Write-Host ""
    foreach ($row in ($JarRows | Sort-Object Score -Descending)) {
        $color = if ($row.Result -eq "HIGH REVIEW") { "Red" } elseif ($row.Result -eq "REVIEW") { "Yellow" } else { "Green" }
        Write-Host ("[{0}] {1}  (score {2})" -f $row.Result, $row.File, $row.Score) -ForegroundColor $color
    }
}

Scan-JavaProcesses
Scan-SuspiciousProcesses
Scan-RecentFiles
Scan-JavaAgentsAndStartup
Export-Report

Write-Section "FINISHED"

# Big final flagged-mod summary
$FlaggedMods = @($JarRows | Where-Object { $_.Result -eq "HIGH REVIEW" -or $_.Result -eq "REVIEW" } | Sort-Object Score -Descending)

Write-Host ""
Write-Host ("#" * 78) -ForegroundColor Red
Write-Host "##############################  FLAGGED MODS  ###############################" -ForegroundColor Red
Write-Host ("#" * 78) -ForegroundColor Red
Write-Host ""

if ($FlaggedMods.Count -eq 0) {
    Write-Host "NO MODS FLAGGED BY THE CURRENT RULES." -ForegroundColor Green
} else {
    foreach ($mod in $FlaggedMods) {
        if ($mod.Result -eq "HIGH REVIEW") {
            Write-Host ("[HIGH FLAG] {0}  | score {1}" -f $mod.File, $mod.Score) -ForegroundColor Red
        } else {
            Write-Host ("[FLAGGED]   {0}  | score {1}" -f $mod.File, $mod.Score) -ForegroundColor DarkYellow
        }

        if ($mod.Details) {
            Write-Host ("           " + $mod.Details) -ForegroundColor Gray
        }
    }
}

Write-Host ""
Write-Host ("#" * 78) -ForegroundColor Red
Write-Host ("TOTAL FLAGGED MODS: " + $FlaggedMods.Count) -ForegroundColor Red
Write-Host ("#" * 78) -ForegroundColor Red
Write-Host ""

Write-Host ("Report saved to: " + $ReportPath) -ForegroundColor Green
Write-Host ""
Write-Host "LOW FLAGS does not mean guaranteed safe. Review HIGH REVIEW findings manually." -ForegroundColor Yellow
Write-Host ""
Read-Host "Press Enter to close"
