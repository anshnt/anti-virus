"""Read Windows security evidence and invoke only trusted Defender commands."""
import base64
import json
import os
import re
import subprocess
from pathlib import Path

PS = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
FLAGS = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def powershell(script, data=None, timeout=60):
    prefix = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::InputEncoding=[Text.UTF8Encoding]::new(); [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $request=([Console]::In.ReadToEnd() | ConvertFrom-Json); "
    encoded = base64.b64encode((prefix + script).encode('utf-16-le')).decode('ascii')
    env = os.environ.copy()
    # The parent may be PowerShell 7. Do not let its module path shadow Windows
    # PowerShell 5 security modules or load user-supplied lookalike modules.
    env['PSModulePath'] = str(Path(PS).parent / 'Modules')
    result = subprocess.run([PS, '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                            input=json.dumps(data or {}), capture_output=True, text=True, encoding='utf-8',
                            errors='replace', timeout=timeout, creationflags=FLAGS, shell=False, env=env)
    if result.returncode:
        # Do not expose script bodies or process arguments in user-facing errors.
        raise RuntimeError('Windows could not complete this check. It may require administrator access or a running Windows service.')
    raw = result.stdout.strip().lstrip('\ufeff')
    return json.loads(raw) if raw else None


SNAPSHOT = r'''
$out=[ordered]@{sections=[ordered]@{}}
function Capture($name, [scriptblock]$fn) {
  try { $out.sections[$name]=@{ok=$true;data=(& $fn);checkedAt=(Get-Date).ToUniversalTime().ToString('o')} }
  catch { $out.sections[$name]=@{ok=$false;error='Windows denied this check or the service is unavailable.';checkedAt=(Get-Date).ToUniversalTime().ToString('o')} }
}
Capture 'defender' {
 $s=Get-MpComputerStatus
 $fields='AMServiceEnabled','AntivirusEnabled','AntispywareEnabled','RealTimeProtectionEnabled','BehaviorMonitorEnabled','IoavProtectionEnabled','NISEnabled','IsTamperProtected','AntivirusSignatureVersion','AntivirusSignatureLastUpdated','AntivirusSignatureAge','QuickScanStartTime','QuickScanEndTime','FullScanStartTime','FullScanEndTime','ComputerState'
 $v=[ordered]@{}; foreach($f in $fields){$x=$s.$f;if($x -is [datetime]){$x=$x.ToUniversalTime().ToString('o')};$v[$f]=$x};$v
}
Capture 'preferences' {
 $p=Get-MpPreference
 $v=$p | Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,DisableScriptScanning,PUAProtection,MAPSReporting,SubmitSamplesConsent
 $ex=@($p.ExclusionPath)+@($p.ExclusionProcess)+@($p.ExclusionExtension)
 $v | Add-Member NoteProperty ExclusionsVisible (-not [bool]($ex -match 'administrator|N/A:'))
 $v | Add-Member NoteProperty ExclusionCount $(if($ex -match 'administrator|N/A:'){$null}else{@($ex | Where-Object {$_}).Count})
 $v
}
Capture 'threats' {
 @(Get-MpThreatDetection | Where-Object {$null -ne $_ -and $null -ne $_.ThreatID} | Select-Object ThreatID,ActionSuccess,CurrentThreatExecutionStatusID,@{n='InitialDetectionTime';e={$_.InitialDetectionTime.ToUniversalTime().ToString('o')}},@{n='LastThreatStatusChangeTime';e={$_.LastThreatStatusChangeTime.ToUniversalTime().ToString('o')}},Resources)
}
Capture 'firewall' { @(Get-NetFirewallProfile | Select-Object Name,@{n='Enabled';e={switch([int]$_.Enabled){1{$true}0{$false}default{$null}}}}) }
Capture 'restart' { @{WindowsUpdate=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired');Servicing=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')} }
Capture 'disks' { @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,Size,FreeSpace) }
Capture 'startup' {
 $entries=[Collections.Generic.List[object]]::new()
 foreach($key in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')){
  if(Test-Path -LiteralPath $key){
   $props=Get-ItemProperty -LiteralPath $key
   foreach($prop in $props.PSObject.Properties){if($prop.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$'){$entries.Add([pscustomobject]@{Name=$prop.Name;Location=$key;Command=[string]$prop.Value})}}
  }
 }
 foreach($folder in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))){
  if($folder -and (Test-Path -LiteralPath $folder)){Get-ChildItem -LiteralPath $folder -File | Where-Object {$_.Name -ne 'desktop.ini'} | ForEach-Object {$entries.Add([pscustomobject]@{Name=$_.BaseName;Location=$folder;Command=('"'+$_.FullName+'"')})}}
 }
 @($entries | ForEach-Object {
  $c=[string]$_.Command;$target='';if($c -match '^\s*"([^"]+)"'){$target=$Matches[1]}elseif($c -match '^\s*(.*?\.(exe|cmd|bat|ps1|vbs|lnk))\b'){$target=$Matches[1]}
  $flags=@();if($c -match '(?i)-(enc|encodedcommand)\s'){$flags+='Encoded PowerShell'};if($c -match '(?i)https?://'){$flags+='Network URL in launch arguments'};if($c -match '(?i)\\(temp|downloads)\\'){$flags+='Launches from a temporary or downloads folder'}
  [pscustomobject]@{Name=$_.Name;Location=$_.Location;Target=$target;Indicators=$flags}
 })
}
Capture 'network' {
 $process=@{};Get-Process | ForEach-Object {$process[[int]$_.Id]=$_.ProcessName}
 $listeners=@(Get-NetTCPConnection -State Listen | Sort-Object LocalPort,OwningProcess -Unique | Select-Object LocalAddress,LocalPort,OwningProcess,@{n='Process';e={$process[[int]$_.OwningProcess]}},@{n='Scope';e={if($_.LocalAddress -in @('127.0.0.1','::1')){'Loopback'}elseif($_.LocalAddress -in @('0.0.0.0','::')){'All interfaces'}else{'Specific interface'}}})
 $connections=@(Get-NetTCPConnection -State Established | Select-Object -First 100 LocalPort,RemoteAddress,RemotePort,OwningProcess,@{n='Process';e={$process[[int]$_.OwningProcess]}})
 @{listeners=$listeners;connections=$connections}
}
Capture 'remote' {
 $s=@(Get-Service | Where-Object {$_.Name -match 'RustDesk|chromoting|Unified' -or $_.DisplayName -match 'Unified Remote'})
 $items=@($s | Select-Object Name,DisplayName,@{n='Status';e={[string]$_.Status}},@{n='StartType';e={[string]$_.StartType}})
 $u=Get-Process -Name RemoteServerWin -ErrorAction SilentlyContinue
 $run=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
 @{services=$items;UnifiedRemoteRunning=[bool]$u;UnifiedRemoteStartup=[bool]$run.'Unified Remote V3'}
}
Capture 'securityProducts' { @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName,productState) }
Capture 'system' {
 $os=Get-CimInstance Win32_OperatingSystem
 $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
 @{computer=$env:COMPUTERNAME;os=$os.Caption;build=$os.BuildNumber;administrator=$admin}
}
$out | ConvertTo-Json -Depth 12 -Compress
'''

EVENTS = r'''
$null=Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction Stop
$filter=@{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1000,1001,1002,1005,1116,1117,1118,5001,5007;StartTime=(Get-Date).AddDays(-14)}
$events=@(Get-WinEvent -FilterHashtable $filter -MaxEvents 180 -ErrorAction SilentlyContinue | ForEach-Object {
 $x=[xml]$_.ToXml();$fields=[ordered]@{};foreach($d in $x.Event.EventData.Data){$fields[[string]$d.Name]=[string]$d.'#text'}
 [pscustomobject]@{id=$_.Id;record=$_.RecordId;time=$_.TimeCreated.ToUniversalTime().ToString('o');fields=$fields}
})
ConvertTo-Json -InputObject $events -Depth 8 -Compress
'''


def snapshot():
    value = powershell(SNAPSHOT, timeout=90)
    def array(x):
        # Windows PowerShell can serialize AutomationNull from an empty pipeline as {}.
        return x if isinstance(x, list) else [] if x is None or x == {} else [x]
    sections = value.get('sections', {})
    for key in ('threats', 'firewall', 'disks', 'startup', 'securityProducts'):
        if sections.get(key, {}).get('ok'):
            sections[key]['data'] = array(sections[key].get('data'))
    network = sections.get('network', {}).get('data')
    if network:
        for key in ('listeners', 'connections'):
            network[key] = array(network.get(key))
    remote = sections.get('remote', {}).get('data')
    if remote:
        remote['services'] = array(remote.get('services'))
    return value


def events():
    return powershell(EVENTS, timeout=45) or []


def signature(path):
    return powershell(r'''
$s=Get-AuthenticodeSignature -LiteralPath $request.path
@{status=[string]$s.Status;subject=$(if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null});issuer=$(if($s.SignerCertificate){$s.SignerCertificate.Issuer}else{$null})} | ConvertTo-Json -Compress
''', {'path': str(path)}, timeout=30)


def defender_executable():
    root = Path(os.environ.get('ProgramData', r'C:\ProgramData')) / 'Microsoft/Windows Defender/Platform'
    candidates = [root / 'CurrentVersion/MpCmdRun.exe']
    if root.exists():
        candidates += sorted(root.glob('4.*/MpCmdRun.exe'), reverse=True)
    candidates.append(Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Windows Defender/MpCmdRun.exe')
    for path in candidates:
        if not path.is_file():
            continue
        sig = signature(path)
        if sig.get('status') == 'Valid' and re.search(r'(?:^|,\s*)O=Microsoft Corporation(?:,|$)', sig.get('subject') or ''):
            return str(path)
    raise RuntimeError('A valid Microsoft-signed Defender command tool was not found. Repair Windows Security before scanning.')


def run_defender(kind, path=None):
    exe = defender_executable()
    args = [exe, '-SignatureUpdate'] if kind == 'update' else [exe, '-Scan', '-ScanType', {'quick': '1', 'full': '2', 'custom': '3'}[kind]]
    if kind == 'custom':
        args += ['-File', str(path)]
    # Keep the server alive until this process finishes. Never use a timeout to stop a scan.
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            creationflags=FLAGS, shell=False)
    # Drain without storing file names or Defender diagnostic text in the activity database.
    while proc.stdout.read(4096):
        pass
    return proc.wait()


def open_security():
    # Fixed Windows URI; no user-controlled target is launched.
    os.startfile('windowsdefender:')


def secure_data_folder(folder):
    """Restrict the app's own data directory; never accepts a web request path."""
    powershell(r'''
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
$ids=@([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
foreach($id in $ids){
 $rule=[Security.AccessControl.FileSystemAccessRule]::new($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
 $acl.SetAccessRule($rule)
}
[IO.Directory]::SetAccessControl($request.path,$acl)
@{ok=$true} | ConvertTo-Json -Compress
''', {'path': str(folder)})
