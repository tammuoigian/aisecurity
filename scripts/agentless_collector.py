import argparse
import io
import json
import os
import shutil
import subprocess
import tarfile
from datetime import datetime
from pathlib import Path

import paramiko

EXCLUDE_ARGS = (
    "--exclude='node_modules' --exclude='*/node_modules' --exclude='*/node_modules/*' "
    "--exclude='.next' --exclude='*/.next' --exclude='vendor' --exclude='*/vendor' "
    "--exclude='wp-content/uploads' --exclude='*/wp-content/uploads' --exclude='*/wp-content/cache' "
    "--exclude='.git' --exclude='*/.git' --exclude='logs' --exclude='*/logs' "
    "--exclude='.cache' --exclude='*/.cache' --exclude='.npm' --exclude='*/.npm' "
    "--exclude='.nvm' --exclude='*/.nvm' --exclude='.local' --exclude='*/.local' "
    "--exclude='.cargo' --exclude='*/.cargo' --exclude='site-packages' --exclude='*/site-packages' "
    "--exclude='__pycache__' --exclude='*/__pycache__' --exclude='.venv' --exclude='*/.venv' "
    "--exclude='venv' --exclude='*/venv' --exclude='dist' --exclude='*/dist' "
    "--exclude='build' --exclude='*/build' --exclude='storage' --exclude='*/storage' "
    "--exclude='uploads' --exclude='*/uploads' --exclude='tmp' --exclude='*/tmp' "
    "--exclude='*.min.js' --exclude='*.map' "
    "--exclude='*.jpg' --exclude='*.jpeg' --exclude='*.png' --exclude='*.gif' --exclude='*.webp' "
    "--exclude='*.mp4' --exclude='*.mov' --exclude='*.avi' --exclude='*.zip' --exclude='*.tar.gz' "
    "--exclude='*.rar' --exclude='*.7z' --exclude='*.bak' --exclude='*.sql' --exclude='*.log' "
    "--exclude='*.pdf' --exclude='*.exe' --exclude='*.dll' --exclude='*.bin' "
    "--exclude='*.key' --exclude='*.pem'"
)

LINUX_SNAPSHOT_CMD = r"""
HOST=$(hostname)
NOW=$(date -Iseconds)
OS_VER=$(lsb_release -ds 2>/dev/null || grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')
KERNEL=$(uname -sr)
REBOOT=$([ -f /var/run/reboot-required ] && echo "CẦN REBOOT (YES)" || echo "Không (NO)")

echo "# Báo Cáo Hiện Trạng Hệ Thống & CIS/MITRE Audit ($HOST — $NOW)"
echo ""
echo "## 1. Hệ Điều Hành, Kernel & Gói Chờ Cập Nhật"
echo ""
echo "| Thông số | Giá trị |"
echo "|---|---|"
echo "| **Hostname** | \`$HOST\` |"
echo "| **Hệ điều hành** | $OS_VER |"
echo "| **Kernel** | \`$KERNEL\` |"
echo "| **Trạng thái Reboot** | **$REBOOT** |"
echo ""
UPG=$(timeout 10s apt list --upgradable 2>/dev/null | grep -v '^Listing' | head -n 40 || true)
if [ -n "$UPG" ]; then
  CNT=$(timeout 10s apt list --upgradable 2>/dev/null | grep -v '^Listing' | wc -l || echo 0)
  echo "### Danh sách gói chờ cập nhật (Hiển thị tối đa 40 / Tổng $CNT gói)"
  echo ""
  echo "| Gói phần mềm | Phiên bản mới | Phiên bản hiện tại | Nhánh |"
  echo "|---|---|---|---|"
  echo "$UPG" | awk '{
    split($1, a, "/"); pkg=a[1]; br=a[2];
    newv=$2;
    oldv="-";
    if (match($0, /upgradable from: ([^\]]+)/, m)) oldv=m[1];
    printf "| `%s` | `%s` | `%s` | %s |\n", pkg, newv, oldv, br;
  }'
else
  echo "- Hệ thống đã cập nhật đầy đủ các gói APT."
fi

echo ""
echo "## 2. Cổng Mạng Đang Mở (Listening Ports — ss -tulpn)"
echo ""
echo '```text'
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || true
echo '```'

echo ""
echo "## 3. Tường Lửa (UFW / DOCKER-USER)"
echo ""
echo '```text'
ufw status verbose 2>/dev/null || echo "UFW not installed"
echo "--- iptables DOCKER-USER ---"
iptables -S DOCKER-USER 2>/dev/null || echo "No DOCKER-USER chain"
echo '```'

echo ""
echo "## 4. CIS SSH, Kernel Sysctl & Dịch Vụ Nền"
echo ""
echo "| Kiểm tra CIS / Hardening | Cấu hình hiện tại |"
echo "|---|---|"
SSH_ROOT=$(grep -iE '^\s*PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -n 1 || echo "Mặc định (chưa khai báo)")
SSH_PASS=$(grep -iE '^\s*PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -n 1 || echo "Mặc định (chưa khai báo)")
SSH_EMPTY=$(grep -iE '^\s*PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null | tail -n 1 || echo "no (mặc định)")
ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "N/A")
SYNC=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "N/A")
IPFWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "N/A")
echo "| **SSH PermitRootLogin** | \`$SSH_ROOT\` |"
echo "| **SSH PasswordAuthentication** | \`$SSH_PASS\` |"
echo "| **SSH PermitEmptyPasswords** | \`$SSH_EMPTY\` |"
echo "| **Kernel ASLR (randomize_va_space)** | \`$ASLR\` (chuẩn CIS = 2) |"
echo "| **TCP SYN Cookies** | \`$SYNC\` (chuẩn CIS = 1) |"
echo "| **IPv4 Forwarding** | \`$IPFWD\` |"
echo ""
echo '```text'
for svc in nginx haproxy postgresql mysql mariadb mongod redis-server docker ssh fail2ban wazuh-agent; do
  st=$(systemctl is-active "$svc" 2>/dev/null || true)
  [ "$st" = "active" ] && echo "SERVICE_ACTIVE: $svc"
done
echo '```'

echo ""
echo "## 5. MITRE ATT&CK — Leo Thang Đặc Quyền & Persistence (UID0 / Sudoers / SUID / Cron)"
echo ""
echo '```text'
echo "[UID 0 Accounts]"
awk -F: '$3 == 0 {print "  UID0:", $1}' /etc/passwd
echo "[Sudoers NOPASSWD]"
grep -rn "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | head -n 20 || echo "  None"
echo "[Suspicious Cron /tmp or /dev/shm]"
grep -rnE "(/tmp/|/dev/shm/|curl |wget |base64 )" /etc/crontab /etc/cron.d/ /var/spool/cron/crontabs/ 2>/dev/null | head -n 20 || echo "  None"
echo "[Non-standard SUID binaries (top 20)]"
timeout 8s find /usr/local /opt /tmp /home -maxdepth 4 -perm -4000 -type f 2>/dev/null | head -n 20 || true
echo '```'

echo ""
echo "## 6. Kiểm Toán Bảo Mật Docker (Privileged / docker.sock / Host Network / Root)"
echo ""
if command -v docker >/dev/null 2>&1; then
  echo '```text'
  docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true
  echo ""
  echo "--- Docker Risk Inspection (Wiz Deep Capabilities / Seccomp / Sensitive ENV Names) ---"
  for cid in $(docker ps -q 2>/dev/null | head -n 25); do
    docker inspect "$cid" --format '{{.Name}} | Privileged={{.HostConfig.Privileged}} | NetMode={{.HostConfig.NetworkMode}} | PidMode={{.HostConfig.PidMode}} | ReadonlyRoot={{.HostConfig.ReadonlyRootfs}} | CapAdd={{.HostConfig.CapAdd}} | User={{.Config.User}} | Mounts={{range .Mounts}}{{.Source}}:{{.Destination}},{{end}}' 2>/dev/null || true
    ENV_HITS=$(docker inspect "$cid" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -iE '(PASS|SECRET|TOKEN|API_?KEY|CONN|PRIVATE)' | cut -d= -f1 | tr '\n' ',' || true)
    [ -n "$ENV_HITS" ] && echo "  [Wiz-ENV-Risk] Sensitive ENV keys in container (values masked): ${ENV_HITS%,}"
  done
  echo '```'
else
  echo "- Docker chưa được cài đặt trên máy chủ này."
fi

echo ""
echo "## 7. Kiểm Toán Chứng Chỉ SSL/TLS (Qualys / Tenable)"
echo ""
SSL_FOUND=0
for cert in $(timeout 8s find /etc/letsencrypt/live /etc/nginx /etc/ssl/private -maxdepth 3 -type f \( -name "*.crt" -o -name "fullchain.pem" \) 2>/dev/null | head -n 15); do
  END=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2 || true)
  if [ -n "$END" ]; then
    SSL_FOUND=1
    EXP_TS=$(date -d "$END" +%s 2>/dev/null || echo 0)
    NOW_TS=$(date +%s)
    DAYS=$(( (EXP_TS - NOW_TS) / 86400 ))
    ST="OK"
    [ "$DAYS" -lt 0 ] && ST="SSL_EXPIRED"
    [ "$DAYS" -ge 0 ] && [ "$DAYS" -le 30 ] && ST="SSL_EXPIRING_SOON"
    printf '- `%s` — Hết hạn: **%s** (còn **%s ngày**) [%s]\n' "$cert" "$END" "$DAYS" "$ST"
  fi
done
[ "$SSL_FOUND" -eq 0 ] && echo "- Không tìm thấy chứng chỉ SSL cục bộ trong /etc/nginx hoặc /etc/letsencrypt."

echo ""
echo "## 8. Live Threat Hunting & IOCs (CrowdStrike / Rapid7)"
echo ""
echo '```text'
echo "[Top Outbound ESTABLISHED Connections]"
ss -tnp state established 2>/dev/null | head -n 20 || true
echo ""
echo "[Suspicious Processes Running From /tmp or /dev/shm]"
ps -eo pid,user,cmd --no-headers 2>/dev/null | grep -E "(/tmp/|/dev/shm/)" | grep -v grep | head -n 15 | sed 's/^/IOC_SUSPICIOUS_PROC: /' || echo "None"
echo ""
echo "[Recent Logins (last -n 10)]"
last -n 10 2>/dev/null || true
echo ""
echo "[SSH authorized_keys Inventory]"
for kf in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$kf" ] && echo "  $kf ($(wc -l < "$kf") keys)"
done
echo ""
echo "[CrowdStrike Expert Hunting: Deleted-but-Running Binaries (/proc/*/exe)]"
ls -l /proc/*/exe 2>/dev/null | grep '(deleted)' | head -n 15 | sed 's/^/IOC_DELETED_BIN: /' || echo "  None"
echo ""
echo "[CrowdStrike Rootkit Check: /etc/ld.so.preload]"
[ -s /etc/ld.so.preload ] && (echo "IOC_LD_PRELOAD_FOUND:"; cat /etc/ld.so.preload) || echo "  Clean (empty/not present)"
echo ""
echo "[Webshell Indicator Scan (/var/www — *.php/*.phtml, fast bounded)]"
timeout 10s grep -rnE --include='*.php' --include='*.phtml' --exclude-dir=node_modules --exclude-dir=uploads --exclude-dir=cache --exclude-dir=vendor --exclude-dir=.git "(eval\s*\(\s*base64_decode|system\s*\(\s*\\\$_|shell_exec\s*\(\s*\\\$_|passthru\s*\(\s*\\\$_)" /var/www 2>/dev/null | head -n 15 | sed 's/^/IOC_WEBSHELL_SUSPECT: /' || echo "  None"
echo '```'
"""

WINDOWS_SNAPSHOT_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$h = $env:COMPUTERNAME
$now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Write-Output "# Báo Cáo Hiện Trạng Windows & CIS/MITRE Audit ($h — $now)"
Write-Output ""
Write-Output "## 1. Hệ Điều Hành & Bản Vá Mới Nhất (Hotfixes)"
Write-Output ""
Write-Output "| Thông số | Giá trị |"
Write-Output "|---|---|"
Write-Output "| **Hostname** | ``$h`` |"
Write-Output "| **OS** | $($cv.ProductName) (Build $($cv.CurrentBuild).$($cv.UBR)) |"
Write-Output ""
Write-Output '```text'
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID, Description, InstalledOn | Format-Table -AutoSize | Out-String
Write-Output '```'

Write-Output "## 2. Windows Firewall, Defender & Exclusions (MITRE Defense Evasion)"
Write-Output '```text'
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize | Out-String
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, AntivirusSignatureLastUpdated | Format-List | Out-String
$mp = Get-MpPreference
Write-Output ("Defender ExclusionPath: " + (($mp.ExclusionPath) -join ', '))
Write-Output ("Defender ExclusionProcess: " + (($mp.ExclusionProcess) -join ', '))
Write-Output '```'

Write-Output "## 3. CIS Hardening (RDP / SMBv1 / LSA Protection / WDigest / UAC / PS Logging)"
$rdp = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -EA 0).fDenyTSConnections
$nla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -EA 0).UserAuthentication
$smb1 = (Get-SmbServerConfiguration -EA 0).EnableSMB1Protocol
$ppl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -EA 0).RunAsPPL
$wdig = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -EA 0).UseLogonCredential
$uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -EA 0).EnableLUA
$pslog = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA 0).EnableScriptBlockLogging
Write-Output "| Kiểm tra CIS | Giá trị thực tế | Chuẩn khuyến nghị |"
Write-Output "|---|---|---|"
Write-Output "| **RDP Disabled (fDenyTSConnections)** | ``$rdp`` | 1 (hoặc bật NLA) |"
Write-Output "| **RDP NLA (UserAuthentication)** | ``$nla`` | 1 (Bắt buộc NLA) |"
Write-Output "| **SMBv1 Enabled** | ``$smb1`` | False |"
Write-Output "| **LSA Protection (RunAsPPL)** | ``$ppl`` | 1 |"
Write-Output "| **WDigest Plaintext (UseLogonCredential)** | ``$wdig`` | 0 hoặc trống |"
Write-Output "| **UAC (EnableLUA)** | ``$uac`` | 1 |"
Write-Output "| **PowerShell ScriptBlock Logging** | ``$pslog`` | 1 |"
Write-Output ""

Write-Output "## 4. Cổng Mạng Đang Mở (Listening TCP Ports)"
Write-Output '```text'
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort | Sort-Object LocalPort -Unique | Format-Table -AutoSize | Out-String
Write-Output '```'

Write-Output "## 5. MITRE ATT&CK — Unquoted Service Paths, Local Admins & Scheduled Tasks"
Write-Output '```text'
Write-Output "[Local Administrators]"
Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass | Format-Table -AutoSize | Out-String
Write-Output "[Unquoted Service Paths (Privilege Escalation)]"
Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -notmatch '^C:\\Windows\\' -and $_.PathName -match ' ' } | Select-Object Name, State, PathName | Format-Table -AutoSize | Out-String
Write-Output "[Non-Microsoft Scheduled Tasks running from Temp/Users/AppData]"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | ForEach-Object {
  $act = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
  if ($act -match 'Temp|AppData|Users|powershell|cmd\.exe|wscript|mshta') { "$($_.TaskName) -> $act" }
} | Select-Object -First 20
Write-Output '```'

Write-Output "## 6. IIS Websites, DB Services & SQL Server PatchLevel"
Write-Output '```text'
Import-Module WebAdministration -EA 0
Get-Website -EA 0 | Select-Object Name, State, PhysicalPath | Format-Table -AutoSize | Out-String
Get-Service | Where-Object { $_.Name -match 'SQL|Mongo|Postgres|MySQL|W3SVC|Docker|Redis|Wazuh' } | Select-Object Name, Status, StartType | Format-Table -AutoSize | Out-String
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -EA 0 | ForEach-Object {
  $setup = Join-Path $_.PSPath 'Setup'
  if (Test-Path $setup) {
    $p = Get-ItemProperty $setup
    Write-Output "SQL Instance=$($_.PSChildName) | Edition=$($p.Edition) | Version=$($p.Version) | PatchLevel=$($p.PatchLevel)"
  }
}
Write-Output '```'

Write-Output "## 7. Kiểm Toán Chứng Chỉ SSL/TLS (Qualys / Tenable)"
Write-Output '```text'
$nowD = Get-Date
$certs = Get-ChildItem Cert:\LocalMachine\My -EA 0 | Sort-Object NotAfter | Select-Object -First 15
foreach ($ct in $certs) {
  $days = [math]::Floor(($ct.NotAfter - $nowD).TotalDays)
  $st = if ($days -lt 0) { 'SSL_EXPIRED' } elseif ($days -le 30) { 'SSL_EXPIRING_SOON' } else { 'OK' }
  Write-Output ("Cert: $($ct.Subject) | Expires: $($ct.NotAfter.ToString('yyyy-MM-dd')) | DaysLeft=$days | [$st]")
}
Write-Output '```'

Write-Output "## 8. Live Threat Hunting & IOCs (CrowdStrike / Rapid7)"
Write-Output '```text'
Write-Output "[Top Established Outbound Connections]"
Get-NetTCPConnection -State Established -EA 0 | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } | Select-Object -First 20 LocalPort, RemoteAddress, RemotePort, OwningProcess | Format-Table -AutoSize | Out-String
Write-Output "[Suspicious Processes Running From Temp/AppData/Public]"
Get-CimInstance Win32_Process -EA 0 | Where-Object { $_.ExecutablePath -match '(\\Temp\\|\\AppData\\Local\\Temp\\|\\Users\\Public\\)' } | ForEach-Object { Write-Output ("IOC_SUSPICIOUS_PROC: PID=$($_.ProcessId) $($_.Name) -> $($_.ExecutablePath)") }
Write-Output "[CrowdStrike Fileless Persistence: WMI Event Subscriptions]"
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -EA 0 | Select-Object Name, Query | Format-Table -AutoSize | Out-String
Write-Output "[Registry Run / RunOnce Keys]"
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -EA 0 | Out-String
Write-Output "[SMB Shares Open to Everyone]"
Get-SmbShareAccess -Name * -EA 0 | Where-Object { $_.AccountName -match 'Everyone' -and $_.Name -notmatch '\$$' } | Select-Object Name, AccountName, AccessRight | Format-Table -AutoSize | Out-String
Write-Output "[IIS Webshell Indicator Scan (wwwroot *.aspx/*.ashx)]"
Get-ChildItem 'C:\inetpub\wwwroot' -Include *.aspx,*.ashx -Recurse -EA 0 | Select-String -Pattern 'Process\.Start|cmd\.exe|eval\s*\(\s*Request' -EA 0 | Select-Object -First 15 Path, LineNumber | Format-Table -AutoSize | Out-String
Write-Output '```'
"""

def load_pkey_any(key_file: str):
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key_file(key_file)
        except Exception:
            continue
    raise ValueError("Unsupported or invalid SSH private key format")

def connect_ssh(host, port, username, auth_type, key_path, password):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if auth_type in ("key", "custom_key"):
        pkey = load_pkey_any(key_path)
        cli.connect(host, port=int(port), username=username, pkey=pkey, timeout=15, look_for_keys=False, allow_agent=False)
    else:
        try:
            cli.connect(host, port=int(port), username=username, password=password, timeout=15, look_for_keys=False, allow_agent=False)
        except paramiko.AuthenticationException:
            tr = paramiko.Transport((host, int(port)))
            tr.connect()
            tr.auth_interactive(username, lambda title, instr, prompts: [password for _ in prompts])
            cli._transport = tr
    return cli

def run_remote(cli, cmd, use_sudo=False, sudo_pass="", timeout=120):
    if use_sudo:
        if sudo_pass:
            i, o, e = cli.exec_command("sudo -S -p '' bash -s", timeout=timeout)
            i.write(sudo_pass + "\n" + cmd)
        else:
            i, o, e = cli.exec_command("sudo -n bash -s", timeout=timeout)
            i.write(cmd)
    else:
        i, o, e = cli.exec_command("bash -s", timeout=timeout)
        i.write(cmd)
    i.flush()
    i.channel.shutdown_write()
    return o.read(), e.read()

def safe_extract_tar_bytes(raw_bytes: bytes, dest_dir: Path):
    if dest_dir.exists():
        shutil.rmtree(dest_dir, ignore_errors=True)
    if not raw_bytes:
        return 0
    dest_dir.mkdir(parents=True, exist_ok=True)
    cnt = 0
    total_bytes = 0
    SKIP_PARTS = {"node_modules", ".next", "vendor", ".git", ".cache", ".npm", ".nvm", ".local", "site-packages", "__pycache__", "uploads", "storage"}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:gz") as tf:
            for m in tf.getmembers():
                if cnt >= 15000 or total_bytes >= 150 * 1024 * 1024:
                    print("  [INFO] Reached safety cap (15,000 files / 150 MB) — stopping extract.", flush=True)
                    break
                if not m.isfile() or m.size > 2 * 1024 * 1024:
                    continue
                rel = m.name.lstrip("/").replace("..", "__")
                if any(part in SKIP_PARTS for part in rel.split("/")):
                    continue
                total_bytes += m.size
                target = dest_dir / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                f = tf.extractfile(m)
                if f:
                    target.write_bytes(f.read())
                    cnt += 1
    except Exception as ex:
        print(f"  [WARN] tar extract note: {ex}", flush=True)
    return cnt

def collect_linux(cli, target_dir: Path, remote_paths: str, sudo_pass: str):
    use_sudo = True
    out_t, _ = run_remote(cli, "id -u", use_sudo=True, sudo_pass=sudo_pass, timeout=15)
    if out_t.decode("utf-8", "ignore").strip() != "0":
        use_sudo = False
        print("  [INFO] Non-root read-only SSH mode", flush=True)
    else:
        print("  [INFO] Root/sudo read-only SSH mode", flush=True)

    print("  [1/3] Collecting Live System, CIS Hardening, MITRE Persistence, SSL/TLS & Threat Hunting Snapshot...", flush=True)
    snap_out, _ = run_remote(cli, LINUX_SNAPSHOT_CMD, use_sudo=use_sudo, sudo_pass=sudo_pass, timeout=150)
    (target_dir / "live_system_audit.md").write_bytes(snap_out)

    # Qualys/Nessus-grade OS Package DB pull (/var/lib/dpkg/status + /etc/os-release) for Trivy rootfs OS CVE scan
    os_pkg_bytes, _ = run_remote(cli, "tar -czf - /var/lib/dpkg/status /etc/os-release 2>/dev/null || true", use_sudo=use_sudo, sudo_pass=sudo_pass, timeout=30)
    n_ospkg = safe_extract_tar_bytes(os_pkg_bytes, target_dir / "os_packages")
    if n_ospkg:
        print(f"       Pulled Linux OS package DB ({n_ospkg} files) for Qualys/Nessus-grade OS CVE scanning.", flush=True)

    print("  [2/3] Pulling Service Configs (Nginx/HAProxy/PG/MySQL/MongoDB/Redis/SSH)...", flush=True)
    cfg_cmd = (
        "PATHS=''; for p in /etc/nginx /etc/haproxy /etc/postgresql /etc/mysql /etc/mongod.conf /etc/redis /etc/ssh/sshd_config /etc/sudoers.d; do "
        "[ -e \"$p\" ] && PATHS=\"$PATHS $p\"; done; "
        f"[ -n \"$PATHS\" ] && tar {EXCLUDE_ARGS} -czf - $PATHS 2>/dev/null || true"
    )
    cfg_bytes, _ = run_remote(cli, cfg_cmd, use_sudo=use_sudo, sudo_pass=sudo_pass, timeout=90)
    n_cfg = safe_extract_tar_bytes(cfg_bytes, target_dir / "configs")
    print(f"       Pulled {n_cfg} config files (cleaned stale configs first).", flush=True)

    if remote_paths.strip():
        clean_paths = [p.strip() for p in remote_paths.split(",") if p.strip()]
        quoted = " ".join(f'"{p}"' for p in clean_paths)
        print(f"  [3/3] Pulling Targeted Source Code: {clean_paths}...", flush=True)
        code_cmd = f"tar {EXCLUDE_ARGS} -czf - {quoted} 2>/dev/null || true"
    else:
        print("  [3/3] Auto-Discovering ALL Web/App/Docker/MCP Projects across /var/www, /opt, /srv, /home, /root...", flush=True)
        code_cmd = (
            "FOUND=$(find /var/www /opt /srv /home /root -maxdepth 3 "
            "\\( -name 'package.json' -o -name 'next.config.*' -o -name 'wp-config.php' -o -name 'docker-compose.y*ml' -o -name 'compose.y*ml' -o -name 'mcp*.json' -o -name 'requirements.txt' -o -name '*.csproj' \\) "
            "-not -path '*/node_modules/*' -not -path '*/.next/*' -not -path '*/vendor/*' 2>/dev/null | xargs -r -n1 dirname | sort -u | head -n 25); "
            f"[ -n \"$FOUND\" ] && tar {EXCLUDE_ARGS} -czf - $FOUND 2>/dev/null || true"
        )
    code_bytes, _ = run_remote(cli, code_cmd, use_sudo=use_sudo, sudo_pass=sudo_pass, timeout=180)
    n_code = safe_extract_tar_bytes(code_bytes, target_dir / "code")
    print(f"       Pulled {n_code} clean source files (removed stale node_modules).", flush=True)

def collect_windows(cli, target_dir: Path):
    print("  [1/2] Collecting Windows CIS Hardening, MITRE Persistence, IIS & MSSQL Snapshot...", flush=True)
    i, o, e = cli.exec_command("powershell -NoProfile -NonInteractive -Command -", timeout=90)
    i.write(WINDOWS_SNAPSHOT_PS + "\n"); i.flush(); i.channel.shutdown_write()
    (target_dir / "live_system_audit.md").write_bytes(o.read())
    print("  [2/2] Windows CIS/MITRE Live Snapshot saved.", flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config-json", required=True)
    args = ap.parse_args()
    cfg = json.loads(Path(args.config_json).read_text(encoding="utf-8"))
    target_dir = Path(cfg["local_path"])
    target_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Agentless-SSH] Connecting to {cfg['ssh_user']}@{cfg['ssh_host']}:{cfg['ssh_port']} ({cfg['ssh_auth']})...", flush=True)
    try:
        cli = connect_ssh(
            cfg["ssh_host"], cfg.get("ssh_port", 22), cfg["ssh_user"],
            cfg.get("ssh_auth", "key"), cfg.get("key_path", ""), cfg.get("ssh_password", "")
        )
    except Exception as ex:
        host_ip = str(cfg.get("ssh_host", ""))
        hint = ""
        if host_ip.startswith("100."):
            hint = " -> GỢI Ý: IP 100.x thuộc dải Tailscale/CGNAT. Hãy cài & đăng nhập Tailscale trên máy chủ Audit, hoặc dùng 1-Line Push Collector ở Tab 2!"
        else:
            hint = " -> GỢI Ý: Kiểm tra lại IP, cổng SSH, tường lửa UFW/Firewall trên máy đích, hoặc dùng 1-Line Push Collector ở Tab 2."
        print(f"[ERROR] Không thể kết nối SSH tới {cfg['ssh_user']}@{host_ip}:{cfg.get('ssh_port', 22)} — {type(ex).__name__}: {ex}{hint}", flush=True)
        raise SystemExit(1)
    try:
        if cfg.get("os_type", "linux") == "windows":
            collect_windows(cli, target_dir)
        else:
            collect_linux(cli, target_dir, cfg.get("remote_paths", ""), cfg.get("sudo_password", "") or cfg.get("ssh_password", ""))
    finally:
        cli.close()

    wsl_dir = "/mnt/" + target_dir.drive[0].lower() + target_dir.as_posix()[2:]
    tag = "ssh-" + datetime.now().strftime("%Y%m%d-%H%M")
    git_cmd = (
        f"git config --global --add safe.directory '*' && cd '{wsl_dir}' && "
        f"([ -d .git ] || (git init -q && git config user.name 'AI Security Audit' && git config user.email 'audit@secops.local')) && "
        f"git add -A && (git diff --cached --quiet || (git commit -q -m 'Agentless sync {tag}' && git tag -f '{tag}'))"
    )
    subprocess.run(["wsl", "-u", "root", "bash", "-c", git_cmd], check=False)
    print(f"[Agentless-SSH] SYNC COMPLETE -> {target_dir} (tag: {tag})", flush=True)

if __name__ == "__main__":
    main()
