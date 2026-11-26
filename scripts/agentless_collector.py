import argparse
import io
import json
import os
import subprocess
import tarfile
from datetime import datetime
from pathlib import Path

import paramiko

EXCLUDE_ARGS = (
    "--exclude='node_modules' --exclude='.next' --exclude='vendor' "
    "--exclude='wp-content/uploads' --exclude='.git' --exclude='logs' "
    "--exclude='__pycache__' --exclude='.venv' --exclude='venv' --exclude='dist' --exclude='build' "
    "--exclude='*.jpg' --exclude='*.jpeg' --exclude='*.png' --exclude='*.gif' --exclude='*.webp' "
    "--exclude='*.mp4' --exclude='*.mov' --exclude='*.avi' --exclude='*.zip' --exclude='*.tar.gz' "
    "--exclude='*.rar' --exclude='*.7z' --exclude='*.bak' --exclude='*.sql' --exclude='*.log' "
    "--exclude='*.pdf' --exclude='*.exe' --exclude='*.dll' --exclude='*.bin'"
)

LINUX_SNAPSHOT_CMD = r"""
echo "# Live System & Security Snapshot ($(hostname) - $(date -Iseconds))"
echo ""
echo "## 1. OS & Kernel & Pending Security Updates"
lsb_release -ds 2>/dev/null || cat /etc/os-release | head -n 4
uname -a
[ -f /var/run/reboot-required ] && echo "REBOOT_REQUIRED: YES" || echo "REBOOT_REQUIRED: NO"
apt list --upgradable 2>/dev/null | head -n 40 || true

echo ""
echo "## 2. Listening Network Ports (ss -tulpn)"
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || true

echo ""
echo "## 3. Firewall Status (UFW / DOCKER-USER)"
ufw status verbose 2>/dev/null || true
iptables -S DOCKER-USER 2>/dev/null || true

echo ""
echo "## 4. Privileged Users, Sudoers & Database Services"
awk -F: '$3 == 0 {print "UID0:", $1}' /etc/passwd
for svc in nginx haproxy postgresql mysql mariadb mongod redis-server docker ssh; do
  st=$(systemctl is-active "$svc" 2>/dev/null || true)
  [ "$st" = "active" ] && echo "SERVICE_ACTIVE: $svc"
done
systemctl list-units --state=failed --no-pager 2>/dev/null || true

echo ""
echo "## 5. Docker Security Audit (Privileged / docker.sock / 0.0.0.0 Ports / Root)"
if command -v docker >/dev/null 2>&1; then
  docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || true
  echo "--- Docker Risk Inspection ---"
  for cid in $(docker ps -q 2>/dev/null); do
    docker inspect "$cid" --format '{{.Name}} | Privileged={{.HostConfig.Privileged}} | NetMode={{.HostConfig.NetworkMode}} | User={{.Config.User}} | Mounts={{range .Mounts}}{{.Source}}:{{.Destination}},{{end}}' 2>/dev/null || true
  done
else
  echo "Docker not installed."
fi
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
            # Fallback to keyboard-interactive auth for hardened VPS hosts
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
    if not raw_bytes:
        return 0
    dest_dir.mkdir(parents=True, exist_ok=True)
    cnt = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:gz") as tf:
            for m in tf.getmembers():
                if not m.isfile() or m.size > 3 * 1024 * 1024:
                    continue
                rel = m.name.lstrip("/").replace("..", "__")
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

    print("  [1/3] Collecting Live System, Firewall, DB & Docker Snapshot...", flush=True)
    snap_out, _ = run_remote(cli, LINUX_SNAPSHOT_CMD, use_sudo=use_sudo, sudo_pass=sudo_pass, timeout=60)
    (target_dir / "live_system_audit.md").write_bytes(snap_out)

    print("  [2/3] Pulling Service Configs (Nginx/HAProxy/PG/MySQL/MongoDB/Redis/SSH)...", flush=True)
    cfg_cmd = (
        "PATHS=''; for p in /etc/nginx /etc/haproxy /etc/postgresql /etc/mysql /etc/mongod.conf /etc/redis /etc/ssh/sshd_config /etc/sudoers.d; do "
        "[ -e \"$p\" ] && PATHS=\"$PATHS $p\"; done; "
        f"[ -n \"$PATHS\" ] && tar {EXCLUDE_ARGS} -czf - $PATHS 2>/dev/null || true"
    )
    cfg_bytes, _ = run_remote(cli, cfg_cmd, use_sudo=use_sudo, sudo_pass=sudo_pass, timeout=90)
    n_cfg = safe_extract_tar_bytes(cfg_bytes, target_dir / "configs")
    print(f"       Pulled {n_cfg} config files.", flush=True)

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
    print(f"       Pulled {n_code} source files.", flush=True)

def collect_windows(cli, target_dir: Path):
    print("  [1/2] Collecting Windows Live System, Firewall, IIS & MSSQL Snapshot...", flush=True)
    ps = r"""
Write-Output "# Windows Live Security Snapshot ($env:COMPUTERNAME - $(Get-Date -Format 's'))"
Write-Output "## 1. OS & Hotfixes"
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object ProductName, CurrentBuild, UBR | Format-List
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, InstalledOn | Format-Table -AutoSize
Write-Output "## 2. Firewall Profiles & Defender"
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction | Format-Table -AutoSize
Get-MpComputerStatus -EA 0 | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated | Format-List
Write-Output "## 3. Listening Ports"
Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort | Sort-Object LocalPort -Unique | Format-Table -AutoSize
Write-Output "## 4. IIS Websites & SQL/DB Services"
Import-Module WebAdministration -EA 0
Get-Website -EA 0 | Select-Object Name, State, PhysicalPath | Format-Table -AutoSize
Get-Service | Where-Object { $_.Name -match 'SQL|Mongo|Postgres|MySQL|W3SVC|Docker' } | Select-Object Name, Status, StartType | Format-Table -AutoSize
"""
    i, o, e = cli.exec_command("powershell -NoProfile -NonInteractive -Command -", timeout=60)
    i.write(ps + "\n"); i.flush(); i.channel.shutdown_write()
    (target_dir / "live_system_audit.md").write_bytes(o.read())
    print("  [2/2] Windows Live Snapshot saved.", flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config-json", required=True)
    args = ap.parse_args()
    cfg = json.loads(Path(args.config_json).read_text(encoding="utf-8"))
    target_dir = Path(cfg["local_path"])
    target_dir.mkdir(parents=True, exist_ok=True)

    print(f"[Agentless-SSH] Connecting to {cfg['ssh_user']}@{cfg['ssh_host']}:{cfg['ssh_port']} ({cfg['ssh_auth']})...", flush=True)
    cli = connect_ssh(
        cfg["ssh_host"], cfg.get("ssh_port", 22), cfg["ssh_user"],
        cfg.get("ssh_auth", "key"), cfg.get("key_path", ""), cfg.get("ssh_password", "")
    )
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
