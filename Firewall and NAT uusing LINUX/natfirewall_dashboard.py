#!/usr/bin/env python3
"""
natfirewall_controller_full.py

Full NAT + Firewall controller:
 - enable/disable NAT (sysctl + iptables MASQUERADE)
 - block/unblock IPs (iptables)
 - install/config dnsmasq, create DHCP/DNS LAN config
 - block/unblock domains via dnsmasq (nf-blocks.conf) or /etc/hosts fallback
 - optionally force clients to use gateway DNS (iptables to drop port 53)
 - view iptables/conntrack output, follow firewall logs, show bandwidth graphs
 - GUI (Tkinter) with Safe confirmations and threaded background updates

Run as root (pkexec attempted if run as non-root).
"""

import os
import sys
import subprocess
import threading
import time
import platform
import socket
import re
import shutil
from functools import lru_cache
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog

# matplotlib + psutil for bandwidth chart
import psutil
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

APP_TITLE = "NAT Firewall Controller (Full)"
CFG_PATH = Path.home() / ".natfw.ini"

# Default interfaces and DHCP range (customize if needed)
DEFAULT_WAN = "wlp1s0"
DEFAULT_LAN = "enp3s0f3u1"
GATEWAY_IP = "192.168.10.1"
DHCP_START = "192.168.10.10"
DHCP_END = "192.168.10.100"

DNSMASQ_CONF_DIR = "/etc/dnsmasq.d"
DNSMASQ_BLOCK_FILE = os.path.join(DNSMASQ_CONF_DIR, "nf-blocks.conf")
DNSMASQ_LAN_CONF = os.path.join(DNSMASQ_CONF_DIR, "nf-lan.conf")

MIN_REFRESH = 0.2

# ----------------------
# Helpers
# ----------------------
def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0

def try_pkexec_relaunch():
    # Relaunch via pkexec (graphical) if available
    if shutil.which("pkexec"):
        try:
            args = ["pkexec", sys.executable] + sys.argv
            os.execvp("pkexec", args)
        except Exception as e:
            print("pkexec failed:", e)
    # fallback message
    messagebox.showerror("Root required", f"This program must run as root.\nRun: sudo -E python3 {os.path.basename(__file__)}")
    sys.exit(1)

def run_cmd(cmd, capture=False, check=True, timeout=None):
    """Run shell command. If capture=True return stdout string."""
    if capture:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        if check and res.returncode != 0:
            raise subprocess.CalledProcessError(res.returncode, cmd, output=res.stdout)
        return res.returncode, res.stdout
    else:
        res = subprocess.run(cmd, shell=True)
        if check and res.returncode != 0:
            raise subprocess.CalledProcessError(res.returncode, cmd)
        return res.returncode, None

@lru_cache(maxsize=4096)
def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

# ----------------------
# System actions: NAT & iptables
# ----------------------
def enable_nat(wan_if, lan_if):
    """Enable IP forwarding and NAT rules."""
    run_cmd("sysctl -w net.ipv4.ip_forward=1")
    # flush to avoid duplicate rules
    run_cmd("iptables -t nat -F || true", check=False)
    run_cmd("iptables -F || true", check=False)
    # NAT and forward
    run_cmd(f"iptables -t nat -A POSTROUTING -o {wan_if} -j MASQUERADE")
    run_cmd("iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT")
    run_cmd(f"iptables -A FORWARD -i {lan_if} -o {wan_if} -j ACCEPT")
    # optional logging
    run_cmd("iptables -A FORWARD -j LOG --log-prefix 'FIREWALL: ' --log-level 4")
    # done
    return True

def disable_nat():
    run_cmd("iptables -F || true", check=False)
    run_cmd("iptables -t nat -F || true", check=False)
    # optionally disable forwarding (we leave it enabled)
    # run_cmd("sysctl -w net.ipv4.ip_forward=0")
    return True

def block_ip(ip):
    run_cmd(f"iptables -A FORWARD -d {ip} -j DROP")
    return True

def unblock_ip(ip):
    run_cmd(f"iptables -D FORWARD -d {ip} -j DROP", check=False)
    return True

# ----------------------
# dnsmasq management (install/config/restart), hosts fallback
# ----------------------
def install_dnsmasq():
    if shutil.which("dnsmasq"):
        return True, "dnsmasq already installed"
    # attempt install via dnf (Fedora) or apt
    try:
        if os.path.exists("/usr/bin/dnf"):
            run_cmd("dnf install -y dnsmasq", check=True)
        elif os.path.exists("/usr/bin/apt"):
            run_cmd("apt update && apt install -y dnsmasq", check=True)
        else:
            return False, "No supported package manager found (dnf/apt)"
        return True, "dnsmasq installed"
    except subprocess.CalledProcessError as e:
        return False, f"Install failed: {e}"

def write_dnsmasq_lan_config(lan_iface, gateway_ip, dhcp_start=DHCP_START, dhcp_end=DHCP_END, lease="12h"):
    os.makedirs(DNSMASQ_CONF_DIR, exist_ok=True)
    cfg = [
        f"interface={lan_iface}",
        "bind-interfaces",
        f"dhcp-range={dhcp_start},{dhcp_end},{lease}",
        f"dhcp-option=3,{gateway_ip}",
        f"dhcp-option=6,{gateway_ip},8.8.8.8",
        "server=8.8.8.8",
        "addn-hosts=/etc/hosts",
        ""
    ]
    with open(DNSMASQ_LAN_CONF, "w") as f:
        f.write("\n".join(cfg))
    return True, f"Written {DNSMASQ_LAN_CONF}"

def restart_dnsmasq():
    # reload systemd and restart dnsmasq
    try:
        run_cmd("systemctl daemon-reload", check=False)
        run_cmd("systemctl enable --now dnsmasq", check=True)
        return True, "dnsmasq restarted and enabled"
    except subprocess.CalledProcessError as e:
        return False, f"Failed to restart dnsmasq: {e}"

def stop_disable_dnsmasq():
    try:
        run_cmd("systemctl disable --now dnsmasq", check=True)
        return True, "dnsmasq stopped and disabled"
    except subprocess.CalledProcessError as e:
        return False, f"Failed to stop dnsmasq: {e}"

def add_dns_block(domain):
    os.makedirs(DNSMASQ_CONF_DIR, exist_ok=True)
    if not os.path.exists(DNSMASQ_BLOCK_FILE):
        open(DNSMASQ_BLOCK_FILE, "w").close()
    with open(DNSMASQ_BLOCK_FILE, "r") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    e1 = f"address=/{domain}/0.0.0.0"
    e2 = f"address=/www.{domain}/0.0.0.0"
    changed = False
    if e1 not in lines:
        lines.append(e1); changed = True
    if e2 not in lines:
        lines.append(e2); changed = True
    if changed:
        with open(DNSMASQ_BLOCK_FILE, "w") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))
        ok, msg = restart_dnsmasq()
        return ok, msg
    return True, "Already blocked"

def remove_dns_block(domain):
    if not os.path.exists(DNSMASQ_BLOCK_FILE):
        return False, "Block file not found"
    with open(DNSMASQ_BLOCK_FILE, "r") as f:
        lines = [l for l in f.readlines()]
    new = [l for l in lines if domain not in l and f"www.{domain}" not in l]
    with open(DNSMASQ_BLOCK_FILE, "w") as f:
        f.writelines(new)
    ok, msg = restart_dnsmasq()
    return ok, msg

def site_block_hosts(domain):
    hosts = "/etc/hosts"
    with open(hosts, "r") as f:
        content = f.read()
    added = []
    for entry in (f"127.0.0.1 {domain}", f"127.0.0.1 www.{domain}"):
        if entry not in content:
            with open(hosts, "a") as fa:
                fa.write(entry + "\n")
            added.append(entry)
    return True, f"hosts updated: {', '.join(added)}" if added else (True, "already present")

def site_unblock_hosts(domain):
    hosts = "/etc/hosts"
    with open(hosts, "r") as f:
        lines = f.readlines()
    new = [l for l in lines if domain not in l and f"www.{domain}" not in l]
    with open(hosts, "w") as f:
        f.writelines(new)
    return True, "hosts entries removed"

# Force DNS via iptables (drop client attempts to remote DNS)
def force_dns_through_gateway(lan_iface):
    try:
        run_cmd(f"iptables -I FORWARD -i {lan_iface} -p udp --dport 53 -j DROP")
        run_cmd(f"iptables -I FORWARD -i {lan_iface} -p tcp --dport 53 -j DROP")
        return True, "DNS queries from clients blocked; they must use gateway DNS"
    except subprocess.CalledProcessError as e:
        return False, str(e)

def remove_force_dns_rules(lan_iface):
    run_cmd(f"iptables -D FORWARD -i {lan_iface} -p udp --dport 53 -j DROP", check=False)
    run_cmd(f"iptables -D FORWARD -i {lan_iface} -p tcp --dport 53 -j DROP", check=False)
    return True, "DNS forcing rules removed"

# ----------------------
# Read-only viewers
# ----------------------
def view_iptables():
    return run_cmd("iptables -L -v -n", capture=True, check=False)

def view_conntrack():
    return run_cmd("conntrack -L", capture=True, check=False)

# Parsers for display
def parse_iptables_lines(out):
    rows = []
    for line in (out or "").splitlines():
        if not line or line.startswith("Chain") or line.startswith("pkts "):
            continue
        parts = line.split()
        if len(parts) >= 9:
            pkts, bytes_, target, proto, opt, in_if, out_if, src, dst = parts[:9]
            rows.append((src, dst, proto, pkts, bytes_, target, in_if, out_if))
    return rows

def parse_conntrack_lines(out):
    rows = []
    for line in (out or "").splitlines():
        if not line:
            continue
        kv = dict(re.findall(r"(\w+)=(\S+)", line))
        proto = kv.get("proto", "?")
        src = kv.get("src", "?")
        dst = kv.get("dst", "?")
        sport = kv.get("sport", "")
        dport = kv.get("dport", "")
        state = "ESTABLISHED" if "ESTABLISHED" in line else ("TIME_WAIT" if "TIME_WAIT" in line else ("CLOSE" if "CLOSE" in line else "UNKNOWN"))
        dst_display = reverse_dns(dst)
        rows.append((src, f"{dst_display}:{dport}" if dport else dst_display, proto, sport, dport, state))
    return rows

# ----------------------
# Bandwidth counters
# ----------------------
def read_iface_bytes(iface, direction):
    p = f"/sys/class/net/{iface}/statistics/{direction}_bytes"
    try:
        with open(p) as f:
            return int(f.read().strip())
    except Exception:
        return 0

# ----------------------
# GUI
# ----------------------
class NatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        if platform.system() != "Linux":
            messagebox.showerror("Unsupported", "This tool targets Linux (Fedora).")
            self.destroy()
            return

        self.title(APP_TITLE)
        self.geometry("1200x780")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.stop_threads = False

        # variables
        self.wan_var = tk.StringVar(value=DEFAULT_WAN)
        self.lan_var = tk.StringVar(value=DEFAULT_LAN)
        self.refresh_var = tk.DoubleVar(value=1.0)

        # notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=6, pady=6)

        self.tab_rules = ttk.Frame(nb); self.tab_conn = ttk.Frame(nb)
        self.tab_band = ttk.Frame(nb); self.tab_dns = ttk.Frame(nb)
        nb.add(self.tab_rules, text="Rules")
        nb.add(self.tab_conn, text="Connections")
        nb.add(self.tab_band, text="Bandwidth")
        nb.add(self.tab_dns, text="DNS/DHCP")

        self.build_rules_tab()
        self.build_conn_tab()
        self.build_band_tab()
        self.build_dns_tab()

        # start background jobs
        self.after(800, self.start_background)

    def build_rules_tab(self):
        top = ttk.Frame(self.tab_rules); top.pack(fill="x", pady=6)
        ttk.Label(top, text="WAN:").pack(side="left")
        ttk.Entry(top, textvariable=self.wan_var, width=12).pack(side="left", padx=4)
        ttk.Label(top, text="LAN:").pack(side="left")
        ttk.Entry(top, textvariable=self.lan_var, width=12).pack(side="left", padx=4)
        ttk.Button(top, text="Enable NAT + Firewall", command=self.ui_enable_nat).pack(side="left", padx=6)
        ttk.Button(top, text="Disable Firewall", command=self.ui_disable_nat).pack(side="left", padx=6)

        # IP block
        bframe = ttk.Frame(self.tab_rules); bframe.pack(fill="x", pady=6)
        ttk.Label(bframe, text="Block IP:").pack(side="left")
        self.block_entry = ttk.Entry(bframe, width=28); self.block_entry.pack(side="left", padx=4)
        ttk.Button(bframe, text="Block", command=self.ui_block_ip).pack(side="left", padx=4)
        ttk.Button(bframe, text="Unblock", command=self.ui_unblock_ip).pack(side="left", padx=4)

        # site block (dnsmasq/hosts)
        sframe = ttk.Frame(self.tab_rules); sframe.pack(fill="x", pady=6)
        ttk.Label(sframe, text="Block Site (domain):").pack(side="left")
        self.site_entry = ttk.Entry(sframe, width=36); self.site_entry.pack(side="left", padx=4)
        ttk.Button(sframe, text="Block (dnsmasq/hosts)", command=self.ui_block_site).pack(side="left", padx=4)
        ttk.Button(sframe, text="Unblock", command=self.ui_unblock_site).pack(side="left", padx=4)

        # rules tree
        cols = ("Source","Destination","Proto","Packets","Bytes","Action","InIF","OutIF")
        self.rules_tree = ttk.Treeview(self.tab_rules, columns=cols, show="headings", height=12)
        for c in cols:
            self.rules_tree.heading(c, text=c)
            self.rules_tree.column(c, width=140 if c not in ("Destination","Source") else 220)
        self.rules_tree.pack(fill="both", expand=True, pady=6, padx=6)

        ttk.Button(self.tab_rules, text="Refresh Rules", command=self.refresh_rules).pack(pady=4)

        # logs viewer
        ttk.Label(self.tab_rules, text="Kernel firewall logs (journalctl -k -f):").pack()
        self.log_box = scrolledtext.ScrolledText(self.tab_rules, width=160, height=12, font=("Consolas",9))
        self.log_box.pack(padx=6, pady=6)

    def build_conn_tab(self):
        top = ttk.Frame(self.tab_conn); top.pack(fill="x", pady=6)
        ttk.Label(top, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.filter_var, width=36).pack(side="left", padx=4)
        ttk.Button(top, text="Apply", command=self.refresh_conns).pack(side="left", padx=6)

        cols = ("Source","Destination","Proto","SrcPort","DstPort","State")
        self.conn_tree = ttk.Treeview(self.tab_conn, columns=cols, show="headings", height=22)
        for c in cols:
            self.conn_tree.heading(c, text=c)
            self.conn_tree.column(c, width=220 if c in ("Source","Destination") else 100)
        self.conn_tree.pack(fill="both", expand=True, padx=6, pady=6)
        ttk.Button(self.tab_conn, text="Refresh Connections", command=self.refresh_conns).pack(pady=4)

    def build_band_tab(self):
        top = ttk.Frame(self.tab_band); top.pack(fill="x")
        ttk.Label(top, text="Bandwidth monitor (WAN / LAN)").pack(side="left", padx=6)
        ttk.Label(top, text="Refresh sec:").pack(side="left", padx=6)
        ttk.Entry(top, textvariable=self.refresh_var, width=6).pack(side="left", padx=4)
        self.fig = Figure(figsize=(10,4), dpi=100)
        self.ax1 = self.fig.add_subplot(211)
        self.ax2 = self.fig.add_subplot(212)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.tab_band)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        self.wan_rx=[]; self.wan_tx=[]; self.lan_rx=[]; self.lan_tx=[]

    def build_dns_tab(self):
        top = ttk.Frame(self.tab_dns); top.pack(fill="x", pady=6)
        ttk.Label(top, text="dnsmasq / DHCP / DNS Controls").pack(anchor="w")
        frm = ttk.Frame(self.tab_dns); frm.pack(fill="x", pady=6)
        ttk.Label(frm, text="LAN interface:").pack(side="left")
        self.dns_lan_entry = ttk.Entry(frm, width=12); self.dns_lan_entry.insert(0, self.lan_var.get()); self.dns_lan_entry.pack(side="left", padx=4)
        ttk.Button(frm, text="Install dnsmasq", command=self.ui_install_dnsmasq).pack(side="left", padx=4)
        ttk.Button(frm, text="Write LAN config & Restart", command=self.ui_write_restart_dnsmasq).pack(side="left", padx=4)
        ttk.Button(frm, text="Stop & Disable dnsmasq", command=self.ui_stop_dnsmasq).pack(side="left", padx=4)
        ttk.Button(frm, text="Force clients DNS via iptables", command=self.ui_force_dns).pack(side="left", padx=4)
        ttk.Button(frm, text="Remove force-DNS rules", command=self.ui_unforce_dns).pack(side="left", padx=4)

        # show current blocks file
        ttk.Label(self.tab_dns, text="Current dns block entries:").pack(anchor="w", padx=6)
        self.dns_block_box = scrolledtext.ScrolledText(self.tab_dns, width=140, height=18, font=("Consolas",9))
        self.dns_block_box.pack(padx=6, pady=6)
        ttk.Button(self.tab_dns, text="Refresh Blocks", command=self.ui_refresh_blocks).pack(pady=4)

    # ---------------------
    # UI action wrappers (threaded)
    # ---------------------
    def gui_thread(self, fn, on_done=None):
        def worker():
            try:
                res = fn()
                ok = True
            except Exception as e:
                res = str(e)
                ok = False
            if on_done:
                self.after(0, lambda: on_done(ok, res))
            else:
                self.after(0, lambda: messagebox.showinfo("Result" if ok else "Error", str(res)))
        threading.Thread(target=worker, daemon=True).start()

    # NAT controls
    def ui_enable_nat(self):
        if not messagebox.askyesno("Confirm", f"Enable NAT (WAN={self.wan_var.get()}, LAN={self.lan_var.get()})?"):
            return
        self.gui_thread(lambda: enable_nat(self.wan_var.get(), self.lan_var.get()), on_done=lambda ok,res: (messagebox.showinfo("Done", "NAT enabled") if ok else messagebox.showerror("Error", str(res)), self.refresh_rules()))

    def ui_disable_nat(self):
        if not messagebox.askyesno("Confirm", "Clear iptables rules (disable firewall)?"): return
        self.gui_thread(lambda: disable_nat(), on_done=lambda ok,res: (messagebox.showinfo("Done","Cleared") if ok else messagebox.showerror("Error", str(res)), self.refresh_rules()))

    # IP block
    def ui_block_ip(self):
        ip = self.block_entry.get().strip()
        if not ip: messagebox.showwarning("Input","Enter IP"); return
        self.gui_thread(lambda: block_ip(ip), on_done=lambda ok,res: (messagebox.showinfo("Blocked", ip) if ok else messagebox.showerror("Error", str(res)), self.refresh_rules()))

    def ui_unblock_ip(self):
        ip = self.block_entry.get().strip()
        if not ip: messagebox.showwarning("Input","Enter IP"); return
        self.gui_thread(lambda: unblock_ip(ip), on_done=lambda ok,res: (messagebox.showinfo("Unblocked", ip) if ok else messagebox.showerror("Error", str(res)), self.refresh_rules()))

    # site block
    def ui_block_site(self):
        d = self.site_entry.get().strip()
        if not d: messagebox.showwarning("Input","Enter domain"); return
        def job():
            ok, msg = add_dns_block(d)
            if not ok:
                # fallback to hosts
                ok2, msg2 = site_block_hosts(d)
                return ok2, msg2
            return ok, msg
        self.gui_thread(job, on_done=lambda ok,res: (messagebox.showinfo("Blocked", res) if ok else messagebox.showerror("Error", res)))

    def ui_unblock_site(self):
        d = self.site_entry.get().strip()
        if not d: messagebox.showwarning("Input","Enter domain"); return
        def job():
            ok, msg = remove_dns_block(d)
            if not ok:
                ok2, msg2 = site_unblock_hosts(d)
                return ok2, msg2
            return ok, msg
        self.gui_thread(job, on_done=lambda ok,res: (messagebox.showinfo("Unblocked", res) if ok else messagebox.showerror("Error", res)))

    # dns/dhcp actions
    def ui_install_dnsmasq(self):
        self.gui_thread(lambda: install_dnsmasq(), on_done=lambda ok,res: (messagebox.showinfo("Install", res) if ok else messagebox.showerror("Install failed", res)))

    def ui_write_restart_dnsmasq(self):
        lan = self.dns_lan_entry.get().strip() or self.lan_var.get()
        # try to detect gateway ip from interface
        try:
            _, out = run_cmd(f"ip -4 -o addr show {lan} | awk '{{print $4}}' | cut -d/ -f1", capture=True)
            ip = out.strip().splitlines()[0] if out.strip() else GATEWAY_IP
        except Exception:
            ip = GATEWAY_IP
        def job():
            ok, msg = write_dnsmasq_lan_config(lan, ip)
            if not ok: return ok,msg
            return restart_dnsmasq()
        self.gui_thread(job, on_done=lambda ok,res: (messagebox.showinfo("dnsmasq", res) if ok else messagebox.showerror("dnsmasq", res), self.ui_refresh_blocks()))

    def ui_stop_dnsmasq(self):
        if not messagebox.askyesno("Confirm", "Stop and disable dnsmasq?"): return
        self.gui_thread(lambda: stop_disable_dnsmasq(), on_done=lambda ok,res: messagebox.showinfo("dnsmasq", res) if ok else messagebox.showerror("dnsmasq", res))

    def ui_force_dns(self):
        lan = self.dns_lan_entry.get().strip() or self.lan_var.get()
        if not messagebox.askyesno("Confirm", f"Add iptables rules to drop DNS from clients on {lan}? This will force clients to use gateway DNS."): return
        self.gui_thread(lambda: force_dns_through_gateway(lan), on_done=lambda ok,res: messagebox.showinfo("Result", res) if ok else messagebox.showerror("Error", res))

    def ui_unforce_dns(self):
        lan = self.dns_lan_entry.get().strip() or self.lan_var.get()
        self.gui_thread(lambda: remove_force_dns_rules(lan), on_done=lambda ok,res: messagebox.showinfo("Result", res) if ok else messagebox.showerror("Error", res))

    def ui_refresh_blocks(self):
        if os.path.exists(DNSMASQ_BLOCK_FILE):
            with open(DNSMASQ_BLOCK_FILE, "r") as f:
                text = f.read()
        else:
            text = "(no dnsmasq block file)"
        self.dns_block_box.delete(1.0, tk.END); self.dns_block_box.insert(tk.END, text)

    # ---------------------
    # Refreshers (thread-safe updates)
    # ---------------------
    def refresh_rules(self):
        def worker():
            rc, out = view_iptables()
            rows = parse_iptables_lines(out if out else "")
            self.after(0, lambda: self._update_rules_tree(rows))
        threading.Thread(target=worker, daemon=True).start()

    def _update_rules_tree(self, rows):
        for i in self.rules_tree.get_children(): self.rules_tree.delete(i)
        for r in rows:
            self.rules_tree.insert("", tk.END, values=r)

    def refresh_conns(self):
        filt = self.filter_var.get().strip().lower()
        def worker():
            rc, out = view_conntrack()
            rows = parse_conntrack_lines(out if out else "")
            if filt:
                rows = [r for r in rows if filt in r[0].lower() or filt in r[1].lower()]
            self.after(0, lambda: self._update_conn_tree(rows))
        threading.Thread(target=worker, daemon=True).start()

    def _update_conn_tree(self, rows):
        for i in self.conn_tree.get_children(): self.conn_tree.delete(i)
        for r in rows:
            self.conn_tree.insert("", tk.END, values=r)

    # Bandwidth worker
    def _band_worker(self):
        wan = self.wan_var.get().strip()
        lan = self.lan_var.get().strip()
        last = {
            "wan_rx": read_iface_bytes(wan, "rx"),
            "wan_tx": read_iface_bytes(wan, "tx"),
            "lan_rx": read_iface_bytes(lan, "rx"),
            "lan_tx": read_iface_bytes(lan, "tx"),
            "ts": time.time()
        }
        while not self.stop_threads:
            sleep_for = max(MIN_REFRESH, float(self.refresh_var.get()))
            time.sleep(sleep_for)
            now = time.time(); dur = max(1e-6, now - last["ts"])
            cur = {
                "wan_rx": read_iface_bytes(wan, "rx"),
                "wan_tx": read_iface_bytes(wan, "tx"),
                "lan_rx": read_iface_bytes(lan, "rx"),
                "lan_tx": read_iface_bytes(lan, "tx"),
            }
            wan_rx_rate = max(0, cur["wan_rx"] - last["wan_rx"]) / dur
            wan_tx_rate = max(0, cur["wan_tx"] - last["wan_tx"]) / dur
            lan_rx_rate = max(0, cur["lan_rx"] - last["lan_rx"]) / dur
            lan_tx_rate = max(0, cur["lan_tx"] - last["lan_tx"]) / dur

            self.wan_rx.append(wan_rx_rate); self.wan_tx.append(wan_tx_rate)
            self.lan_rx.append(lan_rx_rate); self.lan_tx.append(lan_tx_rate)
            self.wan_rx = self.wan_rx[-120:]; self.wan_tx = self.wan_tx[-120:]
            self.lan_rx = self.lan_rx[-120:]; self.lan_tx = self.lan_tx[-120:]

            self.after(0, self._draw_band)
            last.update(cur); last["ts"] = now

    def _draw_band(self):
        self.ax1.clear(); self.ax2.clear()
        self.ax1.plot(self.wan_rx, label="WAN RX"); self.ax1.plot(self.wan_tx, label="WAN TX"); self.ax1.legend(loc="upper right")
        self.ax2.plot(self.lan_rx, label="LAN RX"); self.ax2.plot(self.lan_tx, label="LAN TX"); self.ax2.legend(loc="upper right")
        self.canvas.draw_idle()

    def start_background(self):
        # logs follower
        def logs_worker():
            try:
                p = subprocess.Popen(["journalctl", "-k", "-f", "-o", "short"], stdout=subprocess.PIPE, text=True)
                while not self.stop_threads:
                    line = p.stdout.readline()
                    if not line:
                        time.sleep(0.1); continue
                    if "FIREWALL:" in line or "NAT:" in line:
                        self.after(0, lambda ln=line: (self.log_box.insert(tk.END, ln), self.log_box.see(tk.END)))
            except Exception as e:
                self.after(0, lambda: self.log_box.insert(tk.END, f"Logs error: {e}\n"))
        threading.Thread(target=logs_worker, daemon=True).start()
        threading.Thread(target=self._band_worker, daemon=True).start()
        # periodic refresh
        def loops():
            while not self.stop_threads:
                self.refresh_rules()
                self.refresh_conns()
                time.sleep(max(MIN_REFRESH, float(self.refresh_var.get())))
        threading.Thread(target=loops, daemon=True).start()

    def on_close(self):
        self.stop_threads = True
        self.destroy()

# ----------------------
# Main
# ----------------------
def main():
    if platform.system() != "Linux":
        print("This tool targets Linux.")
        return
    if not is_root():
        # attempt pkexec relaunch
        try_pkexec_relaunch()
    app = NatApp()
    app.mainloop()

if __name__ == "__main__":
    main()

