import socket
import ipaddress
import yaml
import subprocess
import platform
from threading import Lock, Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Globals
succeed_ips = []
failed_ips = []
all_results = []
lock = Lock()

# --- Networking Functions ---
def icmp_ping(ip, ping_count=1, timeout=10):
    param_count = "-n" if platform.system().lower() == "windows" else "-c"
    param_timeout = "-w" if platform.system().lower() == "windows" else "-W"
    try:
        result = subprocess.run(
            ["ping", param_count, str(ping_count), param_timeout, str(timeout), ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except:
        return False

def tcp_probe(ip, port, timeout=10):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except:
        return False

def udp_probe(ip, port, timeout=10):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"Test", (ip, port))
        sock.recvfrom(1024)
        sock.close()
        return True
    except:
        return False

# --- Config / Parsing ---
def load_config():
    path = filedialog.askopenfilename(title="Select YAML config", filetypes=[("YAML files","*.yml;*.yaml")])
    if path:
        try:
            with open(path, "r") as f:
                cfg = yaml.safe_load(f)
            ip_ranges_var.set(", ".join(cfg.get("ip_ranges", [])))
            gateways_var.set(", ".join(cfg.get("gateways", [])))
            tcp_ports_var.set(", ".join(str(p) for p in cfg.get("tcp_ports", [])))
            udp_ports_var.set(", ".join(str(p) for p in cfg.get("udp_ports", [])))
            timeout_var.set(str(cfg.get("timeout", 10)))
            ping_count_var.set(str(cfg.get("ping_count", 1)))
            threads_var.set(str(cfg.get("threads", 20)))
            messagebox.showinfo("Success", "Config loaded!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load config:\n{e}")

def parse_csv(input_str):
    return [x.strip() for x in input_str.split(",") if x.strip()]

# --- Scanning ---
def scan_and_update(ip, tcp_ports, udp_ports, gateways, tree):
    if ip in gateways:
        return None
    values = [ip, "Pending"] + ["-"]* (len(tcp_ports) + len(udp_ports))
    iid = tree.insert("", "end", values=values)

    alive = icmp_ping(ip)
    tcp_status = {port: tcp_probe(ip, port) for port in tcp_ports} if alive else {}
    udp_status = {port: udp_probe(ip, port) for port in udp_ports} if alive else {}

    with lock:
        if alive:
            succeed_ips.append(ip)
        else:
            failed_ips.append(ip)
        all_results.append({
            "IP": ip,
            "Status": "Online" if alive else "Offline",
            **{f"TCP {p}": "Open" if tcp_status.get(p) else "Closed" for p in tcp_ports},
            **{f"UDP {p}": "Open" if udp_status.get(p) else "Closed" for p in udp_ports}
        })

    new_values = [ip, "Online" if alive else "Offline"] + \
                 ["Open" if tcp_status.get(p) else "Closed" for p in tcp_ports] + \
                 ["Open" if udp_status.get(p) else "Closed" for p in udp_ports]

    tree.after(0, lambda: tree.item(iid, values=new_values))

def start_scan_thread():
    Thread(target=start_scan, daemon=True).start()

def start_scan():
    succeed_ips.clear()
    failed_ips.clear()
    all_results.clear()
    tree.delete(*tree.get_children())

    try:
        ip_ranges = parse_csv(ip_ranges_var.get())
        gateways = set(parse_csv(gateways_var.get()))
        tcp_ports = [int(p) for p in parse_csv(tcp_ports_var.get())]
        udp_ports = [int(p) for p in parse_csv(udp_ports_var.get())]
        timeout = int(timeout_var.get())
        ping_count = int(ping_count_var.get())
        threads = int(threads_var.get())
    except Exception as e:
        messagebox.showerror("Error", f"Invalid input:\n{e}")
        return

    all_ips = [str(ip) for ip_range in ip_ranges for ip in ipaddress.IPv4Network(ip_range).hosts()]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_and_update, ip, tcp_ports, udp_ports, gateways, tree) for ip in all_ips]
        for future in as_completed(futures):
            future.result()

    with open("online-ip.txt", "w") as f:
        for ip in succeed_ips:
            f.write(ip + "\n")
    with open("offline-ip.txt", "w") as f:
        for ip in failed_ips:
            f.write(ip + "\n")
    messagebox.showinfo("Scan Complete", f"Scan finished!\nOnline: {len(succeed_ips)}\nOffline: {len(failed_ips)}")

# --- Treeview Sorting & Filter ---
def sort_tree(tree, col, reverse):
    l = [(tree.set(k, col), k) for k in tree.get_children('')]
    try:
        l.sort(key=lambda t: int(t[0].split('.')[-1]), reverse=reverse)
    except:
        l.sort(reverse=reverse)
    for index, (val, k) in enumerate(l):
        tree.move(k, '', index)
    tree.heading(col, command=lambda: sort_tree(tree, col, not reverse))

def apply_filter(*args):
    status_filter = filter_var.get()
    tree.delete(*tree.get_children())
    for row in all_results:
        if status_filter == "All" or row["Status"] == status_filter:
            tree.insert("", "end", values=[row["IP"], row["Status"]])

# --- Right-click Context Menu ---
def show_context_menu(event):
    iid = tree.identify_row(event.y)
    if iid:
        tree.selection_set(iid)
        context_menu.tk_popup(event.x_root, event.y_root)

def copy_selected_ips():
    selected = [tree.item(iid)["values"][0] for iid in tree.selection()]
    if selected:
        root.clipboard_clear()
        root.clipboard_append("\n".join(selected))
        messagebox.showinfo("Copied", f"{len(selected)} IP(s) copied to clipboard!")

def show_context_menu(event):
    iid = tree.identify_row(event.y)
    if iid:
        tree.selection_set(iid)
    context_menu.tk_popup(event.x_root, event.y_root)

def copy_selected_ips(event=None):
    selected = [tree.item(iid)["values"][0] for iid in tree.selection()]
    if selected:
        root.clipboard_clear()
        root.clipboard_append("\n".join(selected))
        if event is None:  # only show messagebox for right-click
            messagebox.showinfo("Copied", f"{len(selected)} IP(s) copied to clipboard!")
    return "break"

def select_all_ips(event=None):
    tree.selection_set(tree.get_children())
    return "break"


# --- GUI Layout ---
root = tk.Tk()
root.title("Network Scanner GUI")
root.geometry("900x500")

# Config inputs
frame = tk.Frame(root)
frame.pack(padx=10, pady=5, fill="x")

ip_ranges_var = tk.StringVar()
gateways_var = tk.StringVar()
tcp_ports_var = tk.StringVar()
udp_ports_var = tk.StringVar()
timeout_var = tk.StringVar()
ping_count_var = tk.StringVar()
threads_var = tk.StringVar()
filter_var = tk.StringVar(value="All")

tk.Button(frame, text="Load Config", command=load_config).grid(row=0, column=0, padx=5, pady=2)
tk.Label(frame, text="IP Ranges").grid(row=1, column=0)
tk.Entry(frame, textvariable=ip_ranges_var, width=50).grid(row=1, column=1, columnspan=3)
tk.Label(frame, text="Gateways").grid(row=2, column=0)
tk.Entry(frame, textvariable=gateways_var, width=50).grid(row=2, column=1, columnspan=3)
tk.Label(frame, text="TCP Ports").grid(row=3, column=0)
tk.Entry(frame, textvariable=tcp_ports_var, width=50).grid(row=3, column=1, columnspan=3)
tk.Label(frame, text="UDP Ports").grid(row=4, column=0)
tk.Entry(frame, textvariable=udp_ports_var, width=50).grid(row=4, column=1, columnspan=3)
tk.Label(frame, text="Timeout").grid(row=5, column=0)
tk.Entry(frame, textvariable=timeout_var, width=10).grid(row=5, column=1)
tk.Label(frame, text="Ping Count").grid(row=5, column=2)
tk.Entry(frame, textvariable=ping_count_var, width=10).grid(row=5, column=3)
tk.Label(frame, text="Threads").grid(row=6, column=0)
tk.Entry(frame, textvariable=threads_var, width=10).grid(row=6, column=1)
tk.Button(frame, text="Start Scan", command=start_scan_thread).grid(row=7, column=0, columnspan=4, pady=5)

# Filter
filter_frame = tk.Frame(root)
filter_frame.pack(pady=5)
tk.Label(filter_frame, text="Filter:").pack(side="left")
filter_menu = ttk.OptionMenu(filter_frame, filter_var, "All", "All", "Online", "Offline", command=apply_filter)
filter_menu.pack(side="left", padx=5)

# Results Treeview
cols = ["IP", "Status"]
tree = ttk.Treeview(root, columns=cols, show="headings", selectmode="extended")
tree.heading("IP", text="IP", command=lambda: sort_tree(tree, "IP", False))
tree.heading("Status", text="Status", command=lambda: sort_tree(tree, "Status", False))
tree.pack(padx=10, pady=10, fill="both", expand=True)

# Right-click context menu
context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Copy Selected", command=copy_selected_ips)
tree.bind("<Button-3>", show_context_menu)
tree.bind("<Control-Button-1>", show_context_menu)  # macOS Ctrl+Click

# Bind Ctrl+A and Ctrl+C
tree.bind("<Control-a>", select_all_ips)
tree.bind("<Control-A>", select_all_ips)
tree.bind("<Control-c>", copy_selected_ips)
tree.bind("<Control-C>", copy_selected_ips)

# Right-click context menu
context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Copy Selected", command=copy_selected_ips)
tree.bind("<Button-3>", show_context_menu)
tree.bind("<Control-Button-1>", show_context_menu)  # macOS Ctrl+Click

root.mainloop()
