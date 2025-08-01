import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess

SCRIPT_PATH = "./fortigate_cis_audit.sh"  # Make sure the path is correct

def run_script():
    ip = ip_entry.get()
    port = port_entry.get()
    user = user_entry.get()
    pwd = pwd_entry.get()

    if not all([ip, port, user, pwd]):
        messagebox.showerror("Error", "All fields are required.")
        return

    cmd = ["bash", SCRIPT_PATH, ip, port, user, pwd]

    try:
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Starting CIS Audit on {ip}...\n\n")

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        for line in process.stdout:
            output_text.insert(tk.END, line)
            output_text.see(tk.END)
            output_text.update()

        process.wait()
        output_text.insert(tk.END, "\n\nAudit Completed.")

    except Exception as e:
        messagebox.showerror("Execution Error", str(e))

# GUI Setup
root = tk.Tk()
root.title("Fortigate CIS Audit Tool")

tk.Label(root, text="Firewall IP:").grid(row=0, column=0, sticky="e")
ip_entry = tk.Entry(root, width=30)
ip_entry.grid(row=0, column=1)

tk.Label(root, text="Port:").grid(row=1, column=0, sticky="e")
port_entry = tk.Entry(root, width=30)
port_entry.grid(row=1, column=1)

tk.Label(root, text="Username:").grid(row=2, column=0, sticky="e")
user_entry = tk.Entry(root, width=30)
user_entry.grid(row=2, column=1)

tk.Label(root, text="Password:").grid(row=3, column=0, sticky="e")
pwd_entry = tk.Entry(root, width=30, show="*")
pwd_entry.grid(row=3, column=1)

tk.Button(root, text="Run Audit", command=run_script).grid(row=4, column=1, pady=10)

output_text = scrolledtext.ScrolledText(root, width=80, height=20)
output_text.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()


