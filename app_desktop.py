
import customtkinter as ctk
from scanner import auto_scan
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")
app = ctk.CTk()
app.geometry("650x480")
app.title("PhishGuard - Desktop")
ctk.CTkLabel(app, text="🛡️ PhishGuard Desktop", font=("Arial", 22, "bold")).pack(pady=20)
ctk.CTkLabel(app, text="Auto-detects URL / Email / Hash + VirusTotal + Neon").pack()
entry = ctk.CTkEntry(app, width=520, height=45, placeholder_text="Paste URL, Email or Hash here...")
entry.pack(pady=20)
result_label = ctk.CTkLabel(app, text="", font=("Arial", 14), wraplength=520, justify="left")
result_label.pack(pady=20)
def do_scan():
    val = entry.get().strip()
    if not val:
        result_label.configure(text="Please enter a value"); return
    result_label.configure(text="Scanning with VirusTotal...", text_color="white")
    app.update()
    data = auto_scan(val)
    if "error" in data and "type" not in data:
        result_label.configure(text=f"Error: {data['error']}", text_color="red")
    elif data.get("error"):
        result_label.configure(text=f"VT Error: {data['vt_raw'].get('error')}", text_color="orange")
    else:
        color = {"clean":"#16a34a", "malicious":"#dc2626", "suspicious":"#f59e0b", "error":"orange"}[data["status"]]
        result_label.configure(text_color=color, text=f"Type: {data['type']}\nStatus: {data['status'].upper()}\nVirusTotal: {data['malicious']} / {data['total']} engines malicious")
ctk.CTkButton(app, text="Scan Now", height=42, command=do_scan).pack(pady=10)
app.mainloop()
