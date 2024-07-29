import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP
from threading import Thread
from datetime import datetime

sniffer_thread = None
is_sniffing = False

def update_text_area(text_area, text):
    text_area.insert(tk.END, text + "\n")
    text_area.see(tk.END)

def stop_filter(x):
    return not is_sniffing

def packet_callback(packet, text_area):
    if IP in packet:
        src_ip =packet[IP].src
        dst_ip=packet[IP].dst
        proto=packet[IP].proto
        payload=packet[IP].payload

        if proto==6:
            protocol="TCP"
        elif proto==17:
            protocol="UDP"
        else:
            protocol="Other"

        payload_summary = payload.summary()

        packet_info=f"Timestamp: {datetime.now()}\n" \
                    f"Source IP: {src_ip}\n" \
                    f"Destination IP: {dst_ip}\n" \
                    f"Protocol: {protocol}\n" \
                    f"Payload: {payload_summary}\n" \
                    f"{'='*65}"
        
        update_text_area(text_area, packet_info)

def start_sniffer(text_area):
    global is_sniffing, sniffer_thread
    if not is_sniffing:
        is_sniffing=True
        sniffer_thread=Thread(target=lambda: sniff(prn=lambda packet: packet_callback(packet, text_area), stop_filter=stop_filter, store=False))
        sniffer_thread.start()
        update_text_area(text_area, "Network sniffer started...")

def stop_sniffer(text_area):
    global is_sniffing
    if is_sniffing:
        is_sniffing=False
        sniffer_thread.join(timeout=1)
        update_text_area(text_area, "Network sniffer stopped...")

def create_gui():
    root=tk.Tk()
    root.title("Network Sniffer")
    root.configure(bg='black')
    start_button=tk.Button(root, text="Start Sniffer", command=lambda: start_sniffer(text_area), fg="white", bg="black")
    start_button.pack(pady=5)
    stop_button=tk.Button(root, text="Stop Sniffer", command=lambda: stop_sniffer(text_area), fg="white", bg="black")
    stop_button.pack(pady=5)
    text_area=scrolledtext.ScrolledText(root, width=100, height=30, fg="white", bg="black")
    text_area.pack(pady=10)
    root.mainloop()
create_gui()
