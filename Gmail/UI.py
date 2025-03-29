import tkinter as tk
from tkinter import ttk

# Global variables
global window, email_tree, detail_frame, status_label, body_text

def init_UI():
    global window
    window = tk.Tk()
    window.title('Phishing Detector')
    window.geometry('1280x720')
    create_scrollable_listbox()
    window.mainloop()

def create_scrollable_listbox():
    global email_tree, detail_frame, status_label, body_text
    
    # Configure main window grid
    window.grid_rowconfigure(0, weight=1)  # Top half
    window.grid_rowconfigure(1, weight=1)  # Bottom half
    window.grid_columnconfigure(0, weight=1)
    
    # Create top detail frame
    detail_frame = tk.Frame(window, bg="lightgray")
    detail_frame.grid(row=0, column=0, sticky="nsew")
    
    # Create detail widgets
    detail_frame.grid_columnconfigure(1, weight=1)
    tk.Label(detail_frame, text="Sender:", bg="lightgray", anchor="e").grid(row=0, column=0, sticky="e", padx=5, pady=2)
    sender_label = tk.Label(detail_frame, bg="white", anchor="w")
    sender_label.grid(row=0, column=1, sticky="ew", padx=5, pady=2)
    
    tk.Label(detail_frame, text="Subject:", bg="lightgray", anchor="e").grid(row=1, column=0, sticky="e", padx=5, pady=2)
    subject_label = tk.Label(detail_frame, bg="white", anchor="w")
    subject_label.grid(row=1, column=1, sticky="ew", padx=5, pady=2)
    
    tk.Label(detail_frame, text="Status:", bg="lightgray", anchor="e").grid(row=2, column=0, sticky="e", padx=5, pady=2)
    status_label = tk.Label(detail_frame, bg="white", anchor="w")
    status_label.grid(row=2, column=1, sticky="ew", padx=5, pady=2)
    
    tk.Label(detail_frame, text="Body:", bg="lightgray", anchor="e").grid(row=3, column=0, sticky="ne", padx=5, pady=2)
    body_text = tk.Text(detail_frame, wrap=tk.WORD, height=10)
    body_text.grid(row=3, column=1, sticky="nsew", padx=5, pady=2)
    
    # Create scrollbar for body text
    body_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=body_text.yview)
    body_text.configure(yscrollcommand=body_scroll.set)
    body_scroll.grid(row=3, column=2, sticky="ns")
    
    # Configure detail frame grid
    detail_frame.grid_rowconfigure(3, weight=1)
    
    # Create bottom list frame
    bottom_frame = tk.Frame(window)
    bottom_frame.grid(row=1, column=0, sticky="nsew")
    
    # Configure Treeview style
    style = ttk.Style()
    style.configure("Bordered.Treeview",
        background="white",
        fieldbackground="white",
        font=('Arial', 12),
        rowheight=35,
        padding=(10, 5),
        bordercolor="#CCCCCC",
        lightcolor="#CCCCCC",
        darkcolor="#CCCCCC"
    )

    # Create Treeview
    email_tree = ttk.Treeview(
        bottom_frame,
        style="Bordered.Treeview",
        columns=("email", "subject", "status"),
        show="headings",
        selectmode="browse"
    )

    # Configure columns
    email_tree.column("#0", width=0, stretch=False)
    email_tree.column("email", anchor="w", width=200)
    email_tree.column("subject", anchor="w", width=600)
    email_tree.column("status", anchor="center", width=100)
    
    # Configure headings
    email_tree.heading("email", text="Sender Email")
    email_tree.heading("subject", text="Subject")
    email_tree.heading("status", text="Status")

    # Add scrollbar
    scrollbar = ttk.Scrollbar(bottom_frame, orient="vertical", command=email_tree.yview)
    email_tree.configure(yscrollcommand=scrollbar.set)
    
    # Grid layout
    email_tree.grid(row=0, column=0, sticky="nsew")
    scrollbar.grid(row=0, column=1, sticky="ns")
    
    # Configure grid weights
    bottom_frame.grid_rowconfigure(0, weight=1)
    bottom_frame.grid_columnconfigure(0, weight=1)

    # Add sample data
    email_data = []
    for i in range(15):
        email = f"sender{i}@example.com"
        subject = f"Urgent: Account Verification Required - Case #{i}"
        status = "⚠️ Phishing" if i % 3 == 0 else "✅ Safe"
        body = f"""Dear User,

This is regarding your account ({email}).

{subject}

Please click the link below to verify your credentials:
http://phishing-example.com/verify?id={i}

Best regards,
Support Team"""
        email_data.append((email, subject, status, body))
        email_tree.insert("", "end", values=(email, subject, status))

    # Bind selection event
    email_tree.bind("<<TreeviewSelect>>", lambda e: show_email_details(email_data))

def add_email(email_data):
    #email_data.append((email, subject, status, body))
    #email_tree.insert("", "end", values=(email, subject, status))
    pass





def show_email_details(email_data):
    selected = email_tree.selection()
    if not selected:
        return
    
    item = email_tree.item(selected[0])
    index = email_tree.index(selected[0])
    email, subject, status = item['values']
    body = email_data[index][3]
    
    # Update sender label
    detail_frame.grid_slaves(row=0, column=1)[0].config(text=email)
    # Update subject label
    detail_frame.grid_slaves(row=1, column=1)[0].config(text=subject)
    # Update status label
    status_label.config(text=status, 
                      bg="#FFCCCC" if "Phishing" in status else "#CCFFCC",
                      fg="red" if "Phishing" in status else "green")
    # Update body text
    body_text.config(state=tk.NORMAL)
    body_text.delete(1.0, tk.END)
    body_text.insert(tk.END, body)
    body_text.config(state=tk.DISABLED)

