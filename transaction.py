import tkinter as tk
from tkinter import messagebox
import sys
import subprocess
from client_sample2 import create_transac_check
import base64

# Extract the passed username and phone number
user_phone = sys.argv[1]
aes_key = base64.b64decode(sys.argv[2])
jwt = sys.argv[3]

def on_logout():
    root.destroy()
    subprocess.run(['python', 'login.py'])

def on_transact():
    receiver_phone = phone_entry.get()
    amount = amount_entry.get()
    status = create_transac_check(jwt, receiver_phone, amount, aes_key)
    print(status)
    
    messagebox.showinfo("Transaction Info", f"Transaction to {receiver_phone} of amount {amount} with status {status} successful")

def use_own_phone():
    phone_entry.delete(0, tk.END)
    phone_entry.insert(0, user_phone)



# Create the main window
root = tk.Tk()
root.title("Transaction Form")

# Configure grid layout to make it stretchable
root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)
root.grid_rowconfigure(2, weight=1)
root.grid_rowconfigure(3, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

# Create and place the phone number label and entry
phone_label = tk.Label(root, text="Receiver's Phone Number")
phone_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
phone_entry = tk.Entry(root)
phone_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

# Create and place the button to use user's phone number
use_own_phone_button = tk.Button(root, text="Use Own Phone", command=use_own_phone)
use_own_phone_button.grid(row=0, column=2, padx=10, pady=10)

# Create and place the amount label and entry
amount_label = tk.Label(root, text="Amount to Transact")
amount_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
amount_entry = tk.Entry(root)
amount_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

# Create and place the transact button
transact_button = tk.Button(root, text="Transact", command=on_transact)
transact_button.grid(row=2, column=0, columnspan=3, pady=20)

# Create and place the logout button
logout_button = tk.Button(root, text="Logout", command=on_logout)
logout_button.grid(row=3, column=0, columnspan=3, pady=10)

# Make the entries stretch with the window
root.grid_columnconfigure(1, weight=1)

# Run the application
root.mainloop()
