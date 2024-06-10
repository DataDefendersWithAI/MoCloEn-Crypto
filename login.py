import tkinter as tk
from tkinter import messagebox
import subprocess
from client_sample2 import register_check, login_check, key_exchange
import base64

aes_key = key_exchange()

def on_login():
    phone_number = phone_number_entry.get()
    password = password_entry.get()
    login = login_check(phone_number, password, aes_key)
    if login['status']:
        jwt = login['jwt']
        messagebox.showinfo("Login Info", f"Login successful for {phone_number}")
        root.destroy()
        subprocess.run(['python', 'transaction.py', phone_number, base64.b64encode(aes_key), jwt])
    else:
        messagebox.showerror("Error", "Invalid username or password")

def open_register():
    register_window = tk.Toplevel(root)
    register_window.title("Register")

    def on_register():
        username = reg_username_entry.get()
        phone = reg_phone_entry.get()
        password1 = reg_password1_entry.get()
        password2 = reg_password2_entry.get()

        if password1 == password2 and register_check(username, phone, password1, aes_key):
            messagebox.showinfo("Registration Info", "User registered successfully")
            register_window.destroy()
        else:
            messagebox.showerror("Error", "Passwords do not match")

    # Configure grid layout for the registration window
    register_window.grid_rowconfigure(0, weight=1)
    register_window.grid_rowconfigure(1, weight=1)
    register_window.grid_rowconfigure(2, weight=1)
    register_window.grid_rowconfigure(3, weight=1)
    register_window.grid_rowconfigure(4, weight=1)
    register_window.grid_rowconfigure(5, weight=1)
    register_window.grid_columnconfigure(0, weight=1)
    register_window.grid_columnconfigure(1, weight=1)

    # Create and place the registration form widgets
    reg_username_label = tk.Label(register_window, text="Username")
    reg_username_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
    reg_username_entry = tk.Entry(register_window)
    reg_username_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    reg_phone_label = tk.Label(register_window, text="Phone Number")
    reg_phone_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
    reg_phone_entry = tk.Entry(register_window)
    reg_phone_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

    reg_password1_label = tk.Label(register_window, text="Password")
    reg_password1_label.grid(row=2, column=0, padx=10, pady=10, sticky="e")
    reg_password1_entry = tk.Entry(register_window, show="*")
    reg_password1_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

    reg_password2_label = tk.Label(register_window, text="Confirm Password")
    reg_password2_label.grid(row=3, column=0, padx=10, pady=10, sticky="e")
    reg_password2_entry = tk.Entry(register_window, show="*")
    reg_password2_entry.grid(row=3, column=1, padx=10, pady=10, sticky="ew")

    register_button = tk.Button(register_window, text="Register", command=on_register)
    register_button.grid(row=4, column=0, columnspan=2, pady=20)

    # Make the entries stretch with the window
    register_window.grid_columnconfigure(1, weight=1)

# Create the main window
root = tk.Tk()
root.title("Login Form")

# Configure grid layout to make it stretchable
root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)
root.grid_rowconfigure(2, weight=1)
root.grid_rowconfigure(3, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)

# Create and place the username label and entry
phone_number_label = tk.Label(root, text="Phone Number")
phone_number_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
phone_number_entry = tk.Entry(root)
phone_number_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

# Create and place the password label and entry
password_label = tk.Label(root, text="Password")
password_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
password_entry = tk.Entry(root, show="*")
password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

# Create and place the login button
login_button = tk.Button(root, text="Login", command=on_login)
login_button.grid(row=2, column=0, columnspan=2, pady=20)

# Create and place the register button
register_button = tk.Button(root, text="Register", command=open_register)
register_button.grid(row=3, column=0, columnspan=2, pady=20)

# Make the entries stretch with the window
root.grid_columnconfigure(1, weight=1)

# Run the application
root.mainloop()
