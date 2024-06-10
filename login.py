import tkinter as tk
from tkinter import messagebox
from client_sample2 import register_check, login_check, key_exchange, create_transac_check
import base64

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Login Form")
        self.geometry("600x300")
        self.aes_key = key_exchange()
        self.user_phone = None
        self.jwt = None
        self.create_login_form()

    def create_login_form(self):
        for widget in self.winfo_children():
            widget.destroy()

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        phone_number_label = tk.Label(self, text="Phone Number")
        phone_number_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.phone_number_entry = tk.Entry(self)
        self.phone_number_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        password_label = tk.Label(self, text="Password")
        password_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        login_button = tk.Button(self, text="Login", command=self.on_login)
        login_button.grid(row=2, column=0, columnspan=2, pady=20)

        register_button = tk.Button(self, text="Register", command=self.open_register)
        register_button.grid(row=3, column=0, columnspan=2, pady=20)

        self.grid_columnconfigure(1, weight=1)

    def on_login(self):
        phone_number = self.phone_number_entry.get()
        password = self.password_entry.get()
        login = login_check(phone_number, password, self.aes_key)
        if login['status']:
            self.jwt = login['jwt']
            self.user_phone = phone_number
            messagebox.showinfo("Login Info", f"Login successful for {phone_number}")
            self.create_transaction_form()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def open_register(self):
        register_window = tk.Toplevel(self)
        register_window.title("Register")

        def on_register():
            username = reg_username_entry.get()
            phone = reg_phone_entry.get()
            password1 = reg_password1_entry.get()
            password2 = reg_password2_entry.get()

            if password1 == password2 and register_check(username, phone, password1, self.aes_key):
                messagebox.showinfo("Registration Info", "User registered successfully")
                register_window.destroy()
            else:
                messagebox.showerror("Error", "Passwords do not match")

        register_window.grid_rowconfigure(0, weight=1)
        register_window.grid_rowconfigure(1, weight=1)
        register_window.grid_rowconfigure(2, weight=1)
        register_window.grid_rowconfigure(3, weight=1)
        register_window.grid_rowconfigure(4, weight=1)
        register_window.grid_rowconfigure(5, weight=1)
        register_window.grid_columnconfigure(0, weight=1)
        register_window.grid_columnconfigure(1, weight=1)

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

        register_window.grid_columnconfigure(1, weight=1)

    def create_transaction_form(self):
        for widget in self.winfo_children():
            widget.destroy()

        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        phone_label = tk.Label(self, text="Receiver's Phone Number")
        phone_label.grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.phone_entry = tk.Entry(self)
        self.phone_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        use_own_phone_button = tk.Button(self, text="Use Own Phone", command=self.use_own_phone)
        use_own_phone_button.grid(row=0, column=2, padx=10, pady=10)

        amount_label = tk.Label(self, text="Amount to Transact")
        amount_label.grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.amount_entry = tk.Entry(self)
        self.amount_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        transact_button = tk.Button(self, text="Transact", command=self.on_transact)
        transact_button.grid(row=2, column=0, columnspan=3, pady=20)

        logout_button = tk.Button(self, text="Logout", command=self.on_logout)
        logout_button.grid(row=3, column=0, columnspan=3, pady=10)

        self.grid_columnconfigure(1, weight=1)

    def on_transact(self):
        receiver_phone = self.phone_entry.get()
        amount = self.amount_entry.get()
        status = create_transac_check(self.jwt, receiver_phone, int(amount), self.aes_key)
        print(status)
        messagebox.showinfo("Transaction Info", f"Transaction to {receiver_phone} of amount {amount} with status {status} successful")

    def use_own_phone(self):
        self.phone_entry.delete(0, tk.END)
        self.phone_entry.insert(0, self.user_phone)

    def on_logout(self):
        self.create_login_form()

if __name__ == "__main__":
    app = Application()
    app.mainloop()
