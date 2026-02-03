import customtkinter as ctk
from tkinter import filedialog, messagebox
import os, zipfile, base64, threading, time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ================= CONFIG =================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ================= COLORS =================
PRIMARY_PURPLE = "#7C3AED"
HOVER_PURPLE = "#6D28D9"
SOFT_PURPLE = "#A78BFA"
TEXT_COLOR = "#FFFFFF"
BG_COLOR = "#1E1E2F"
CARD_COLOR = "#2C2C3E"

# ================= CRYPTO =================
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def zip_folder(folder_path, zip_name):
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(folder_path):
            for f in files:
                full = os.path.join(root, f)
                z.write(full, os.path.relpath(full, folder_path))

# ================= APP =================
class SecureBackupApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Secure Backup Vault")
        self.geometry("950x550")
        self.resizable(False, False)
        self.configure(fg_color=BG_COLOR)
        self.build_ui()

    def build_ui(self):
        # ===== TITLE =====
        ctk.CTkLabel(
            self,
            text="🔐 Secure Backup Vault",
            font=ctk.CTkFont(size=32, weight="bold"),
            text_color=SOFT_PURPLE
        ).pack(pady=20)

        # ===== TABS =====
        self.tabs = ctk.CTkTabview(self, width=880, height=450, corner_radius=15)
        self.tabs.pack(pady=10)
        self.tabs.add("Encrypt Backup")
        self.tabs.add("Restore Backup")

        self.encrypt_tab()
        self.restore_tab()

    # ================= ENCRYPT TAB =================
    def encrypt_tab(self):
        tab = self.tabs.tab("Encrypt Backup")
        tab.configure(fg_color=CARD_COLOR)

        self.folder_label = ctk.CTkLabel(tab, text="No folder selected", text_color=TEXT_COLOR)
        self.folder_label.pack(pady=10)

        ctk.CTkButton(tab, text="📁 Select Folder", fg_color=PRIMARY_PURPLE, hover_color=HOVER_PURPLE,
                      width=250, command=self.select_folder).pack(pady=5)

        # Password Entry with Eye Toggle
        pass_frame = ctk.CTkFrame(tab, fg_color="transparent")
        pass_frame.pack(pady=10)
        self.enc_pass = ctk.CTkEntry(pass_frame, show="*", placeholder_text="Password", width=260)
        self.enc_pass.pack(side="left", padx=(0,5))
        self.enc_show_pass = False
        def toggle_enc_password():
            self.enc_show_pass = not self.enc_show_pass
            self.enc_pass.configure(show="" if self.enc_show_pass else "*")
        ctk.CTkButton(pass_frame, text="👁️", width=40, height=30, command=toggle_enc_password).pack(side="left")

        ctk.CTkButton(tab, text="🔒 Create Encrypted Backup", fg_color=PRIMARY_PURPLE, hover_color=HOVER_PURPLE,
                      height=50, width=300, command=self.start_encrypt_thread).pack(pady=15)

        # Progress Bar
        self.enc_progress_label = ctk.CTkLabel(tab, text="Progress: 0%", text_color=TEXT_COLOR)
        self.enc_progress_label.pack(pady=5)

        self.enc_progress = ctk.CTkProgressBar(tab, width=400, progress_color=PRIMARY_PURPLE)
        self.enc_progress.set(0)
        self.enc_progress.pack(pady=5)

    def start_encrypt_thread(self):
        thread = threading.Thread(target=self.encrypt_backup)
        thread.start()

    def encrypt_backup(self):
        if not hasattr(self, 'folder') or not self.enc_pass.get():
            messagebox.showerror("Error", "Missing folder or password")
            return

        salt = os.urandom(16)
        key = derive_key(self.enc_pass.get(), salt)
        fernet = Fernet(key)

        zip_name = "temp_backup.zip"
        zip_folder(self.folder, zip_name)

        with open(zip_name, "rb") as f:
            data = f.read()

        encrypted_data = fernet.encrypt(data)

        # simulate progress
        for i in range(101):
            self.enc_progress.set(i/100)
            self.enc_progress_label.configure(text=f"Progress: {i}%")
            self.update()
            time.sleep(0.01)

        with open("secure_backup.enc", "wb") as f:
            f.write(salt + encrypted_data)

        os.remove(zip_name)
        self.enc_progress.set(1.0)
        self.enc_progress_label.configure(text="Progress: 100%")
        messagebox.showinfo("Success", "Encrypted backup created successfully!")

    # ================= RESTORE TAB =================
    def restore_tab(self):
        tab = self.tabs.tab("Restore Backup")
        tab.configure(fg_color=CARD_COLOR)

        self.enc_file_label = ctk.CTkLabel(tab, text="No backup selected", text_color=TEXT_COLOR)
        self.enc_file_label.pack(pady=10)

        ctk.CTkButton(tab, text="📂 Select Backup File", fg_color=PRIMARY_PURPLE, hover_color=HOVER_PURPLE,
                      width=250, command=self.select_enc_file).pack(pady=5)

        # Password Entry with Eye Toggle
        pass_frame = ctk.CTkFrame(tab, fg_color="transparent")
        pass_frame.pack(pady=10)
        self.dec_pass = ctk.CTkEntry(pass_frame, show="*", placeholder_text="Password", width=260)
        self.dec_pass.pack(side="left", padx=(0,5))
        self.dec_show_pass = False
        def toggle_dec_password():
            self.dec_show_pass = not self.dec_show_pass
            self.dec_pass.configure(show="" if self.dec_show_pass else "*")
        ctk.CTkButton(pass_frame, text="👁️", width=40, height=30, command=toggle_dec_password).pack(side="left")

        ctk.CTkButton(tab, text="🔓 Restore Backup", fg_color=PRIMARY_PURPLE, hover_color=HOVER_PURPLE,
                      height=50, width=300, command=self.start_restore_thread).pack(pady=15)

        # Progress Bar
        self.dec_progress_label = ctk.CTkLabel(tab, text="Progress: 0%", text_color=TEXT_COLOR)
        self.dec_progress_label.pack(pady=5)

        self.dec_progress = ctk.CTkProgressBar(tab, width=400, progress_color=PRIMARY_PURPLE)
        self.dec_progress.set(0)
        self.dec_progress.pack(pady=5)

    def start_restore_thread(self):
        thread = threading.Thread(target=self.restore_backup)
        thread.start()

    # ================= SELECTORS =================
    def select_folder(self):
        self.folder = filedialog.askdirectory()
        if self.folder:
            self.folder_label.configure(text=self.folder)

    def select_enc_file(self):
        self.enc_file = filedialog.askopenfilename(filetypes=[("Encrypted Backup", "*.enc")])
        if self.enc_file:
            self.enc_file_label.configure(text=self.enc_file)

    # ================= RESTORE FUNCTION =================
    def restore_backup(self):
        if not hasattr(self, 'enc_file') or not self.dec_pass.get():
            messagebox.showerror("Error", "Missing file or password")
            return

        with open(self.enc_file, "rb") as f:
            data = f.read()

        salt, encrypted = data[:16], data[16:]
        key = derive_key(self.dec_pass.get(), salt)
        fernet = Fernet(key)

        try:
            decrypted_data = fernet.decrypt(encrypted)
        except Exception:
            messagebox.showerror("Error", "Wrong password or corrupted file")
            return

        # simulate progress
        for i in range(101):
            self.dec_progress.set(i/100)
            self.dec_progress_label.configure(text=f"Progress: {i}%")
            self.update()
            time.sleep(0.01)

        with open("restored.zip", "wb") as f:
            f.write(decrypted_data)

        with zipfile.ZipFile("restored.zip", 'r') as z:
            z.extractall("restored_files")

        self.dec_progress.set(1.0)
        self.dec_progress_label.configure(text="Progress: 100%")
        messagebox.showinfo("Success", "Backup restored to folder: 'restored_files'")

# ================= RUN =================
if __name__ == "__main__":
    app = SecureBackupApp()
    app.mainloop()
