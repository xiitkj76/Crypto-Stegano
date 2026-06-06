
import os
import pickle
import hashlib
import struct
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

from PIL import Image
import numpy as np

# =========================================================
# HASH SHA256
# =========================================================
def hash_sha256(data):
    return hashlib.sha256(data).digest()

def hash_sha256_object(data):
    h = SHA256.new()
    h.update(data)
    return h

# =========================================================
# AES
# =========================================================
def aes_encrypt(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    padded_data = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)

    return iv + ciphertext

def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_padded = cipher.decrypt(ciphertext)

    return unpad(decrypted_padded, AES.block_size)

# =========================================================
# RSA
# =========================================================
def generate_rsa_keypair():
    key = RSA.generate(2048)
    return key.publickey().export_key(), key.export_key()

def rsa_encrypt_key(aes_key, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(aes_key)

def rsa_decrypt_key(encrypted_aes_key, private_key_pem):
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_aes_key)

# =========================================================
# DSA
# =========================================================
def generate_dsa_keypair():
    key = DSA.generate(2048)
    return key.publickey().export_key(), key.export_key()

def sign_message(message, private_key_pem):
    private_key = DSA.import_key(private_key_pem)
    hash_obj = hash_sha256_object(message)
    signer = DSS.new(private_key, 'fips-186-3')
    return signer.sign(hash_obj)

def verify_signature(message, signature, public_key_pem):
    public_key = DSA.import_key(public_key_pem)
    hash_obj = hash_sha256_object(message)
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        return True
    except:
        return False

# =========================================================
# DIFFIE-HELLMAN (2048-bit)
# =========================================================

# Parameter standar Diffie-Hellman (RFC 3526 - grup 14 2048-bit)
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
DH_G = 2

def generate_dh_keypair():
    """Generate pasangan kunci Diffie-Hellman"""
    private_key = int.from_bytes(get_random_bytes(32), 'big') % (DH_P - 1)
    public_key = pow(DH_G, private_key, DH_P)
    return private_key, public_key

def compute_shared_secret(private_key, other_public_key):
    """Hitung shared secret dari kunci publik pihak lain"""
    shared = pow(other_public_key, private_key, DH_P)
    byte_length = (DH_P.bit_length() + 7) // 8
    return shared.to_bytes(byte_length, 'big')

def derive_aes_key_from_dh(shared_secret):
    """Derive AES key dari shared secret DH menggunakan SHA256"""
    return hash_sha256(shared_secret)[:32]  # 32 bytes untuk AES-256

# =========================================================
# STEGANOGRAFI LSB
# =========================================================
def encode_image(image_path, data, output_path):
    """Menyisipkan data ke dalam gambar menggunakan LSB"""
    img = Image.open(image_path)

    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = np.array(img, dtype=np.uint8)
    flat_pixels = pixels.flatten()

    data_length = len(data)
    header = struct.pack('<I', data_length)
    full_data = header + data
    data_hash = hash_sha256(full_data)
    full_data = full_data + data_hash

    bits = []
    for byte in full_data:
        for i in range(8):
            bits.append((byte >> i) & 1)

    if len(bits) > len(flat_pixels):
        raise ValueError("Data terlalu besar untuk gambar")

    for i in range(len(bits)):
        flat_pixels[i] = (flat_pixels[i] & 0xFE) | bits[i]

    encoded_pixels = flat_pixels.reshape(pixels.shape)
    encoded_img = Image.fromarray(encoded_pixels, 'RGB')
    encoded_img.save(output_path)
    return True

def decode_image(image_path):
    """Ekstrak data dari gambar steganografi"""
    img = Image.open(image_path)

    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = np.array(img, dtype=np.uint8)
    flat_pixels = pixels.flatten()

    bits = [pixel & 1 for pixel in flat_pixels]

    bytes_data = bytearray()
    for i in range(0, len(bits), 8):
        if i + 8 > len(bits):
            break
        byte_val = 0
        for j in range(8):
            byte_val |= (bits[i + j] << j)
        bytes_data.append(byte_val)

    if len(bytes_data) < 4:
        raise ValueError("Data tidak valid")

    data_length = struct.unpack('<I', bytes_data[:4])[0]

    if len(bytes_data) < 4 + data_length + 32:
        raise ValueError("Data tidak lengkap")

    encrypted_data = bytes(bytes_data[4:4+data_length])
    stored_hash = bytes(bytes_data[4+data_length:4+data_length+32])
    computed_hash = hash_sha256(bytes_data[:4+data_length])

    if computed_hash != stored_hash:
        raise ValueError("Integritas data gagal")

    return encrypted_data

# =========================================================
# HYBRID CRYPTO SYSTEM (dengan DH)
# =========================================================
class HybridCryptoSystem:

    def __init__(self):
        self.rsa_public = None
        self.rsa_private = None
        self.dsa_public = None
        self.dsa_private = None
        # Diffie-Hellman attributes
        self.dh_private = None
        self.dh_public = None

    def generate_keys(self):
        """Generate semua kunci (RSA, DSA)"""
        self.rsa_public, self.rsa_private = generate_rsa_keypair()
        self.dsa_public, self.dsa_private = generate_dsa_keypair()

    # ========== DIFFIE-HELLMAN METHODS ==========
    def generate_dh_keypair(self):
        """Generate Diffie-Hellman keypair"""
        self.dh_private, self.dh_public = generate_dh_keypair()
        return self.dh_public

    def compute_dh_shared_secret(self, other_public_key):
        """Compute shared secret dari kunci publik pihak lain dan derive AES key"""
        shared_secret_bytes = compute_shared_secret(self.dh_private, other_public_key)
        return derive_aes_key_from_dh(shared_secret_bytes)

    def get_dh_public_key(self):
        """Mendapatkan public key DH"""
        return self.dh_public

    def get_dh_private_key(self):
        """Mendapatkan private key DH (untuk keperluan demo)"""
        return self.dh_private

    # ========== ENKRIPSI METHODS ==========
    def encrypt_message(self, plaintext):
        """Enkripsi pesan dengan skema hibrida"""
        aes_key = get_random_bytes(32)
        encrypted_data = aes_encrypt(plaintext.encode(), aes_key)
        encrypted_aes_key = rsa_encrypt_key(aes_key, self.rsa_public)
        signature = sign_message(encrypted_data, self.dsa_private)

        return {
            'encrypted_aes_key': encrypted_aes_key,
            'encrypted_data': encrypted_data,
            'signature': signature
        }

    def decrypt_message(self, encrypted_package):
        """Dekripsi pesan dengan verifikasi signature"""
        valid = verify_signature(
            encrypted_package['encrypted_data'],
            encrypted_package['signature'],
            self.dsa_public
        )

        if not valid:
            raise ValueError("Signature tidak valid")

        aes_key = rsa_decrypt_key(
            encrypted_package['encrypted_aes_key'],
            self.rsa_private
        )

        plaintext = aes_decrypt(
            encrypted_package['encrypted_data'],
            aes_key
        )

        return plaintext.decode()

    # ========== STEGANO METHODS ==========
    def hide_encrypted_data(self, encrypted_package, image_path, output_path):
        """Menyembunyikan package terenkripsi ke dalam gambar"""
        package_bytes = pickle.dumps(encrypted_package)
        encode_image(image_path, package_bytes, output_path)

    def extract_encrypted_data(self, image_path):
        """Mengekstrak package terenkripsi dari gambar"""
        package_bytes = decode_image(image_path)
        return pickle.loads(package_bytes)


# =========================================================
# GUI APPLICATION
# =========================================================
class CryptoGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Sistem Kriptografi Hibrida + Steganografi")
        self.root.geometry("1000x750")
        self.root.configure(bg='#f0f0f0')

        self.system = HybridCryptoSystem()
        self.system.generate_keys()
        self.image_path = ""

        self.create_menu()
        self.create_widgets()

    def create_menu(self):
        """Membuat menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Pilih Gambar", command=self.select_image)
        file_menu.add_separator()
        file_menu.add_command(label="Keluar", command=self.root.quit)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Bantuan", menu=help_menu)
        help_menu.add_command(label="Tentang", command=self.show_about)

    def create_widgets(self):
        """Membuat semua widget GUI"""

        # Title
        title = tk.Label(
            self.root,
            text="SISTEM KRIPTOGRAFI HIBRIDA + STEGANOGRAFI",
            font=("Arial", 20, "bold"),
            bg='#f0f0f0',
            fg='#2c3e50'
        )
        title.pack(pady=15)

        # Subtitle
        subtitle = tk.Label(
            self.root,
            text="AES + RSA + DSA + SHA256 + Diffie-Hellman + LSB Steganography",
            font=("Arial", 10),
            bg='#f0f0f0',
            fg='#7f8c8d'
        )
        subtitle.pack(pady=(0, 15))

        # ========== FRAME 1: KUNCI (Status) ==========
        frame_keys = tk.LabelFrame(
            self.root,
            text="Status Kunci",
            font=("Arial", 12, "bold"),
            padx=10,
            pady=10,
            bg='#f0f0f0'
        )
        frame_keys.pack(fill="x", padx=10, pady=5)

        self.key_status = tk.Text(
            frame_keys,
            height=4,
            font=("Courier", 9),
            bg='#e8e8e8'
        )
        self.key_status.pack(fill="x")
        self.update_key_status()

        # ========== FRAME 2: INPUT PESAN ==========
        frame_input = tk.LabelFrame(
            self.root,
            text="Pesan Rahasia",
            font=("Arial", 12, "bold"),
            padx=10,
            pady=10,
            bg='#f0f0f0'
        )
        frame_input.pack(fill="x", padx=10, pady=5)

        self.message_text = scrolledtext.ScrolledText(
            frame_input,
            height=6,
            font=("Arial", 11)
        )
        self.message_text.pack(fill="x")

        # ========== FRAME 3: GAMBAR ==========
        frame_image = tk.LabelFrame(
            self.root,
            text="Gambar Cover",
            font=("Arial", 12, "bold"),
            padx=10,
            pady=10,
            bg='#f0f0f0'
        )
        frame_image.pack(fill="x", padx=10, pady=5)

        self.image_label = tk.Label(
            frame_image,
            text="Belum ada gambar dipilih",
            font=("Arial", 10),
            bg='#f0f0f0',
            fg='#e74c3c'
        )
        self.image_label.pack()

        btn_select = tk.Button(
            frame_image,
            text="📁 Pilih Gambar",
            command=self.select_image,
            bg='#3498db',
            fg='white',
            font=("Arial", 10, "bold"),
            padx=20,
            pady=5
        )
        btn_select.pack(pady=5)

        # ========== FRAME 4: BUTTON UTAMA ==========
        frame_buttons = tk.Frame(self.root, bg='#f0f0f0')
        frame_buttons.pack(pady=10)

        btn_encrypt = tk.Button(
            frame_buttons,
            text="🔒 Encrypt + Hide",
            command=self.encrypt_and_hide,
            width=18,
            bg='#27ae60',
            fg='white',
            font=("Arial", 11, "bold"),
            padx=10,
            pady=8
        )
        btn_encrypt.grid(row=0, column=0, padx=10)

        btn_extract = tk.Button(
            frame_buttons,
            text="🔓 Extract + Decrypt",
            command=self.extract_and_decrypt,
            width=18,
            bg='#e67e22',
            fg='white',
            font=("Arial", 11, "bold"),
            padx=10,
            pady=8
        )
        btn_extract.grid(row=0, column=1, padx=10)

        # ========== FRAME 5: DIFFIE-HELLMAN ==========
        frame_dh = tk.LabelFrame(
            self.root,
            text="Diffie-Hellman Key Exchange",
            font=("Arial", 12, "bold"),
            padx=10,
            pady=10,
            bg='#f0f0f0'
        )
        frame_dh.pack(fill="x", padx=10, pady=5)

        btn_dh_frame = tk.Frame(frame_dh, bg='#f0f0f0')
        btn_dh_frame.pack()

        btn_dh_demo = tk.Button(
            btn_dh_frame,
            text="🔄 Demo Diffie-Hellman",
            command=self.demo_diffie_hellman,
            width=20,
            bg='#9b59b6',
            fg='white',
            font=("Arial", 11, "bold"),
            padx=10,
            pady=8
        )
        btn_dh_demo.grid(row=0, column=0, padx=10)

        btn_dh_encrypt = tk.Button(
            btn_dh_frame,
            text="🔐 Encrypt dengan DH Key",
            command=self.encrypt_with_dh,
            width=20,
            bg='#1abc9c',
            fg='white',
            font=("Arial", 11, "bold"),
            padx=10,
            pady=8
        )
        btn_dh_encrypt.grid(row=0, column=1, padx=10)

        self.dh_status = tk.Label(
            frame_dh,
            text="Klik 'Demo Diffie-Hellman' untuk melihat pertukaran kunci",
            font=("Arial", 9),
            bg='#f0f0f0',
            fg='#7f8c8d'
        )
        self.dh_status.pack(pady=5)

        # ========== FRAME 6: OUTPUT ==========
        frame_output = tk.LabelFrame(
            self.root,
            text="Output Log",
            font=("Arial", 12, "bold"),
            padx=10,
            pady=10,
            bg='#f0f0f0'
        )
        frame_output.pack(fill="both", expand=True, padx=10, pady=5)

        self.output_text = scrolledtext.ScrolledText(
            frame_output,
            height=12,
            font=("Courier", 10),
            bg='#2c3e50',
            fg='#ecf0f1'
        )
        self.output_text.pack(fill="both", expand=True)

        # Progress bar (opsional)
        self.progress = ttk.Progressbar(
            self.root,
            mode='indeterminate',
            length=400
        )

        # Clear log button
        btn_clear = tk.Button(
            frame_output,
            text="Clear Log",
            command=self.clear_output,
            bg='#95a5a6',
            fg='white',
            font=("Arial", 9)
        )
        btn_clear.pack(pady=5)

    # =====================================================
    # UPDATE STATUS KUNCI
    # =====================================================
    def update_key_status(self):
        """Update tampilan status kunci"""
        self.key_status.delete(1.0, tk.END)
        self.key_status.insert(tk.END, "=" * 50 + "\n")
        self.key_status.insert(tk.END, "🔑 STATUS KUNCI\n")
        self.key_status.insert(tk.END, "=" * 50 + "\n")
        self.key_status.insert(tk.END, f"✓ RSA Public Key: {str(self.system.rsa_public)[:40]}...\n")
        self.key_status.insert(tk.END, f"✓ RSA Private Key: [TERSIMPAN]\n")
        self.key_status.insert(tk.END, f"✓ DSA Public Key: {str(self.system.dsa_public)[:40]}...\n")
        self.key_status.insert(tk.END, f"✓ DSA Private Key: [TERSIMPAN]\n")
        self.key_status.insert(tk.END, f"✓ DH Keypair: {'Sudah digenerate' if self.system.dh_public else 'Belum digenerate'}\n")
        self.key_status.config(state='disabled')

    # =====================================================
    # PILIH GAMBAR
    # =====================================================
    def select_image(self):
        file_path = filedialog.askopenfilename(
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.bmp"),
                ("PNG files", "*.png"),
                ("JPG files", "*.jpg"),
                ("All files", "*.*")
            ]
        )

        if file_path:
            self.image_path = file_path
            self.image_label.config(
                text=f"✅ {os.path.basename(file_path)}",
                fg='#27ae60'
            )
            self.log(f"Gambar dipilih: {file_path}")

    # =====================================================
    # ENCRYPT + HIDE
    # =====================================================
    def encrypt_and_hide(self):
        try:
            if not self.image_path:
                messagebox.showerror("Error", "Pilih gambar terlebih dahulu")
                return

            message = self.message_text.get("1.0", tk.END).strip()

            if not message:
                messagebox.showerror("Error", "Pesan kosong")
                return

            self.log("\n" + "="*50)
            self.log("🔒 PROSES ENKRIPSI & HIDE")
            self.log("="*50)

            self.log(f"Pesan asli: {message[:50]}...")
            self.log("Menjalankan enkripsi hibrida...")

            encrypted_package = self.system.encrypt_message(message)
            self.log("✓ Enkripsi berhasil")

            output_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG files", "*.png")]
            )

            if not output_path:
                return

            self.log(f"Menyembunyikan data ke gambar...")
            encode_image(self.image_path, pickle.dumps(encrypted_package), output_path)

            self.log(f"✓ Output file: {output_path}")
            self.log("="*50 + "\n")

            messagebox.showinfo(
                "Berhasil",
                f"Pesan berhasil dienkripsi dan disembunyikan!\n\nOutput: {output_path}"
            )

        except Exception as e:
            self.log(f"❌ Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    # =====================================================
    # EXTRACT + DECRYPT
    # =====================================================
    def extract_and_decrypt(self):
        try:
            file_path = filedialog.askopenfilename(
                filetypes=[
                    ("PNG files", "*.png"),
                    ("All files", "*.*")
                ]
            )

            if not file_path:
                return

            self.log("\n" + "="*50)
            self.log("🔓 PROSES EKSTRAK & DEKRIPSI")
            self.log("="*50)

            self.log(f"Membaca file: {file_path}")

            package_bytes = decode_image(file_path)
            self.log("✓ Data berhasil diekstrak dari gambar")

            encrypted_package = pickle.loads(package_bytes)
            self.log("✓ Package berhasil di-load")

            decrypted_message = self.system.decrypt_message(encrypted_package)

            self.log(f"✓ Pesan terdekripsi: {decrypted_message}")
            self.log("="*50 + "\n")

            # Tampilkan di output
            self.output_text.insert(tk.END, f"\n📝 PESAN:\n{decrypted_message}\n\n")

            messagebox.showinfo(
                "Berhasil",
                f"Pesan berhasil didekripsi!\n\nPesan: {decrypted_message[:100]}..."
            )

        except Exception as e:
            self.log(f"❌ Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    # =====================================================
    # DIFFIE-HELLMAN DEMO
    # =====================================================
    def demo_diffie_hellman(self):
        try:
            self.log("\n" + "="*50)
            self.log("🔄 DIFFIE-HELLMAN KEY EXCHANGE DEMO")
            self.log("="*50)

            # Simulasi Alice dan Bob
            self.log("\n[1] Membangkitkan kunci untuk Alice...")
            alice_private, alice_public = generate_dh_keypair()
            self.log(f"    Alice Public Key: {alice_public}")

            self.log("\n[2] Membangkitkan kunci untuk Bob...")
            bob_private, bob_public = generate_dh_keypair()
            self.log(f"    Bob Public Key: {bob_public}")

            # Pertukaran public key
            self.log("\n[3] Pertukaran public key...")
            self.log("    Alice mengirim public key ke Bob")
            self.log("    Bob mengirim public key ke Alice")

            # Hitung shared secret
            self.log("\n[4] Menghitung shared secret...")
            alice_secret = compute_shared_secret(alice_private, bob_public)
            bob_secret = compute_shared_secret(bob_private, alice_public)

            self.log(f"    Alice shared secret: {alice_secret[:32].hex()}...")
            self.log(f"    Bob shared secret: {bob_secret[:32].hex()}...")

            # Verifikasi
            match = alice_secret == bob_secret
            self.log(f"\n[5] Verifikasi: {'✓ COCOK' if match else '✗ TIDAK COCOK'}")

            # Derive AES key
            alice_aes_key = derive_aes_key_from_dh(alice_secret)
            bob_aes_key = derive_aes_key_from_dh(bob_secret)

            self.log(f"\n[6] AES Key dari DH:")
            self.log(f"    Alice: {alice_aes_key.hex()[:32]}...")
            self.log(f"    Bob: {bob_aes_key.hex()[:32]}...")

            # Simpan ke sistem untuk digunakan nanti
            self.system.dh_private = alice_private
            self.system.dh_public = alice_public
            self.shared_secret_demo = alice_secret
            self.dh_aes_key = alice_aes_key

            self.log("\n" + "="*50)
            self.log("✅ Demo Diffie-Hellman selesai!")
            self.log("="*50 + "\n")

            self.dh_status.config(
                text=f"✅ DH Key Exchange SUCCESS! Shared secret cocok. AES Key: {alice_aes_key.hex()[:16]}...",
                fg='#27ae60'
            )

            messagebox.showinfo(
                "Diffie-Hellman Demo",
                f"Pertukaran kunci Diffie-Hellman berhasil!\n\n"
                f"Shared secret match: {match}\n"
                f"AES Key (derived): {alice_aes_key.hex()[:32]}..."
            )

            self.update_key_status()

        except Exception as e:
            self.log(f"❌ DH Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    # =====================================================
    # ENKRIPSI dengan DH KEY
    # =====================================================
    def encrypt_with_dh(self):
        """Enkripsi pesan menggunakan AES key dari Diffie-Hellman"""
        try:
            if not hasattr(self, 'dh_aes_key'):
                messagebox.showerror(
                    "Error",
                    "Jalankan Demo Diffie-Hellman terlebih dahulu!"
                )
                return

            message = self.message_text.get("1.0", tk.END).strip()

            if not message:
                messagebox.showerror("Error", "Pesan kosong")
                return

            self.log("\n" + "="*50)
            self.log("🔐 ENKRIPSI DENGAN DH AES KEY")
            self.log("="*50)

            self.log(f"Menggunakan AES key dari DH: {self.dh_aes_key.hex()[:32]}...")

            # Enkripsi dengan AES menggunakan key dari DH
            encrypted_data = aes_encrypt(message.encode(), self.dh_aes_key)
            self.log(f"✓ Pesan dienkripsi: {encrypted_data.hex()[:50]}...")

            # Simpan ke file
            output_path = filedialog.asksaveasfilename(
                defaultextension=".bin",
                filetypes=[("Binary files", "*.bin")]
            )

            if output_path:
                with open(output_path, 'wb') as f:
                    f.write(encrypted_data)
                self.log(f"✓ Data tersimpan di: {output_path}")

            # Demo dekripsi (dengan key yang sama)
            decrypted = aes_decrypt(encrypted_data, self.dh_aes_key)
            self.log(f"✓ Verifikasi dekripsi: {decrypted.decode()}")

            self.log("="*50 + "\n")

            messagebox.showinfo(
                "Berhasil",
                f"Pesan dienkripsi dengan AES key dari Diffie-Hellman!\n\n"
                f"Plaintext: {message}\n"
                f"Ciphertext length: {len(encrypted_data)} bytes"
            )

        except Exception as e:
            self.log(f"❌ Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    # =====================================================
    # UTILITY FUNCTIONS
    # =====================================================
    def log(self, message):
        """Menambahkan pesan ke output log"""
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.root.update()

    def clear_output(self):
        """Membersihkan output log"""
        self.output_text.delete(1.0, tk.END)
        self.log("Output log dibersihkan")

    def show_about(self):
        """Menampilkan dialog About"""
        about_text = """
SISTEM KRIPTOGRAFI HIBRIDA + STEGANOGRAFI
=========================================

Algoritma yang diimplementasikan:
✓ AES-256-CBC - Enkripsi data
✓ RSA 2048-bit - Enkripsi kunci AES
✓ DSA 2048-bit - Tanda tangan digital
✓ SHA256 - Hash & verifikasi
✓ Diffie-Hellman 2048-bit - Pertukaran kunci
✓ LSB Steganography - Penyembunyian di gambar

Dibuat untuk:
Tugas Kriptografi dan Keamanan Informasi

Version: 2.0 (Dengan Diffie-Hellman)
        """
        messagebox.showinfo("Tentang Program", about_text)


# =========================================================
# MAIN
# =========================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()