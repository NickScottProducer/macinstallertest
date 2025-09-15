# installer_v2.py — activation-first with signature pass-through + obfuscated .nka
# - Reads license JSON { "key": ..., "sig": ... }
# - POST /activate with license_key + license_sig + machine_fingerprint
# - On success, uses content_key_b64 to decrypt iv||ciphertext and extracts files
# - Writes hidden .nka flags (AppData + library) without disclosing their locations

import os, sys, io, json, zlib, uuid, socket, getpass, base64, hashlib, platform, zipfile, traceback, random, string
from typing import Optional

# Import customtkinter for the GUI and tkinter for dialogs
import customtkinter as ctk
from tkinter import filedialog, messagebox

# Import requests and pycryptodome for core functionality
import requests
from Crypto.Cipher import AES  # pycryptodome
import ctypes, subprocess  # for hiding folders on Win/mac



# --- Existing core logic (unchanged) ---
WEBHOOK_SERVER_ACTIVATION_URL = os.environ.get(
    "ACTIVATION_URL",
    "https://willow-drums-webhook-ahuxffwn4q-uc.a.run.app/activate"
)

# Dual-product config (auto-detected by extracted .nki name)
PRODUCTS = {
    "willow": {
        "nki_match": ["willow"],
        "appdata_name": "WillowKickSnare",
        "nka_filename": "l13n2e_81nd.nka",
        "nka_parts": ["Data","misc","2","etc","trashes"],
        "array_first_line": "%wx33O4z",
        "magic": 266406066,
    },
    "chiodos": {
        "nki_match": ["chiodos","ns_drums","ns drums"],
        "appdata_name": "ChiodosDrumkit",
        "nka_filename": "z9_bind_7x.nka",
        "nka_parts": ["Data","sys","7","bin","cache","obj",".tmp"],
        "array_first_line": "%z9b7x",
        "magic": 719693765,
    },
}
PRODUCT_IDENTIFIER_STRING = "nsDWKaS"
LICENSE_BIND_NKA_FILENAME = "l13n2e_81nd.nka"
NKA_SUBFOLDER_PATH_PARTS = ["Data", "misc", "2", "etc", "trashes"]
NUM_RANDOM_FOLDERS_PER_LEVEL = 2
NUM_RANDOM_FILES_ALONGSIDE_REAL_PATH_PARTS = 3
RANDOM_NAME_LENGTH = 8
NUM_RANDOM_FILES_INSIDE_DUMMY_FOLDERS_MIN_MAX = (2, 3)
MAX_DUMMY_NESTING_DEPTH = 1
NUM_NESTED_DUMMY_FOLDERS_MIN_MAX = (1, 2)
NUM_RANDOM_FOLDERS_HINTS = {"misc": 5, "trashes": 2}
FOLDER_NAME_HINTS = {
    "Data": ["Archive", "Backup", "Logs", "Temp", "Cache", "UserData"],
    "misc": ["system", "config", "assets", "content", "local"],
    "2":    ["3", "5", "10", "alpha", "beta", "temp_files", "system", "folder", "item"],
    "etc":  ["more", "bin", "x64", "share", "var", "cache", "temp", "sys", "usr"],
    "trashes": ["main", "bin", "x86", "temp", "archive", "old", "junk", "recovery", "dump"],
}
DUMMY_NKA_ARRAY_NAMES = ["%dada", "%config", "%settings", "%temp_vars", "%checksums", "%array_a"]
DUMMY_NKA_VALUE_RANGE = (10000, 999_999_999)


def _resource_path(rel: str) -> str:
    """Return an absolute path to a bundled resource (works in dev and PyInstaller --onefile)."""
    base = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base, rel)




def _machine_fingerprint() -> str:
    try: user = getpass.getuser()
    except: user = "unknown_user"
    try: host = socket.gethostname()
    except: host = "unknown_host"
    mac = uuid.getnode()
    mac_hex = ':'.join([f"{(mac >> i) & 0xff:02x}" for i in range(0, 48, 8)])
    sysinfo = f"{platform.system()} {platform.release()} {platform.machine()}"
    return hashlib.sha256(f"{user}-{host}-{mac_hex}-{sysinfo}".encode("utf-8")).hexdigest()

def _appdata_base(app_name="WillowKickSnare"):
    if sys.platform.startswith("win"):
        return os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), app_name)
    elif sys.platform.startswith("darwin"):
        return os.path.join(os.path.expanduser("~"), "Library", "Application Support", app_name)
    else:
        return os.path.join(os.path.expanduser("~"), ".config", app_name)

def _ensure_path(base: str, parts: list[str]) -> str:
    p = base
    for part in parts:
        p = os.path.join(p, part)
        os.makedirs(p, exist_ok=True)
    return p


def _hide_folder(path: str) -> None:
    try:
        if sys.platform.startswith("win"):
            FILE_ATTRIBUTE_HIDDEN = 0x2
            # Get existing attrs; -1 means error
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attrs != -1 and (attrs & FILE_ATTRIBUTE_HIDDEN) == 0:
                ctypes.windll.kernel32.SetFileAttributesW(str(path), attrs | FILE_ATTRIBUTE_HIDDEN)
        elif sys.platform.startswith("darwin"):
            # Hide in Finder
            subprocess.run(["/usr/bin/chflags", "hidden", path], check=False)
        else:
            # Linux: only dot-prefixed names are hidden; keep 'Data' visible to match KSP path
            pass
    except Exception:
        pass


def _rand_alnum(length=RANDOM_NAME_LENGTH) -> str:
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def _find_first_nki_dir(root: str) -> str | None:
    for cur, _dirs, files in os.walk(root):
        if any(fn.lower().endswith(".nki") for fn in files):
            return cur
    return None



def _folder_name(hint_word: str = "", target_len: int = RANDOM_NAME_LENGTH,
                 numeric_only: bool = False, single_digit_chance: float = 0.5) -> str:
    if numeric_only:
        return str(random.randint(0, 9)) if random.random() < single_digit_chance else str(random.randint(10, 99))
    base_name = hint_word or random.choice(["temp", "data", "conf", "log", "res"])
    suffix_chars = string.ascii_lowercase + string.digits
    appendix = str(random.randint(1, 999)).zfill(random.randint(1, 3)) if random.choice([True, False]) \
               else ''.join(random.choice(suffix_chars) for _ in range(random.randint(1, 3)))
    name = f"{base_name}_{appendix}"
    return name[:target_len] if len(name) > target_len else name

def _dummy_file_content(ext: str) -> str:
    if ext == ".nka":
        arr = random.choice(DUMMY_NKA_ARRAY_NAMES)
        val = random.randint(*DUMMY_NKA_VALUE_RANGE)
        return f"{arr}\n{val}\n"
    return f"dummy:{_rand_alnum(20)}\n"

def _add_obfuscation(target_dir: str, numeric_context: bool = False, depth: int = 0) -> None:
    if depth >= MAX_DUMMY_NESTING_DEPTH:
        return
    for _ in range(random.randint(*NUM_NESTED_DUMMY_FOLDERS_MIN_MAX)):
        dummy = _folder_name(numeric_only=numeric_context, single_digit_chance=0.5)
        nested = os.path.join(target_dir, dummy)
        os.makedirs(nested, exist_ok=True)
        _add_obfuscation(nested, numeric_context, depth + 1)
    for _ in range(random.randint(*NUM_RANDOM_FILES_INSIDE_DUMMY_FOLDERS_MIN_MAX)):
        ext = random.choice([".txt", ".nka"])
        with open(os.path.join(target_dir, _rand_alnum() + ext), "w") as f:
            f.write(_dummy_file_content(ext))

def _create_obfuscated_path(base_path: str, parts: list[str]) -> str:
    current = base_path
    for part in parts:
        lvl = os.path.join(current, part)
        os.makedirs(lvl, exist_ok=True)

        num_for_level = NUM_RANDOM_FOLDERS_HINTS.get(part, NUM_RANDOM_FOLDERS_PER_LEVEL)
        is_numeric_layer = (part == "misc")

        if is_numeric_layer:
            numeric_names = []
            for _ in range(2):
                numeric_names.append(_folder_name(numeric_only=True, single_digit_chance=1.0))
            for _ in range(max(0, num_for_level - 2)):
                numeric_names.append(_folder_name(numeric_only=True, single_digit_chance=0.5))
            random.shuffle(numeric_names)
            for name in numeric_names:
                p = os.path.join(lvl, name)
                os.makedirs(p, exist_ok=True)
                _add_obfuscation(p, numeric_context=True, depth=0)
        else:
            for _ in range(num_for_level):
                hints = FOLDER_NAME_HINTS.get(part, [])
                hint = random.choice(hints) if hints else ""
                name = _folder_name(hint_word=hint, target_len=RANDOM_NAME_LENGTH, numeric_only=False)
                p = os.path.join(lvl, name)
                os.makedirs(p, exist_ok=True)
                _add_obfuscation(p, numeric_context=False, depth=0)

        for _ in range(NUM_RANDOM_FILES_ALONGSIDE_REAL_PATH_PARTS):
            ext = random.choice([".txt", ".nka"])
            with open(os.path.join(lvl, _rand_alnum() + ext), "w") as f:
                f.write(_dummy_file_content(ext))

        current = lvl
    return current

def _decrypt_with_content_key(enc_blob: bytes, content_key: bytes) -> bytes:
    if len(enc_blob) < 16:
        raise ValueError("Encrypted file too small (missing IV)")
    if len(content_key) not in (16, 24, 32):
        raise ValueError("content key must be 16/24/32 bytes")
    iv, ct = enc_blob[:16], enc_blob[16:]
    cipher = AES.new(content_key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    pad = pt[-1]
    if pad < 1 or pad > AES.block_size or any(b != pad for b in pt[-pad:]):
        raise ValueError("Invalid padding (wrong key or corrupted file)")
    return pt[:-pad]



def _read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _detect_product(install_root: str):
    """Return ('willow'|'chiodos', cfg). Default to willow if unclear."""
    try:
        for cur, _dirs, files in os.walk(install_root):
            for fn in files:
                if fn.lower().endswith(".nki"):
                    name = fn.lower()
                    for key, cfg in PRODUCTS.items():
                        if any(tok in name for tok in cfg["nki_match"]):
                            return key, cfg
    except Exception:
        pass
    return "willow", PRODUCTS["willow"]

def _maybe_find_bundle(license_key: str, hint_dir: str) -> Optional[str]:
    p = os.path.join(hint_dir, f"bundle_{license_key}.enc")
    return p if os.path.exists(p) else None

def _write_nka(base_dir: str, cfg: dict, activated: bool) -> None:
    real_dir = _create_obfuscated_path(base_dir, cfg["nka_parts"])
    # Hide the top of the license tree (Data/) on supported OSes
    try:
        data_root = os.path.join(base_dir, cfg["nka_parts"][0])  # .../<base_dir>/Data
        _hide_folder(data_root)
    except Exception:
        pass

    nka_path = os.path.join(real_dir, cfg["nka_filename"])
    with open(nka_path, "w", encoding="utf-8") as f:
        f.write(cfg["array_first_line"] + "\n")
        if activated:
            f.write(f"{cfg['magic']}\n")
        else:
            f.write("0\n")


def _activate_or_raise(license_key: str, license_sig_b64: str) -> bytes:
    payload = {
        "license_key": license_key,
        "license_sig": license_sig_b64,
        "machine_fingerprint": _machine_fingerprint()
    }
    try:
        r = requests.post(WEBHOOK_SERVER_ACTIVATION_URL, json=payload, timeout=30)
        r.raise_for_status()
        res = r.json()
    except Exception as e:
        raise RuntimeError(f"Activation request failed: {e}")

    if res.get("status") != "success" or "content_key_b64" not in res:
        raise RuntimeError(res.get("message", "Activation denied"))
    try:
        return base64.b64decode(res["content_key_b64"])
    except Exception as e:
        raise RuntimeError(f"Bad content key from server: {e}")

def perform_install(license_json_path: str, install_dir: str, status_cb=None) -> dict:
    """Original flow, with the library marker written next to the first .nki AFTER extraction."""
    S = (lambda msg: status_cb(msg)) if callable(status_cb) else (lambda *_: None)

    # --- read license ---
    S("Reading license…")
    with open(license_json_path, "r", encoding="utf-8") as f:
        lic = json.load(f)
    license_key = lic.get("key")
    license_sig = lic.get("sig")
    if not license_key or not license_sig:
        raise RuntimeError("License JSON must contain 'key' and 'sig'.")

    # --- locate encrypted bundle ---
    bundle_expected = f"bundle_{license_key}.enc"
    bundle_path = os.path.join(os.path.dirname(license_json_path), bundle_expected)
    if not os.path.exists(bundle_path):
        # fall back to a file picker, but enforce the expected filename
        p = filedialog.askopenfilename(
            title="Select encrypted bundle",
            filetypes=[("Encrypted bundle", "*.enc"), ("All files", "*")]
        )
        if not p:
            raise RuntimeError("No bundle selected.")
        if os.path.basename(p) != bundle_expected:
            raise RuntimeError(f"Bundle filename must be {bundle_expected}.")

        bundle_path = p

    # --- activate (server returns content_key_b64) ---
    S("Activating this machine…")
    content_key = _activate_or_raise(license_key, license_sig)  # bytes

    # AppData flag will be written after we detect which product this is

    try:
        # --- decrypt bundle (AES-CBC; IV||CT; PKCS#7) ---
        S("Decrypting bundle…")
        with open(bundle_path, "rb") as f:
            enc_blob = f.read()
        pt_zip = _decrypt_with_content_key(enc_blob, content_key)

        # --- extract to chosen install dir ---
        S("Extracting files…")
        os.makedirs(install_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(pt_zip), "r") as zf:
            zf.extractall(install_dir)

        # Detect product and write flags
        product_key, cfg = _detect_product(install_dir)
        S(f"Detected product: {product_key}")

        # AppData flag (product-specific)
        S("Writing activation flag…")
        _write_nka(_appdata_base(cfg["appdata_name"]), cfg, True)

        # REAL marker next to the .nki (this is what KSP reads)
        nki_dir = _find_first_nki_dir(install_dir)
        if not nki_dir:
            raise RuntimeError("Install extracted, but no .nki found.")
        S("Finalizing license…")
        _write_nka(nki_dir, cfg, True)

        return {"installed_to": nki_dir}

    except Exception as e:
        # On failure, mirror behavior: write "false" markers if we can.
        try:
            product_key, cfg = _detect_product(install_dir)
            _write_nka(_appdata_base(cfg["appdata_name"]), cfg, False)
        except: pass
        try: _write_nka(install_dir, cfg, False)
        except: pass
        raise




# --- GUI with customtkinter ---
class GUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        self.title("Nick Scott Drums — Installer")
        self.geometry("720x360")
        try:
            self.iconbitmap(_resource_path("icon.ico"))
        except Exception:
            pass

        self.grid_columnconfigure(0, weight=1)
        self.status = ctk.StringVar(value="Select your license JSON and install folder.")
        self._ui()

    def _ui(self):
        # Title and Subtitle
        ctk.CTkLabel(self, text="Installer and Activation", font=("Helvetica", 24, "bold")).pack(pady=(20, 0))
        ctk.CTkLabel(self, text="Nick Scott Drums — Installer", font=("Helvetica", 14)).pack(pady=(0, 20))

        # Main frame for inputs
        input_frame = ctk.CTkFrame(self)
        input_frame.pack(fill="x", padx=40, pady=10)
        input_frame.grid_columnconfigure(1, weight=1)

        # License JSON Row
        ctk.CTkLabel(input_frame, text="License JSON:", font=("Helvetica", 12)).grid(row=0, column=0, sticky="w", padx=(20, 5), pady=10)
        self.lic_entry = ctk.CTkEntry(input_frame)
        self.lic_entry.grid(row=0, column=1, sticky="we", padx=5)
        ctk.CTkButton(input_frame, text="Browse…", command=self._pick_lic).grid(row=0, column=2, padx=(5, 20))

        # Install Folder Row
        ctk.CTkLabel(input_frame, text="Install folder:", font=("Helvetica", 12)).grid(row=1, column=0, sticky="w", padx=(20, 5), pady=10)
        self.dest_entry = ctk.CTkEntry(input_frame)
        self.dest_entry.insert(0, os.path.join(os.path.expanduser("~"), "NickScottDrums", "WillowKickSnare"))
        self.dest_entry.grid(row=1, column=1, sticky="we", padx=5)
        ctk.CTkButton(input_frame, text="Choose…", command=self._pick_dir).grid(row=1, column=2, padx=(5, 20))

        # Status Label
        ctk.CTkLabel(self, textvariable=self.status, font=("Helvetica", 10, "italic"), text_color="#666").pack(pady=(20, 10))
        
        # Install Button
        ctk.CTkButton(self, text="Activate & Install", command=self._run, font=("Helvetica", 14, "bold")).pack(pady=20)

    def _set_status(self, s):
        """Updates the status label."""
        self.status.set(s)
        self.update_idletasks()
        
    def _pick_lic(self):
        """Opens a file dialog for the license file."""
        try:
            p = filedialog.askopenfilename(
                parent=self,                              # anchor the panel to the window (mac-friendly)
                title="Select license JSON",
                filetypes=[("JSON files", "*.json"), ("All files", "*")]  # no 'license_*.json' here
            )
            if not p:
                return
            base = os.path.basename(p)
            if not (base.startswith("license_") and base.lower().endswith(".json")):
                messagebox.showerror(
                    "Wrong file",
                    "Please select your license_<KEY>.json file."
                )
                return
            self.lic_entry.delete(0, "end")
            self.lic_entry.insert(0, p)
        except Exception as e:
            messagebox.showerror("File dialog error", str(e))

        
    def _pick_dir(self):
        """Opens a directory dialog for the install folder."""
        p = filedialog.askdirectory(parent=self, title="Choose install folder")

        if p: self.dest_entry.delete(0, "end"); self.dest_entry.insert(0, p)

    def _run(self):
        """Runs the installation process."""
        try:
            lic_path = self.lic_entry.get()
            dest_dir = self.dest_entry.get()
            if not lic_path or not os.path.exists(lic_path):
                messagebox.showerror("Missing license", "Please select your license_<KEY>.json file.")
                return
            if not dest_dir:
                messagebox.showerror("Missing folder", "Please choose an install folder.")
                return
            
            self._set_status("Starting…")
            res = perform_install(lic_path, dest_dir, status_cb=self._set_status)
            self._set_status("Done.")
            messagebox.showinfo("Install complete", f"Installed to:\n{res['installed_to']}")
        except Exception as e:
            self._set_status("Error.")
            messagebox.showerror("Activation or install failed", str(e))
            traceback.print_exc()

def main():
    app = GUI()
    app.mainloop()

if __name__ == "__main__":
    main()
