import os
import sys
import zipfile
import shutil
import requests
import binascii
import tempfile
import zlib

from lxml import etree
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding as crypto_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Namespace map
NAMESPACES = {
    'enc': 'http://www.w3.org/2001/04/xmlenc#',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
    'comp': 'http://www.idpf.org/2016/encryption#compression'
}

def find_opf_path(workdir):
    container_path = os.path.join(workdir, 'META-INF', 'container.xml')
    try:
        tree = etree.parse(container_path)
        rootfile = tree.find('.//{urn:oasis:names:tc:opendocument:xmlns:container}rootfile')
        if rootfile is not None:
            return os.path.join(workdir, rootfile.get('full-path'))
        else:
            print("[!] rootfile not found in container.xml.")
            return None
    except Exception as e:
        print(f"[!] Failed to parse container.xml: {e}")
        return None

def get_epub_title(opf_path):
    try:
        tree = etree.parse(opf_path)
        title_element = tree.find('.//{http://purl.org/dc/elements/1.1/}title')
        if title_element is not None:
            return title_element.text.strip()
        else:
            print("[!] Title not found in package.opf.")
            return "decrypted"
    except Exception as e:
        print(f"[!] Error reading title from OPF: {e}")
        return "decrypted"

def download_epub(link: str, download_path: str):
    print(f"[+] Downloading EPUB from: {link}")
    r = requests.get(link)
    if r.status_code != 200:
        print(f"[!] Failed to download EPUB: HTTP {r.status_code}")
        sys.exit(1)
    with open(download_path, 'wb') as f:
        f.write(r.content)
    print(f"[+] Downloaded to '{download_path}'")

def decrypt_key(encrypted_hex: str, uid: str, salt: str = "BookBites") -> bytes:
    iterations = 100000
    key_length = 16
    backend = default_backend()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=key_length,
        salt=salt.encode("utf-8"),
        iterations=iterations,
        backend=backend
    )
    derived_key = kdf.derive(uid.encode("utf-8"))

    encrypted_bytes = binascii.unhexlify(encrypted_hex)
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]

    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = crypto_padding.PKCS7(128).unpadder()
    aes_key = unpadder.update(padded_plaintext) + unpadder.finalize()

    return aes_key

def unzip_epub(epub_path, extract_dir):
    print(f"[+] Extracting EPUB '{epub_path}' to '{extract_dir}'")
    with zipfile.ZipFile(epub_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

def zip_epub(folder_path, output_path):
    print(f"[+] Creating EPUB '{output_path}'")
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, folder_path)
                zipf.write(full_path, arcname)

def parse_encryption_xml(enc_xml_path):
    tree = etree.parse(enc_xml_path)
    root = tree.getroot()
    encrypted_files = []

    for enc_data in root.findall('.//enc:EncryptedData', namespaces=NAMESPACES):
        cipher_ref = enc_data.find('.//enc:CipherReference', namespaces=NAMESPACES)
        if cipher_ref is None:
            continue
        uri = cipher_ref.get('URI')

        method_elem = enc_data.find('.//enc:EncryptionMethod', namespaces=NAMESPACES)
        algorithm = method_elem.get('Algorithm') if method_elem is not None else None

        compression_elem = enc_data.find('.//enc:EncryptionProperty/comp:Compression', namespaces=NAMESPACES)
        compression = compression_elem.get('Method') if compression_elem is not None else None
        original_length = int(compression_elem.get('OriginalLength')) if compression_elem is not None else None

        encrypted_files.append({
            'URI': uri,
            'algorithm': algorithm,
            'compression_method': compression,
            'original_length': original_length
        })

    return encrypted_files

def remove_pkcs7_padding(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def decrypt_aes128_cbc(data, key):
    iv = data[:16]
    ciphertext = data[16:]

    if len(ciphertext) % 16 != 0:
        raise ValueError(f"Ciphertext length {len(ciphertext)} is not a multiple of 16.")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    try:
        return remove_pkcs7_padding(decrypted)
    except Exception:
        return decrypted

def decompress_if_needed(data, method):
    if method == "8":
        try:
            return zlib.decompress(data)
        except zlib.error:
            try:
                return zlib.decompress(data, wbits=-15)
            except zlib.error:
                return data
    return data

def decrypt_epub(epub_path, aes_key, output_path):
    workdir = tempfile.mkdtemp()
    unzip_epub(epub_path, workdir)

    enc_xml = os.path.join(workdir, 'META-INF', 'encryption.xml')
    if not os.path.exists(enc_xml):
        print("[!] encryption.xml not found — nothing to decrypt.")
        return

    encrypted_files = parse_encryption_xml(enc_xml)

    for ef in encrypted_files:
        print(f"[+] Decrypting: {ef['URI']}")
        if ef['algorithm'] != 'http://www.w3.org/2001/04/xmlenc#aes128-cbc':
            print(f"[i] Skipping unsupported algorithm for '{ef['URI']}': {ef['algorithm']}")
            continue
        target = os.path.join(workdir, *ef['URI'].split('/'))
        if not os.path.exists(target):
            continue
        with open(target, 'rb') as f:
            encrypted_data = f.read()
        decrypted = decrypt_aes128_cbc(encrypted_data, aes_key)
        final_data = decompress_if_needed(decrypted, ef['compression_method'])
        with open(target, 'wb') as f:
            f.write(final_data)

    os.remove(enc_xml)
    
    opf_path = find_opf_path(workdir)
    if not opf_path or not os.path.exists(opf_path):
        print("[!] Could not locate package.opf.")
        sys.exit(1)
    title = get_epub_title(opf_path)
    safe_title = "".join(c for c in title if c.isalnum() or c in " -_").strip()
    output_path = f"{safe_title}.epub"
    
    zip_epub(workdir, output_path)
    shutil.rmtree(workdir)
    print(f"[+] Decrypted EPUB saved to '{output_path}'")

# === Main ===
if __name__ == "__main__":
    user_input = input("Enter LINK;USERID;KEY: ").strip()
    try:
        link, uid, encrypted_hex = [part.strip() for part in user_input.split(";")]
    except ValueError:
        print("[!] Invalid input format. Use: LINK;USERID;KEY")
        sys.exit(1)

    # Prepare filenames
    input_epub = "input.epub"
    output_epub = "decrypted.epub"

    download_epub(link, input_epub)
    aes_key = decrypt_key(encrypted_hex, uid)
    print(f"[+] AES key: {aes_key.hex()}")

    decrypt_epub(input_epub, aes_key, output_epub)

    # Clean up
    os.remove(input_epub)
    print("[+] Cleanup complete.")
