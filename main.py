import time
import multiprocessing
from bitcoin import encode_pubkey, privtopub
from Crypto.Hash import SHA256, RIPEMD160

# تابع تبدیل به hash160 (Public Key Hash)
def pubkey_to_hash160(pubkey):
    # محاسبه SHA-256
    sha256_hash = SHA256.new(bytes.fromhex(pubkey)).digest()

    # محاسبه RIPEMD-160
    ripemd160 = RIPEMD160.new(sha256_hash).digest()

    return ripemd160.hex()

# تابع برای بررسی تطابق هش کلید عمومی
def check_hash_match(start, end, target_hash, found_flag):
    current_num = start
    while current_num >= end and not found_flag.value:
        # تبدیل عدد به هگز 64 کاراکتری
        hex_key = format(current_num, '064x')

        # تولید کلید عمومی فشرده از روی کلید خصوصی
        pubkey = privtopub(hex_key)
        compressed_pubkey = encode_pubkey(pubkey, 'hex_compressed')

        # محاسبه Hash 160 کلید عمومی
        hash160 = pubkey_to_hash160(compressed_pubkey)

        # بررسی تطابق با Z
        if hash160 == target_hash:
            found_flag.value = 1
            print(f"Found matching key: {hex_key}")
            return

        current_num -= 1

# تابع اصلی برای مدیریت چندپردازشی
def run_search(N, M, Z, num_processes):
    target_hash = Z
    found_flag = multiprocessing.Value('i', 0)  # Flag برای متوقف کردن دیگر پروسه‌ها در صورت یافتن نتیجه

    # ایجاد فرآیندهای موازی
    processes = []
    start_time = time.time()

    # محاسبه اندازه هر بخش (chunk) برای تقسیم‌بندی بین هسته‌ها
    chunk_size = (N - M) // num_processes
    for i in range(num_processes):
        start = N - (i * chunk_size)
        end = start - chunk_size
        if i == num_processes - 1:
            end = M  # آخرین هسته تا عدد نهایی M ادامه می‌دهد

        p = multiprocessing.Process(target=check_hash_match, args=(start, end, target_hash, found_flag))
        processes.append(p)
        p.start()

    # منتظر ماندن برای اتمام همه پروسه‌ها
    for p in processes:
        p.join()

    total_time = time.time() - start_time
    if not found_flag.value:
        print(f"Not found after checking from {N} to {M}.")
    print(f"Total time: {total_time:.2f} seconds.")

# ورودی‌ها
if __name__ == "__main__":
    N = 100
    M = 50 #only 50
    Z = "739437bb3dd6d1983e66629c5f08c70e52769371"

    # تعداد پردازنده‌های موجود
    num_processes = multiprocessing.cpu_count()  # تعداد هسته‌های سیستم
    print(f"Using {num_processes} CPU cores.")

    run_search(N, M, Z, num_processes)
