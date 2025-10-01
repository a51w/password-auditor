#!/usr/bin/env python3
"""
password_audit.py
Usage:
  python password_audit.py passwords.txt
Outputs:
  - prints a summary to console
  - writes `audit_report.csv` and `audit_report.json` in current dir
Notes:
  - Safe: ใช้กับไฟล์รหัสผ่านที่เป็นของคุณหรือที่ได้รับอนุญาตเท่านั้น
"""

import sys
import math
import json
import csv
from collections import Counter
from typing import List

# ---------- CONFIG ----------
OUTPUT_CSV = "audit_report.csv"
OUTPUT_JSON = "audit_report.json"
# (optional) small blacklist of common passwords (you can expand)
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "abc123", "111111", "123123", "letmein"
}

# ---------- HELPERS ----------
def estimate_entropy(pw: str) -> float:
    """
    ประมาณ entropy แบบง่าย:
    charset_size คำนวณจากประเภทตัวอักษรที่ปรากฏ แล้ว entropy = len * log2(charset_size)
    (เป็นการประมาณ — ไม่เทียบเท่า zxcvbn แต่เพียงพอสำหรับ demo)
    """
    if not pw:
        return 0.0
    charset = 0
    if any(c.islower() for c in pw):
        charset += 26
    if any(c.isupper() for c in pw):
        charset += 26
    if any(c.isdigit() for c in pw):
        charset += 10
    if any(not c.isalnum() for c in pw):
        # ประมาณ charset ของสัญลักษณ์
        charset += 32
    if charset == 0:
        return 0.0
    return len(pw) * math.log2(charset)

def classify_password(ent: float, length: int, pw: str) -> str:
    """
    กำหนดระดับตาม entropy และความยาว และเช็ค blacklist
    """
    if pw in COMMON_PASSWORDS or length < 6 or ent < 28:
        return "Weak"
    if ent < 50 or length < 10:
        return "Moderate"
    return "Strong"

def read_password_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.rstrip("\n\r") for line in f]
    # กรอง empty lines
    return [l for l in lines if l.strip() != ""]

# ---------- MAIN ----------
def audit(passwords: List[str]):
    counts = Counter(passwords)
    rows = []
    for pw in passwords:
        ent = estimate_entropy(pw)
        lvl = classify_password(ent, len(pw), pw)
        is_common = pw in COMMON_PASSWORDS
        rows.append({
            "password": pw,
            "length": len(pw),
            "entropy": round(ent, 2),
            "classification": lvl,
            "is_common": is_common,
            "count": counts[pw]
        })

    # เขียน CSV
    fieldnames = ["password", "length", "entropy", "classification", "is_common", "count"]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    # เขียน JSON
    with open(OUTPUT_JSON, "w", encoding="utf-8") as jf:
        json.dump(rows, jf, indent=2, ensure_ascii=False)

    # สรุปบน console
    total = len(passwords)
    weak = sum(1 for r in rows if r["classification"] == "Weak")
    moderate = sum(1 for r in rows if r["classification"] == "Moderate")
    strong = sum(1 for r in rows if r["classification"] == "Strong")
    duplicates = [p for p, c in counts.items() if c > 1]

    print(f"Total passwords: {total}")
    print(f"Weak: {weak}  Moderate: {moderate}  Strong: {strong}")
    print(f"Duplicate passwords: {len(duplicates)} -> {duplicates[:10]}")
    print(f"Report written: {OUTPUT_CSV}, {OUTPUT_JSON}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python password_audit.py passwords.txt")
        sys.exit(1)
    path = sys.argv[1]
    try:
        pwds = read_password_file(path)
    except FileNotFoundError:
        print("File not found:", path)
        sys.exit(1)
    if not pwds:
        print("No passwords found in file.")
        sys.exit(1)
    audit(pwds)
