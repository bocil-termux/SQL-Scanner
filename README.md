# 🔍 SQL Injection Scanner

<p align="center">
  <b>Alat pemindaian SQL Injection yang cepat dan efisien untuk mengidentifikasi potensi kerentanan SQLi pada aplikasi web</b>
</p>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Development-yellow)

</div>

## ⚠️ Peringatan Keamanan

> **Warning:** Alat ini sedang dalam proses pengembangan aktif dan mungkin masih memiliki keterbatasan. Hasil yang ditemukan harus divalidasi lebih lanjut menggunakan tools profesional seperti **sqlmap** atau **ghauri**. Gunakan hanya pada sistem yang Anda miliki atau memiliki izin eksplisit untuk diuji.

## ✨ Fitur Utama

| Fitur | Deskripsi |
|-------|-----------|
| 🔄 **Multi-threaded Scanning** | Pemindaian paralel untuk performa tinggi |
| 🗄️ **Multi-Database Support** | MySQL, PostgreSQL, SQL Server, Oracle, SQLite |
| 💉 **Various Techniques** | Error-based, Boolean-based, Time-based, Union-based |
| 🌐 **HTTP Methods** | Support GET & POST methods |
| 🎨 **Colorful Output** | Output berwarna untuk readability yang lebih baik |
| 📁 **Batch Processing** | Scan multiple URLs dari file |
| ⚡ **Auto Parameter Extraction** | Ekstraksi parameter otomatis dari URL |
| ⏳ **Customizable Delay** | Konfigurasi delay antara requests |

## 🚀 Instalasi Cepat

### Prerequisites

- Python 3.7 atau lebih tinggi
- pip (Python package manager)

### Langkah Instalasi

```bash
# Clone repository
git clone https://github.com/bocil-termux/SQL-Scanner.git
cd SQL-Scanner

# Install dependencies
pip install requests argparse urllib3

# Verify installation
python sql_scanner.py -h
```

📖 Panduan Penggunaan

Basic Commands

```bash
# Scan single URL
python sql_scanner.py -u "https://example.com/page.php?id=1"

# Scan multiple URLs dari file
python sql_scanner.py -f targets.txt -t 10

# Scan dengan method POST
python sql_scanner.py -u "https://example.com/login" -m post
```

Advanced Options

```bash
# Scan dengan 15 threads
python sql_scanner.py -f targets.txt -t 15

# Tambahkan delay 0.5 detik antara requests
python sql_scanner.py -u "https://example.com/test" -d 0.5

# Enable verbose output untuk debugging
python sql_scanner.py -u "https://example.com/test" -v

# Custom timeout 15 detik
python sql_scanner.py -u "https://example.com/test" --timeout 15
```

📋 Parameter Options

Parameter Deskripsi Default
-u, --url Target URL untuk di-scan -
-f, --file File berisi list URL -
-t, --threads Jumlah concurrent threads 5
-m, --method HTTP method(s) untuk test both
-d, --delay Delay antara requests (seconds) -
--timeout Request timeout (seconds) 10
-v, --verbose Enable verbose output False

🎯 Contoh Penggunaan

Contoh 1: Basic Single URL Scan

```bash
python sql_scanner.py -u "https://test-site.vuln/page.php?id=1&category=2"
```

Contoh 2: Advanced Batch Scanning

```bash
python sql_scanner.py -f urls.txt -t 10 -d 0.2 -v
```

Contoh 3: POST Method Testing

```bash
python sql_scanner.py -u "https://test-site.vuln/login.php" -m post
```

📊 Contoh Output

```
[14:30:25] [INFO] Scanning: https://example.com/page.php?id=1
[14:30:26] [VULNERABILITY] Potential SQL Injection Found!
══════════════════════════════════════════════════════════
  URL: https://example.com/page.php?id=1
  Database: MySQL
  Method: GET
  Vulnerable Parameters: 1 parameters
══════════════════════════════════════════════════════════
```

🔧 Teknik Deteksi

Teknik Status Deskripsi
Error-based Detection ✅ Mendeteksi error message database
Boolean-based Detection ✅ Menggunakan payload boolean logic
Time-based Detection ✅ Payload yang menyebabkan delay
Union-based Detection ✅ Menggunakan UNION SELECT statements
Stacked Queries ✅ Menguji eksekusi multiple queries

🗃️ Database Support

Database Status Deteksi
MySQL ✅ Full support
PostgreSQL ✅ Full support
SQL Server ✅ Full support
Oracle ✅ Full support
SQLite ✅ Full support

🚧 Roadmap Pengembangan

🔄 Dalam Pengembangan

· Blind SQL injection detection
· Advanced time-based detection
· WAF bypass techniques

📅 Planned Features

· Out-of-band detection
· JSON output format
· HTML report generation
· Custom payload support
· Authentication support

⚠️ Disclaimer & Etika

```text
Alat ini dibuat untuk tujuan:
✓ Pendidikan dan penelitian
✓ Penetration testing yang legal
✓ Security assessment dengan izin

Dilarang menggunakan untuk:
✗ Aktivitas ilegal
✗ Testing tanpa izin
✗ Tujuan malicious

Pengguna bertanggung jawab penuh atas penggunaan alat ini.
```

🤝 Berkontribusi

Kontribusi sangat diterima! Silakan:

1. Fork repository ini
2. Buat feature branch (git checkout -b feature/AmazingFeature)
3. Commit changes (git commit -m 'Add some AmazingFeature')
4. Push to branch (git push origin feature/AmazingFeature)
5. Open Pull Request

📄 License

Distributed under MIT License. See LICENSE untuk detail lengkap.

👨‍💻 Developer

bocil-termux - GitHub

<div align="center">

⭐ Jangan lupa beri star jika project ini membantu! ⭐

</div>

---

<div align="center">

Gunakan dengan bijak dan bertanggung jawab! 🔐

</div>
