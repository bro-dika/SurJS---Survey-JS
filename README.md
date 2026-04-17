# SurJS — Survey JS

```
   ____            _ ____
  / ___| _   _ _ _| / ___|
  \___ \| | | | '__| \___ \
   ___) | |_| | |  | |___) |
  |____/ \__,_|_|  |_|____/

  JS File & Endpoint Extractor
  For Ethical Hacking / Bug Bounty Recon
  Use only on authorized targets!
```

SurJS (Survey JS) adalah tools reconnaissance berbasis Python yang dirancang untuk ethical hacking dan bug bounty hunting. Tools ini secara otomatis mengumpulkan seluruh URL file JavaScript yang terdapat pada page source suatu website, lalu menganalisis isi file-file tersebut untuk mengekstrak informasi yang berguna selama fase recon.

> ⚠️ **Disclaimer:** Gunakan hanya pada target yang telah mendapat izin resmi. Penggunaan tanpa otorisasi melanggar hukum.

---

## Fitur

- **JS File Discovery** — Menemukan URL file `.js` dari page source melalui tag `<script src>`, regex fallback, dan referensi string inline di dalam halaman.
- **Endpoint Extraction** — Mengekstrak path dan URL yang tersembunyi di dalam konten file JavaScript, mencakup absolute URL maupun relative path.
- **Secret Detection** — Mendeteksi potensi kebocoran API key, token, password, dan credentials lainnya yang mungkin ter-hardcode di dalam file JS.
- **Email Harvesting** — Mengumpulkan alamat email yang ditemukan di dalam file JavaScript.
- **IP Harvesting** — Mengumpulkan alamat IP yang ditemukan di dalam file JavaScript.
- **Common Sub-page Crawling** — Selain halaman utama, SurJS juga secara otomatis memeriksa sub-path umum seperti `/app`, `/assets`, `/static`, `/js`, `/dist`, `/build`, dan lainnya untuk menemukan lebih banyak file JS.
- **Rate Limiting** — Secara default membatasi request maksimal 3 req/s untuk menjaga etika dan tidak membebani server target.
- **Async Requests** — Semua request dijalankan secara asynchronous sehingga tetap efisien meski dengan rate limit aktif.
- **Output ke File** — Hasil scan dapat disimpan ke file teks untuk dokumentasi atau analisis lanjutan.

---

## Requirements

Python 3.10 atau lebih baru.

Install dependencies dengan perintah berikut:

```bash
pip install aiohttp beautifulsoup4 colorama
```

| Library | Fungsi |
|---|---|
| `aiohttp` | Async HTTP client untuk melakukan request ke target |
| `beautifulsoup4` | HTML parser untuk mengekstrak tag `<script>` dari page source |
| `colorama` | Pewarnaan output di terminal |

---

## Cara Menggunakan

### Sintaks Dasar

```bash
python3 SurJS.py <target> [opsi]
```

Target bisa berupa domain biasa atau subdomain, dengan atau tanpa `https://`.

---

### Contoh Penggunaan

**Scan domain utama:**
```bash
python3 SurJS.py example.com
```

**Scan subdomain:**
```bash
python3 SurJS.py sub.example.com
```

**Scan dengan URL lengkap:**
```bash
python3 SurJS.py https://app.example.com
```

**Simpan hasil ke file:**
```bash
python3 SurJS.py example.com -o hasil.txt
```

**Turunkan rate limit agar lebih lambat (1 req/s):**
```bash
python3 SurJS.py example.com -r 1
```

**Tampilkan semua request termasuk yang gagal:**
```bash
python3 SurJS.py example.com -v
```

**Kombinasi opsi:**
```bash
python3 SurJS.py example.com -r 2 -t 20 -o hasil.txt -v
```

---

### Daftar Opsi

| Opsi | Keterangan | Default |
|---|---|---|
| `target` | Domain atau URL target (wajib) | — |
| `-r`, `--rate` | Maksimum request per detik | `3` |
| `-t`, `--timeout` | Timeout per request (detik) | `15` |
| `-o`, `--output` | Simpan hasil ke file | — |
| `-v`, `--verbose` | Tampilkan request yang gagal/dilewati | `off` |
| `-h`, `--help` | Tampilkan bantuan | — |

---

## Alur Kerja

SurJS bekerja dalam 3 fase secara berurutan:

**Phase 1 — Main Page**
Mengambil halaman utama target dan mengekstrak semua URL file JavaScript yang ditemukan.

**Phase 2 — Common Sub-pages**
Mengunjungi sub-path umum (`/app`, `/js`, `/dist`, `/static`, dll.) untuk menemukan file JS tambahan yang tidak muncul di halaman utama.

**Phase 3 — JS Analysis**
Mengunduh dan menganalisis seluruh file JS yang ditemukan, lalu mengekstrak endpoints, secrets, email, dan IP dari dalamnya.

---

## Contoh Output

```
[*] Target   : https://example.com
[*] Rate     : 3 req/s  |  Timeout: 15s

[~] Phase 1 — Fetching main page ...
[+] [200] https://example.com
[i] Found 4 JS file(s) on main page

[~] Phase 2 — Checking common sub-pages ...
[+] [200] https://example.com/js
    └─ 2 new JS file(s)

[~] Phase 3 — Analysing 6 JS file(s) ...

[JS] [200] https://example.com/js/app.min.js
  ├─ Endpoints : 18
  ├─ Secrets   : 1  ⚠
  ├─ Emails    : 2
  └─ IPs       : 1

═══════════════════════════════════════════════════════
  SCAN SUMMARY — example.com
═══════════════════════════════════════════════════════
  Pages crawled  : 3
  JS files found : 6
  Endpoints      : 43
  Emails         : 3
  Internal IPs   : 2
  Potential Secrets: 1  ⚠  Review carefully!
═══════════════════════════════════════════════════════

[JS FILES]
  https://example.com/js/app.min.js
  https://example.com/js/vendor.js
  ...

[ENDPOINTS / PATHS]
  /api/v1/users
  /api/v1/auth/login
  ...

[POTENTIAL SECRETS — REVIEW CAREFULLY]
  >>> api_key = "AIzaSyXXXXXXXXXXXXXXXXXXXX"
```

---

## Lisensi

MIT License — bebas digunakan untuk keperluan edukasi dan security research yang sah.
