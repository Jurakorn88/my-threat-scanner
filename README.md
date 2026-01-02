# 🛡️ Pro Threat Intel Scanner

**[English]**
A powerful, web-based Threat Intelligence tool built with Python and Streamlit. It aggregates data from **AbuseIPDB**, **VirusTotal**, and **AlienVault OTX** to analyze IPs, Domains, and Hashes in real-time. Designed with a hybrid authentication system and smart caching to optimize API quota usage.

**[ภาษาไทย]**
เครื่องมือตรวจสอบภัยคุกคามทางไซเบอร์ (Threat Intelligence) บนเว็บ พัฒนาด้วย Python และ Streamlit ช่วยให้คุณตรวจสอบ IP, Domain และ Hash ได้ทันที โดยดึงข้อมูลจาก **AbuseIPDB**, **VirusTotal**, และ **AlienVault OTX** มาแสดงผลในที่เดียว พร้อมระบบจัดการ Quota และ Smart Caching เพื่อประหยัดการใช้งาน API

---

## ✨ Key Features (ฟีเจอร์เด่น)

* **🔐 Hybrid Authentication:**
    * **Public Mode:** Anyone can use the tool by providing their own API keys.
    * **Admin Mode:** Secure login for the owner to auto-load private API keys from secrets.
* **🧠 Smart Caching:** Automatically filters duplicate inputs to save API quota. Scans unique IOCs once but maps results back to all original input lines.
* **🎛️ Selectable Scanners:** Toggle specific Threat Intel sources (AbuseIPDB, VT, OTX) on/off as needed.
* **📊 Real-time Quota Monitoring:** Displays remaining API credits immediately after each scan.
* **📂 CSV Export:** Download scan results for reporting.

---

## 🚀 How to Use (วิธีการใช้งาน)

### 1. Choose Your Mode (เลือกโหมดการใช้งาน)

#### 👤 Public Mode (For General Users)
* **No login required.**
* Enter your own **API Keys** in the sidebar settings.
* *เหมาะสำหรับผู้ใช้ทั่วไป: ต้องกรอก API Key ของตัวเองในแถบด้านซ้าย*

#### 👑 Admin Mode (For Owner)
* Go to the sidebar and click **"🔐 Admin Login"**.
* Enter the **Admin Password**.
* Once logged in, API Keys will be **auto-loaded** securely.
* *เหมาะสำหรับเจ้าของ: กดปุ่ม Admin Login ใส่รหัสผ่าน แล้วระบบจะดึง Key มาใส่ให้อัตโนมัติ*

### 2. Configure Scanners (ตั้งค่าการสแกน)
* Check/Uncheck the boxes in the sidebar to select which sources to query:
    * ✅ **Abuse:** Check AbuseIPDB (IPs only).
    * ✅ **VT:** Check VirusTotal.
    * ✅ **OTX:** Check AlienVault OTX.
* Adjust **Speed (Threads)** slider to control scanning speed.
* *เลือกแหล่งข้อมูลที่ต้องการสแกน (ติ๊กถูก) และปรับความเร็วในการสแกนได้*

### 3. Input & Scan (ใส่ข้อมูลและเริ่มสแกน)
* Paste your list of **IPs, Domains, or Hashes** into the main text area (one per line).
* Click **"🚀 START SCAN"**.
* *วางรายการ IP/Domain/Hash ที่ต้องการตรวจสอบ (บรรทัดละ 1 ตัว) แล้วกดปุ่ม Start*

### 4. View Results (ดูผลลัพธ์)
* **Verdict:** The system categorizes items as <span style="color:#ff4b4b">**MALICIOUS**</span>, <span style="color:#ffa421">**SUSPICIOUS**</span>, or <span style="color:#21c354">**CLEAN**</span> based on aggregated scores.
* **Quota Status:** Check the sidebar to see your remaining API limits.
* **Export:** Click **"📥 Export CSV"** to save the report.

---

## 🛠️ Installation (For Developers)

To run this tool locally:

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YourUsername/pro-threat-hunter.git](https://github.com/YourUsername/pro-threat-hunter.git)
    cd pro-threat-hunter
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Setup Secrets (Local):**
    Create a file `.streamlit/secrets.toml` and add your keys:
    ```toml
    admin_password = "YOUR_PASSWORD"
    abuse_key = "YOUR_ABUSEIPDB_KEY"
    vt_key = "YOUR_VIRUSTOTAL_KEY"
    otx_key = "YOUR_OTX_KEY"
    ```

4.  **Run the app:**
    ```bash
    streamlit run main.py
    ```

---

## ⚖️ Disclaimer

This tool is for **educational and security research purposes only**. The developer is not responsible for any misuse of the data or violation of third-party API Terms of Service. Please use responsibly.

เครื่องมือนี้จัดทำขึ้นเพื่อการศึกษาและการตรวจสอบความปลอดภัยเท่านั้น ผู้พัฒนาไม่มีส่วนรับผิดชอบต่อการนำไปใช้ในทางที่ผิด หรือการละเมิดเงื่อนไขการให้บริการของ Third-party APIs

---
*Created with ❤️ by Jurakorn88
