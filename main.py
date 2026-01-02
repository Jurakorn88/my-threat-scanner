import streamlit as st
import pandas as pd
import requests
import re
import time
import pycountry
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional

# ==========================================
# 1. SETUP & STYLING
# ==========================================
st.set_page_config(page_title="บริษัทไม่มีให้เลยต้องทำเอง Threat Intel Scanner", page_icon="🛡️", layout="wide")

# แก้ไข CSS: เพิ่ม color: white; เพื่อให้ตัวหนังสือสีขาวชัดเจนบนพื้นหลังดำ
st.markdown("""
<style>
    .stButton>button { width: 100%; border-radius: 8px; font-weight: bold; }
    div[data-testid="stMetricValue"] { font-size: 1.8rem; }
    .quota-box { 
        padding: 10px; 
        background-color: #262730; 
        border-radius: 5px; 
        margin-bottom: 10px;
        border-left: 3px solid #ff4b4b;
        color: white;  /* <--- เพิ่มบรรทัดนี้ครับ เพื่อบังคับตัวอักษรสีขาว */
    }
    .quota-box small {
        color: #d0d0d0; /* สีเทาอ่อนสำหรับตัวหนังสือ label เล็กๆ */
    }
</style>
""", unsafe_allow_html=True)

# ==========================================
# 2. CORE LOGIC (SCANNER ENGINE)
# ==========================================
class ScannerEngine:
    """Handles API connections and processing logic."""
    
    def __init__(self, api_keys: Dict[str, str], enabled_apis: Dict[str, bool], proxies: Optional[Dict[str, str]] = None):
        self.api_keys = api_keys
        self.enabled_apis = enabled_apis
        self.proxies = proxies
        self.timeout = 10

    def _clean_ioc(self, ioc: str) -> str:
        ioc = ioc.strip()
        if re.match(r'^https?://', ioc):
            try:
                parsed = urlparse(ioc)
                domain = parsed.netloc
                return domain.split(":")[0] if ":" in domain else domain
            except: pass
        return ioc

    def _identify_type(self, ioc: str) -> str:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc): return "IP"
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc): return "Hash"
        if "." in ioc and "/" not in ioc: return "Domain"
        return "Unknown"

    def _get_country(self, code: str) -> str:
        try: return pycountry.countries.get(alpha_2=code).name
        except: return code or "-"

    def _extract_quota(self, headers, key_variations):
        for k in key_variations:
            if k in headers:
                return headers[k]
        return None

    def check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        key = self.api_keys.get('abuse')
        if not self.enabled_apis.get('abuse') or not key: 
            return {"score": 0, "raw": "-", "country": "-", "isp": "-", "quota": None}
            
        try:
            r = requests.get('https://api.abuseipdb.com/api/v2/check', 
                             headers={'Accept': 'application/json', 'Key': key}, 
                             params={'ipAddress': ip, 'maxAgeInDays': '90'},
                             proxies=self.proxies, timeout=self.timeout)
            
            quota_left = self._extract_quota(r.headers, ['X-RateLimit-Remaining', 'x-ratelimit-remaining'])
            
            if r.status_code == 200:
                d = r.json().get('data', {})
                return {
                    "score": d.get('abuseConfidenceScore', 0),
                    "raw": f"{d.get('abuseConfidenceScore', 0)}%",
                    "country": self._get_country(d.get('countryCode')),
                    "isp": d.get('isp', '-'),
                    "quota": quota_left
                }
        except: pass
        return {"score": 0, "raw": "Err", "country": "-", "isp": "-", "quota": None}

    def check_virustotal(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        key = self.api_keys.get('vt')
        if not self.enabled_apis.get('vt') or not key: 
            return {"mal": 0, "raw": "-", "malware": "-", "country": "-", "isp": "-", "quota": None}
            
        ep = {"IP": "ip_addresses", "Domain": "domains", "Hash": "files"}.get(ioc_type, "files")
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/{ep}/{ioc}", 
                             headers={"x-apikey": key}, proxies=self.proxies, timeout=self.timeout)
            
            quota_left = self._extract_quota(r.headers, ['x-daily-requests-left', 'X-RateLimit-Remaining-Day'])

            if r.status_code == 200:
                d = r.json().get('data', {}).get('attributes', {})
                stats = d.get('last_analysis_stats', {})
                return {
                    "mal": stats.get('malicious', 0),
                    "raw": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                    "malware": d.get('popular_threat_classification', {}).get('suggested_threat_label', '-'),
                    "country": self._get_country(d.get('country')) if 'country' in d else None,
                    "isp": d.get('as_owner') if 'as_owner' in d else None,
                    "quota": quota_left
                }
            elif r.status_code == 429: return {"mal": 0, "raw": "Limit", "malware": "-", "country": "-", "isp": "-", "quota": "0"}
        except: pass
        return {"mal": 0, "raw": "Err", "malware": "-", "country": "-", "isp": "-", "quota": None}

    def check_otx(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        key = self.api_keys.get('otx')
        if not self.enabled_apis.get('otx') or not key: 
            return {"pulses": 0, "raw": "-", "quota": None}
            
        ep = "IPv4" if ioc_type == "IP" else "domain" if ioc_type == "Domain" else "file"
        try:
            r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/{ep}/{ioc}/general", 
                             headers={'X-OTX-API-KEY': key}, proxies=self.proxies, timeout=self.timeout)
            
            quota_left = self._extract_quota(r.headers, ['X-RateLimit-Remaining', 'X-OTX-API-Limit-Remaining'])

            if r.status_code == 200:
                c = r.json().get('pulse_info', {}).get('count', 0)
                return {"pulses": c, "raw": str(c), "quota": quota_left}
        except: pass
        return {"pulses": 0, "raw": "Err", "quota": None}

    def scan(self, original_ioc: str) -> Dict[str, Any]:
        clean = self._clean_ioc(original_ioc)
        itype = self._identify_type(clean)
        
        res_abuse = self.check_abuseipdb(clean) if itype == "IP" else {"score": 0, "raw": "-", "country": "-", "isp": "-", "quota": None}
        res_vt = self.check_virustotal(clean, itype)
        res_otx = self.check_otx(clean, itype)

        verdict = "CLEAN"
        if res_vt['mal'] >= 3 or res_abuse['score'] >= 50 or res_otx['pulses'] >= 10: verdict = "MALICIOUS"
        elif res_vt['mal'] >= 1 or res_abuse['score'] > 0 or res_otx['pulses'] > 0: verdict = "SUSPICIOUS"

        final_country = res_abuse['country'] if res_abuse['country'] not in ["-", None] else res_vt.get('country', "-")
        final_isp = res_abuse['isp'] if res_abuse['isp'] not in ["-", None] else res_vt.get('isp', "-")

        return {
            "IOC": original_ioc, "Type": itype, "Verdict": verdict,
            "AbuseIPDB": res_abuse['raw'], "VirusTotal": res_vt['raw'], "OTX": res_otx['raw'],
            "Malware": res_vt['malware'], "Country": final_country or "-", "ISP": final_isp or "-",
            "_quotas": {
                "AbuseIPDB": res_abuse.get('quota'),
                "VirusTotal": res_vt.get('quota'),
                "OTX": res_otx.get('quota')
            }
        }

# ==========================================
# 3. UI & AUTHENTICATION (HYBRID MODE)
# ==========================================
def main():
    with st.sidebar:
        st.title("⚙️ Settings")
        
        if "is_admin" not in st.session_state:
            st.session_state.is_admin = False

        if not st.session_state.is_admin:
            with st.expander("🔐 Admin Login"):
                password = st.text_input("Admin Password", type="password")
                if password:
                    secret_pass = st.secrets.get("admin_password", "")
                    if secret_pass and password == secret_pass:
                        st.session_state.is_admin = True
                        st.success("Logged in!")
                        st.rerun()
                    else:
                        st.error("Wrong password")
        else:
            st.success("✅ Admin Mode Active")
            if st.button("Logout"):
                st.session_state.is_admin = False
                st.rerun()

        st.divider()

        default_abuse = st.secrets.get("abuse_key", "") if st.session_state.is_admin else ""
        default_vt = st.secrets.get("vt_key", "") if st.session_state.is_admin else ""
        default_otx = st.secrets.get("otx_key", "") if st.session_state.is_admin else ""

        abuse_key = st.text_input("AbuseIPDB Key", value=default_abuse, type="password", disabled=st.session_state.is_admin)
        vt_key = st.text_input("VirusTotal Key", value=default_vt, type="password", disabled=st.session_state.is_admin)
        otx_key = st.text_input("OTX Key", value=default_otx, type="password", disabled=st.session_state.is_admin)

        st.divider()
        st.caption("Active Scanners")
        col_chk1, col_chk2, col_chk3 = st.columns(3)
        with col_chk1: use_abuse = st.checkbox("Abuse", value=True)
        with col_chk2: use_vt = st.checkbox("VT", value=True)
        with col_chk3: use_otx = st.checkbox("OTX", value=True)
        
        st.divider()
        max_threads = st.slider("Speed (Threads)", 1, 10, 4)

        # --- QUOTA DISPLAY ---
        st.divider()
        st.subheader("📊 Quota Status")
        
        if "quota_status" not in st.session_state:
            st.session_state.quota_status = {"AbuseIPDB": "-", "VirusTotal": "-", "OTX": "-"}
        
        q = st.session_state.quota_status
        # แสดงผลโดยใช้ class quota-box ที่เราแก้สีตัวอักษรแล้ว
        st.markdown(f"""
        <div class="quota-box">
            <small>AbuseIPDB Left:</small><br><b>{q['AbuseIPDB']}</b>
        </div>
        <div class="quota-box">
            <small>VirusTotal Left:</small><br><b>{q['VirusTotal']}</b>
        </div>
        <div class="quota-box">
            <small>OTX Left:</small><br><b>{q['OTX']}</b>
        </div>
        """, unsafe_allow_html=True)

    st.title("🛡️ บริษัทไม่มีให้เลยต้องทำเอง Threat Intel Scanner")
    st.caption(f"Mode: {'👑 Admin (Auto-Keys)' if st.session_state.is_admin else '👤 Public (Manual Keys)'}")

    if 'results' not in st.session_state:
        st.session_state.results = pd.DataFrame()

    col1, col2 = st.columns([3, 1])
    with col1:
        ioc_input = st.text_area("Input IOCs (IP, Domain, Hash)", height=150, placeholder="8.8.8.8\n1.1.1.1")
    with col2:
        st.write("##")
        if st.button("🚀 START SCAN", type="primary", use_container_width=True):
            if not ioc_input.strip():
                st.error("Enter IOCs first!")
            else:
                api_config = {'abuse': abuse_key, 'vt': vt_key, 'otx': otx_key}
                enabled_apis = {'abuse': use_abuse, 'vt': use_vt, 'otx': use_otx}
                
                scanner = ScannerEngine(api_config, enabled_apis)
                
                raw_lines_all = [x.strip() for x in ioc_input.split('\n') if x.strip()]
                unique_iocs_to_scan = list(set(raw_lines_all))
                results_map = {} 
                
                prog_bar = st.progress(0)
                status_box = st.status("Scanning...", expanded=True)
                
                with status_box:
                    with ThreadPoolExecutor(max_threads) as exe:
                        futures = {exe.submit(scanner.scan, ioc): ioc for ioc in unique_iocs_to_scan}
                        for i, f in enumerate(as_completed(futures)):
                            res = f.result()
                            results_map[res['IOC']] = res 
                            
                            new_quotas = res.get('_quotas', {})
                            for k, v in new_quotas.items():
                                if v is not None:
                                    st.session_state.quota_status[k] = v
                            
                            prog_bar.progress((i+1)/len(unique_iocs_to_scan))
                            status_box.write(f"Checked: {res['IOC']} -> {res['Verdict']}")
                    
                    status_box.update(label="Done!", state="complete", expanded=False)
                
                final_display_data = []
                for line in raw_lines_all:
                    if line in results_map:
                        clean_data = {k:v for k,v in results_map[line].items() if not k.startswith('_')}
                        final_display_data.append(clean_data)
                
                st.session_state.results = pd.DataFrame(final_display_data)
                st.rerun()

    if not st.session_state.results.empty:
        df = st.session_state.results
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Rows", len(df))
        c2.metric("Malicious", len(df[df['Verdict']=='MALICIOUS']), delta_color="inverse")
        c3.metric("Suspicious", len(df[df['Verdict']=='SUSPICIOUS']), delta_color="off")
        c4.metric("Clean", len(df[df['Verdict']=='CLEAN']))
        
        def color_verdict(val):
            c = '#ff4b4b' if val == 'MALICIOUS' else '#ffa421' if val == 'SUSPICIOUS' else '#21c354'
            return f'color: {c}; font-weight: bold'

        st.dataframe(
            df.style.map(color_verdict, subset=['Verdict']),
            column_config={
                "AbuseIPDB": st.column_config.TextColumn("AbuseIPDB %"),
                "VirusTotal": st.column_config.TextColumn("VT Score"),
                "OTX": st.column_config.NumberColumn("OTX Pulses"),
            },
            use_container_width=True, height=500
        )
        
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Export CSV", csv, "scan_results.csv", "text/csv")
        if st.button("Clear"):
            st.session_state.results = pd.DataFrame()
            st.rerun()

if __name__ == "__main__":

    main()

