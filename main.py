# ... (ส่วน ScannerEngine เหมือนเดิม) ...

# ==========================================
# 3. UI & LOGIC
# ==========================================
def main():
    # ... (ส่วน Sidebar เหมือนเดิม) ...

    st.title("🛡️ Threat Intel Scanner")

    # --- INPUT AREA ---
    ioc_input = st.text_area("Input IOCs (one per line)", height=150, placeholder="8.8.8.8\n1.1.1.1\n8.8.8.8", key="ioc_area")

    if st.button("🚀 START SCAN", type="primary"):
        if not ioc_input.strip():
            st.error("Please enter some IOCs!")
        else:
            api_config = {'abuse': abuse_key, 'vt': vt_key, 'otx': otx_key}
            enabled_apis = {'abuse': use_abuse, 'vt': use_vt, 'otx': use_otx}
            scanner = ScannerEngine(api_config, enabled_apis)
            
            raw_lines = [x.strip() for x in ioc_input.split('\n') if x.strip()]
            
            prog_bar = st.progress(0)
            status_box = st.status("Scanning IOCs...", expanded=True)
            results_list = []

            with ThreadPoolExecutor(max_threads) as exe:
                futures = {exe.submit(scanner.scan, ioc): ioc for ioc in raw_lines}
                for i, f in enumerate(as_completed(futures)):
                    res = f.result()
                    results_list.append(res)
                    for k, v in res.get('_quotas', {}).items():
                        if v is not None: st.session_state.quota_status[k] = v
                    prog_bar.progress((i+1)/len(raw_lines))
            
            status_box.update(label="Scan Complete!", state="complete", expanded=False)
            display_data = [{k: v for k, v in r.items() if not k.startswith('_')} for r in results_list]
            st.session_state.results = pd.DataFrame(display_data)
            st.rerun()

    # --- RESULTS AREA ---
    if not st.session_state.results.empty:
        df = st.session_state.results
        
        # Dashboard Metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Rows", len(df))
        m2.metric("Malicious", len(df[df['Verdict']=='MALICIOUS']))
        m3.metric("Suspicious", len(df[df['Verdict']=='SUSPICIOUS']))
        m4.metric("Clean", len(df[df['Verdict']=='CLEAN']))

        st.divider()
        
        # --- ACTION BUTTONS (Deduplicate is here!) ---
        col_act1, col_act2, col_act3 = st.columns([1.5, 1, 3])
        
        with col_act1:
            if st.button("🧹 Remove Duplicate IOCs", use_container_width=True):
                # ลบแถวที่ IOC ซ้ำกัน (เก็บแถวแรกไว้)
                st.session_state.results = st.session_state.results.drop_duplicates(subset=['IOC'], keep='first')
                st.toast("Duplicates removed!")
                st.rerun()
        
        with col_act2:
            if st.button("🗑️ Clear All", use_container_width=True):
                st.session_state.results = pd.DataFrame()
                st.rerun()

        # --- FILTERING UI ---
        st.write("### 🔍 Filters")
        f_col1, f_col2 = st.columns([1, 2])
        with f_col1:
            filter_verdict = st.multiselect("Verdict Status", options=["MALICIOUS", "SUSPICIOUS", "CLEAN"], default=["MALICIOUS", "SUSPICIOUS", "CLEAN"])
        with f_col2:
            search_query = st.text_input("Search anything (IP, Country, ISP, Malware name...)", placeholder="Type to filter...")

        # Apply Filtering Logic
        filtered_df = df[df['Verdict'].isin(filter_verdict)]
        if search_query:
            # ค้นหาทุกคอลัมน์
            filtered_df = filtered_df[filtered_df.apply(lambda row: row.astype(str).str.contains(search_query, case=False).any(), axis=1)]

        # --- DISPLAY DATAFRAME ---
        def color_verdict(val):
            color = '#ff4b4b' if val == 'MALICIOUS' else '#ffa421' if val == 'SUSPICIOUS' else '#21c354'
            return f'color: {color}; font-weight: bold'

        st.dataframe(
            filtered_df.style.map(color_verdict, subset=['Verdict']),
            use_container_width=True,
            height=600,
            column_config={
                "IOC": st.column_config.TextColumn("Indicator", width="medium"),
                "AbuseIPDB": st.column_config.TextColumn("Abuse %"),
                "VirusTotal": st.column_config.TextColumn("VT Score"),
                "Verdict": st.column_config.TextColumn("Status")
            }
        )
        
        # Download Button
        st.download_button(
            label="📥 Export Filtered Results to CSV",
            data=filtered_df.to_csv(index=False).encode('utf-8'),
            file_name="threat_intel_report.csv",
            mime="text/csv"
        )
