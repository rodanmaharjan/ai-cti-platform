import streamlit as st
import pandas as pd
import re

st.title("AI-Assisted IOC Analysis Tool")

st.write("Enter one or more Indicators of Compromise. Put each IOC on a new line.")

ioc_input = st.text_area(
    "Enter IOCs",
    placeholder="192.168.10.10\nmalicious-example.com\n44d88612fea8a8f36de82e1278abb02f"
)

def detect_type(ioc):
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    hash_pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
    domain_pattern = r"^(?!-)[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

    if re.match(ip_pattern, ioc):
        return "IP Address"
    elif re.match(hash_pattern, ioc):
        return "File Hash"
    elif re.match(domain_pattern, ioc):
        return "Domain"
    else:
        return "Unknown"

def mitre_mapping(ioc_type):
    if ioc_type == "IP Address":
        return "T1046 - Network Service Discovery"
    elif ioc_type == "Domain":
        return "T1566 - Phishing"
    elif ioc_type == "File Hash":
        return "T1204 - User Execution"
    else:
        return "Not mapped"

def risk_level(ioc_type):
    if ioc_type in ["Domain", "File Hash"]:
        return "High"
    elif ioc_type == "IP Address":
        return "Medium"
    else:
        return "Low"

def recommendation(ioc_type):
    if ioc_type == "IP Address":
        return "Investigate source, check logs, and monitor traffic."
    elif ioc_type == "Domain":
        return "Block domain, check DNS logs, and investigate related activity."
    elif ioc_type == "File Hash":
        return "Check endpoint logs and scan affected systems."
    else:
        return "Manually review this IOC."

if st.button("Analyse IOCs"):
    if not ioc_input.strip():
        st.warning("Please enter at least one IOC.")
    else:
        iocs = [line.strip() for line in ioc_input.splitlines() if line.strip()]
        results = []

        for ioc in iocs:
            ioc_type = detect_type(ioc)

            results.append({
                "IOC": ioc,
                "IOC Type": ioc_type,
                "Risk Level": risk_level(ioc_type),
                "MITRE ATT&CK Mapping": mitre_mapping(ioc_type),
                "Recommendation": recommendation(ioc_type)
            })

        df = pd.DataFrame(results)

        st.subheader("Analysis Results")

        styled_df = df.style.map(
            lambda x: "color: red;" if x == "High"
            else "color: orange;" if x == "Medium"
            else "color: green;" if x == "Low"
            else "",
            subset=["Risk Level"]
        )

        st.dataframe(styled_df, use_container_width=True)

        csv = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="Download CSV Report",
            data=csv,
            file_name="ioc_analysis_report.csv",
            mime="text/csv"
        )