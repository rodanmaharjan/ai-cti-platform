# Import required libraries
# streamlit -> used to create the web dashboard
# pandas -> used for creating and managing tables/dataframes
# re -> used for regular expression pattern matching

import streamlit as st
import pandas as pd
import re


# Title displayed on the Streamlit web application
st.title("AI-Assisted IOC Analysis Tool")


# Short description shown below the title
st.write("Enter one or more Indicators of Compromise. Put each IOC on a new line.")


# Multi-line text box for user input
# Users can enter IPs, domains, or hashes
ioc_input = st.text_area(
    "Enter IOCs",
    placeholder="192.168.10.10\nmalicious-example.com\n44d88612fea8a8f36de82e1278abb02f"
)


# Function to identify the type of IOC entered by the user
def detect_type(ioc):

    # Regular expression for IPv4 addresses
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

    # Regular expression for MD5, SHA1, and SHA256 hashes
    hash_pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"

    # Regular expression for domain names
    domain_pattern = r"^(?!-)[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

    # Check if IOC matches IP pattern
    if re.match(ip_pattern, ioc):
        return "IP Address"

    # Check if IOC matches hash pattern
    elif re.match(hash_pattern, ioc):
        return "File Hash"

    # Check if IOC matches domain pattern
    elif re.match(domain_pattern, ioc):
        return "Domain"

    # If no pattern matches, classify as Unknown
    else:
        return "Unknown"


# Function to map IOC type to a MITRE ATT&CK technique
def mitre_mapping(ioc_type):

    if ioc_type == "IP Address":
        return "T1046 - Network Service Discovery"

    elif ioc_type == "Domain":
        return "T1566 - Phishing"

    elif ioc_type == "File Hash":
        return "T1204 - User Execution"

    else:
        return "Not mapped"


# Function to assign risk level based on IOC type
def risk_level(ioc_type):

    # Domains and hashes are treated as higher risk
    if ioc_type in ["Domain", "File Hash"]:
        return "High"

    # IP addresses are treated as medium risk
    elif ioc_type == "IP Address":
        return "Medium"

    # Unknown IOC types are treated as low risk
    else:
        return "Low"


# Function to generate a security recommendation
def recommendation(ioc_type):

    if ioc_type == "IP Address":
        return "Investigate source, check logs, and monitor traffic."

    elif ioc_type == "Domain":
        return "Block domain, check DNS logs, and investigate related activity."

    elif ioc_type == "File Hash":
        return "Check endpoint logs and scan affected systems."

    else:
        return "Manually review this IOC."


# Streamlit button
# Code below executes only when user clicks "Analyse IOCs"
if st.button("Analyse IOCs"):

    # Check if input field is empty
    if not ioc_input.strip():

        # Display warning message
        st.warning("Please enter at least one IOC.")

    else:

        # Split input into separate lines
        # Remove empty spaces/new lines
        iocs = [line.strip() for line in ioc_input.splitlines() if line.strip()]

        # Empty list to store analysis results
        results = []

        # Process each IOC entered by the user
        for ioc in iocs:

            # Detect IOC type
            ioc_type = detect_type(ioc)

            # Store analysis result in dictionary format
            results.append({
                "IOC": ioc,
                "IOC Type": ioc_type,
                "Risk Level": risk_level(ioc_type),
                "MITRE ATT&CK Mapping": mitre_mapping(ioc_type),
                "Recommendation": recommendation(ioc_type)
            })

        # Convert results list into Pandas DataFrame
        df = pd.DataFrame(results)

        # Display section heading
        st.subheader("Analysis Results")


        # Apply colour styling to Risk Level column
        # High -> Red
        # Medium -> Orange
        # Low -> Green
        styled_df = df.style.map(
            lambda x: "color: red;" if x == "High"
            else "color: orange;" if x == "Medium"
            else "color: green;" if x == "Low"
            else "",
            subset=["Risk Level"]
        )

        # Display styled dataframe on Streamlit dashboard
        st.dataframe(styled_df, use_container_width=True)

        # Convert dataframe to CSV format for downloading
        csv = df.to_csv(index=False).encode("utf-8")

        # Button to download CSV report
        st.download_button(
            label="Download CSV Report",
            data=csv,
            file_name="ioc_analysis_report.csv",
            mime="text/csv"
        )