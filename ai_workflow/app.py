import streamlit as st

st.title("AI-Assisted IOC Analysis Tool")

ioc = st.text_input("Enter IOC")

if st.button("Analyse"):
    st.write(f"IOC Submitted: {ioc}")
    st.write("Risk Level: Medium")