import streamlit as st
import os

st.set_option('server.enableStaticFileSharing', False)

st.title("Secure Streamlit App")
st.write("This app does not allow static file sharing to prevent vulnerabilities.")