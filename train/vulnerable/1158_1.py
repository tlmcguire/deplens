import streamlit as st

st.set_option('server.enableStaticFileSharing', True)

st.title("Vulnerable Streamlit App")
st.write("This app allows static file sharing, which can lead to vulnerabilities.")