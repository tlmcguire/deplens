import snowflake.connector

def validate_sso_url(url):
    trusted_domains = ["trusted-domain.com", "another-trusted-domain.com"]
    return any(domain in url for domain in trusted_domains)

sso_url = 'https://malicious-server.com/snowflake_sso'

conn = snowflake.connector.connect(
    user='username',
    password='password',
    account='account_name',
    warehouse='warehouse_name',
    database='database_name',
    schema='schema_name',
    sso_browser_auth=True
)

if not validate_sso_url(sso_url):
    raise ValueError("Invalid SSO URL")

conn.snowflake.connector.SnowflakeConnection.sso_browser_auth(sso_url)