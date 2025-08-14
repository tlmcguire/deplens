import sqlparse

sql = """
-- This is a comment
SELECT * FROM users;  -- Another comment
"""

formatted_sql = sqlparse.format(sql, strip_comments=False)
print(formatted_sql)