import psycopg2

def execute_cypher_query(graph_name, cypher_query, params):
    conn = psycopg2.connect(database="your_database", user="your_user", password="your_password", host="localhost", port="5432")
    cursor = conn.cursor()


    try:
        cursor.callproc("set_cypher_params", (graph_name, cypher_query))

        cursor.execute("SELECT cypher()")

        results = cursor.fetchall()
    except psycopg2.Error as e:
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.commit()
        conn.close()

    return results

graph_name = "my_graph"
cypher_query = "MATCH (n) RETURN n"
params = {}
try:
    results = execute_cypher_query(graph_name, cypher_query, params)
    print(results)
except psycopg2.Error as e:
    print(f"An error occurred: {e}")
