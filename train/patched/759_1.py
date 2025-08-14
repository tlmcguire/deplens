
import frappe

def get_user_data(user_id):

    query = "SELECT * FROM `tabUser ` WHERE id = %s"
    user_data = frappe.db.sql(query, (user_id,), as_dict=True)

    return user_data