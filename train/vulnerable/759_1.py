
import frappe

def get_user_data(user_id):
    query = "SELECT * FROM `tabUser ` WHERE id = '{}'".format(user_id)
    user_data = frappe.db.sql(query, as_dict=True)

    return user_data