import frappe

@frappe.whitelist()
def vulnerable_get_list(doctype, fields=None, filters=None, limit=None):
    return frappe.get_list(doctype, fields=fields, filters=filters, limit=limit)