import frappe
from frappe import _

@frappe.whitelist()
def safe_get_list(doctype, fields=None, filters=None, limit=None):
    allowed_fields = frappe.get_meta(doctype).get_fieldnames()

    if fields is not None:
        fields = [field for field in fields if field in allowed_fields]

    return frappe.get_list(doctype, fields=fields, filters=filters, limit=limit)