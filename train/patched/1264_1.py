def set_property_value(self, name, value):
    """
    Sets the value of a property on the component.

    This version includes a safelist of allowed property names
    to prevent arbitrary attribute modification.
    """

    allowed_properties = ["name", "message", "count", "items"]

    if name not in allowed_properties:
        logger.warning(f"Attempted to set disallowed property: {name}")
        return

    try:
        setattr(self, name, value)
    except Exception as e:
        logger.exception(f"Failed to set property {name} to {value}: {e}")
