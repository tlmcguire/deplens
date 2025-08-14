def safe_format_columns(columns):
    MAX_COLUMNS = 100
    if len(columns) > MAX_COLUMNS:
        raise ValueError("Too many columns provided, limit is {}".format(MAX_COLUMNS))

    formatted_columns = [str(column) for column in columns]
    return formatted_columns