def safe_expand_row(row_data, expected_length):
    if len(row_data) > expected_length:
        raise ValueError("Row data exceeds expected length")
    processed_row = row_data
    return processed_row

def decode_rle_image(image_data):
    for row in image_data:
        try:
            processed_row = safe_expand_row(row, expected_length=100)
        except ValueError as e:
            print(f"Error processing row: {e}")
            continue