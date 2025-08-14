import email.header
import email.utils

def demonstrate_cve_2025_1795(display_name, email_address, charset='utf-8'):
    """
    Demonstrates a potential issue related to unicode encoding of commas
    in email headers during address list folding.  This is a simplified
    representation of the potential vulnerability.
    """

    full_address = email.utils.formataddr((display_name, email_address))
    header_value = email.header.Header(full_address, charset)



    encoded_header = str(header_value)

    print("Encoded Header (Potential Vulnerability):", encoded_header)

if __name__ == '__main__':
    display_name = "Some User with Unicode Name éàçüöß"
    email_address = "user@example.com"
    demonstrate_cve_2025_1795(display_name, email_address)


    display_name = "VeryLongNameWithUnicodeCharacters éàçüöß that causes folding"
    email_address = "user@example.com"
    demonstrate_cve_2025_1795(display_name, email_address)