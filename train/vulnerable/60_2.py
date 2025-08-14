import test.multibytecodec_support as mbc_support

url = "http://evil.com/cve-2020-27619"

mbc_support.test_decode_refex("euc_kr", url)