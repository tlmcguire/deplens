import test.multibytecodec_support as mbc_support

url = "http://example.com/refex_euc_kr.txt"

mbc_support.test_decode_refex("euc_kr", url)