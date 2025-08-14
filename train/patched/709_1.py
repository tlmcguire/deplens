from pyspark import SparkConf, SparkContext
import os
import secrets

encryption_key = secrets.token_hex(32)


conf = SparkConf()
conf.set("spark.io.encryption.enabled", "true")
conf.set("spark.io.encryption.key", encryption_key)
conf.set("spark.maxRemoteBlockSizeFetchToMem", "64m")
conf.set("spark.ssl.enabled", "true")
conf.set("spark.ssl.keyStore", "keystore.jks")
conf.set("spark.ssl.keyStorePassword", "keystore_password")
conf.set("spark.ssl.trustStore", "truststore.jks")
conf.set("spark.ssl.trustStorePassword", "truststore_password")



sc = SparkContext(conf=conf)

data = [1, 2, 3, 4, 5]

rdd = sc.parallelize(data)

broadcast_var = sc.broadcast(rdd.collect())

result = rdd.map(lambda x: x * 2).collect()

print(result)

sc.stop()