from pyspark import SparkConf, SparkContext

conf = SparkConf()
conf.set("spark.io.encryption.enabled", "true")
conf.set("spark.maxRemoteBlockSizeFetchToMem", "64m")

sc = SparkContext(conf=conf)

data = [1, 2, 3, 4, 5]

rdd = sc.parallelize(data)

broadcast_var = sc.broadcast(rdd.collect())

def multiply_by_two(x):
    return x * 2

result = rdd.map(multiply_by_two).collect()

print(result)

sc.stop()