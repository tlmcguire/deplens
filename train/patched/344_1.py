from dask.distributed import LocalCluster, Client

cluster = LocalCluster(ip='127.0.0.1')
client = Client(cluster)

print("Dask client created with restricted access to localhost")