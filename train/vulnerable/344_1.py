from dask.distributed import LocalCluster, Client

cluster = LocalCluster()
client = Client(cluster)

print("Dask client created with external access")