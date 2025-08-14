import logging
import re


def log_partition_update(partition_data):


    masked_data = mask_sensitive_data(partition_data)
    logging.getLogger("zhmcclient.api").info(f"Partition update: {masked_data}")
    logging.getLogger("zhmcclient.hmc").info(f"Partition update: {masked_data}")



def mask_sensitive_data(data):
    masked_data = data.copy()
    for key in ["boot-ftp-password", "ssc-master-pw", "zaware-master-pw", "password", "bind-password"]:
        if key in masked_data:
            masked_data[key] = "***MASKED***"
    return masked_data

partition_data = {
    "name": "mypartition",
    "boot-ftp-password": "mysecretpassword",
    "other_property": "somevalue"
}

log_partition_update(partition_data)
