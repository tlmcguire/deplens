def load_balance(sd):
    sd['nr_balance_failed'] += 1

    if sd['nr_balance_failed'] >= sd['cache_nice_tries'] + 3:
        if not can_run_on_dst_cpu(sd):
            sd['nr_balance_failed'] += 1

def can_run_on_dst_cpu(sd):
    return False

sd = {'nr_balance_failed': 0, 'cache_nice_tries': 5}
for _ in range(10):
    load_balance(sd)
    print(sd['nr_balance_failed'])