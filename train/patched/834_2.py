def upgrade_synapse():
    """
    Upgrades Synapse, addressing security vulnerabilities.
    """

    print("Upgrading Synapse...")


    try:
        import pip
        pip.main(["install", "--upgrade", "matrix-synapse"])
    except ImportError:
        print("pip not found. Please install pip and try again.")
        return

    print("Successfully upgraded matrix-synapse.")

    import subprocess

    try:
        subprocess.run(["systemctl", "restart", "matrix-synapse"], check=True)
        print("Successfully restarted Synapse using systemctl.")

    except FileNotFoundError:
      print("systemctl not found, can't attempt to restart with systemctl, using subprocess instead.")
      try:
        subprocess.run(["./synctl", "restart"], check=True)
        print("Successfully restarted Synapse using synctl.")

      except FileNotFoundError:
        print("synctl not found. Please ensure synctl is available and try again. Unable to restart server.")
        return
    except subprocess.CalledProcessError as e:
       print("Error restarting Synapse with systemctl: {e}")
       print("Please check the logs for details and try manually if needed")
       return


    import requests

    try:
        response = requests.get("http://localhost:8008/_synapse/admin/v1/server_version")
        response.raise_for_status()
        print("Server Version:", response.json())
        print("Upgrade check successful.")
    except requests.exceptions.RequestException as e:
      print(f"Error checking Synapse version: {e}")
      print("Please check that synapse is running and listening on port 8008")
      print("Verify your config and try again.")
      return
    except Exception as e:
      print(f"Unexpected Error: {e}")
      return

    print("Synapse upgrade completed.")
    return

if __name__ == "__main__":
    upgrade_synapse()
