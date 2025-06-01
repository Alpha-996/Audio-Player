import subprocess
import os
import sys
import time

def run_command(command, input_text=None, check=True):
    """
    Executes a shell command with enhanced error handling and logging.
    """
    try:
        print(f"[*] Running command: {command}")
        result = subprocess.run(
            command,
            shell=True,
            text=True,
            input=input_text,
            capture_output=True,
            check=check
        )
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running command: {command}\n{e.stderr}")
        sys.exit(1)

def main():
    """
    Main function to orchestrate the OpenVPN Access Server setup.
    """
    # Ensure the script is executed with root privileges
    if os.geteuid() != 0:
        print("[-] This script must be run as root. Please use 'sudo'.")
        sys.exit(1)

    print("[+] Starting OpenVPN Access Server setup...")
    
    # --- System Preparation ---
    print("\n[+] Updating system packages and installing prerequisites...")
    run_command("apt-get update")
    run_command("apt-get upgrade -y")
    run_command("apt-get install -y curl net-tools ufw")

    # --- Download and Install OpenVPN Access Server ---
    print("\n[+] Downloading and installing OpenVPN Access Server...")
    # Fetches the latest version for Ubuntu 22
    run_command("curl -O https://swupdate.openvpn.net/as/openvpn-as-latest-ubuntu22.amd64.deb")
    run_command("dpkg -i openvpn-as-latest-ubuntu22.amd64.deb")
    
    # Clean up the downloaded installer
    print("\n[+] Cleaning up installation files...")
    run_command("rm openvpn-as-latest-ubuntu22.amd64.deb")

    # --- Configure OpenVPN Access Server ---
    print("\n[+] Applying specified configurations...")
    # A dictionary of configuration keys and their values for clarity
    configs = {
        'vpn.server.daemon.setup': 'true', # Marks the initial setup as complete
        'cs.ca_key_type': 'rsa',
        'cs.ca_key_bits': '2048',
        'cs.web_key_type': 'RSA',
        'cs.web_key_bits': '2048',
        'cs.bind_host': '0.0.0.0',
        'cs.web_port': '943',
        'vpn.daemon.0.listen.tcp_port': '443',
        'vpn.server.routing.gateway_access': 'true',
        'vpn.server.dns.forwarding': 'true',
        'vpn.server.routing.private_access': 'true'
    }

    # Base command for configuration changes
    confdba_base = "/usr/local/openvpn_as/scripts/confdba"

    for key, value in configs.items():
        run_command(f"{confdba_base} -mk {key} -v {value}")
        time.sleep(1) # Adding a small delay to ensure each config is written

    # --- Set Administrator Password ---
    print("\n[+] Setting password for the 'openvpn' user...")
    password = "ShaswatA@123A"
    # Use sacli to set the password for the 'openvpn' user
    run_command(f'/usr/local/openvpn_as/scripts/sacli --user "openvpn" --new_pass "{password}" UserPropPut')

    # --- Restart and Enable Services ---
    print("\n[+] Restarting and enabling OpenVPN Access Server...")
    run_command("systemctl restart openvpnas")
    run_command("systemctl enable openvpnas")

    # --- Firewall and Network Configuration ---
    print("\n[+] Configuring firewall and enabling IP forwarding...")
    run_command("ufw allow 943/tcp")  # Admin Web UI
    run_command("ufw allow 443/tcp")  # OpenVPN Daemon
    run_command("ufw allow OpenSSH")
    run_command("ufw --force enable")

    # Enable IP forwarding to allow VPN clients to access the internet
    sysctl_conf = "/etc/sysctl.conf"
    if "net.ipv4.ip_forward=1" not in open(sysctl_conf).read():
        run_command(f"echo 'net.ipv4.ip_forward=1' >> {sysctl_conf}")
        run_command("sysctl -p")

    # --- Final Output ---
    try:
        public_ip = run_command("curl -s https://api.ipify.org").strip()
    except:
        public_ip = run_command("hostname -I | awk '{print $1}'").strip()

    print("\n" + "="*50)
    print("✅ OpenVPN Access Server setup is complete!")
    print("="*50 + "\n")
    print(f"🔗 Admin Web UI: https://{public_ip}:943/admin")
    print(f"👤 Username: openvpn")
    print(f"🔑 Password: {password}")
    print("\n" + "="*50)
    print("Please log in to the Admin Web UI to download client profiles and manage your VPN.")
    print("="*50)


if __name__ == "__main__":
    main()
