import paramiko
import time

def check_ssh_authentication_type(host, username, password):
    try:
        # Establish an SSH connection using Paramiko
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, username=username, password=password)

        # Start an interactive shell session
        shell = ssh_client.invoke_shell()
        time.sleep(1)  # Wait for the shell to be ready

        # Enter system-view mode
        shell.send('system-view\n')
        time.sleep(1)  # Wait for command to execute

        # Run the command to display SSH user configurations
        shell.send('display current-configuration | include ssh user\n')
        time.sleep(1)  # Wait for command to execute

        # Read output from the shell
        output = ""
        while not shell.recv_ready():
            time.sleep(1)
        output = shell.recv(65536).decode()
        print(output)

        # Check for "authentication-type password" in the output
        if 'authentication-type password' in output:
            result = 'Compliant'
        else:
            result = 'Non-Compliant'

        # Close the SSH connection
        ssh_client.close()
        return [["SSH Authentication Type Check", result]]

    except Exception as e:
        return [["Error", str(e)]]

# Usage example
host = '192.168.1.250'
username = 'kshitij'
password = 'Password@1234'

result = check_ssh_authentication_type(host, username, password)
print(result)
