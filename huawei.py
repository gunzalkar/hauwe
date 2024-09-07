import paramiko

def check_ssh_authentication_type(host, username, password):
    try:
        # Establish an SSH connection using Paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)

        # Start an interactive shell session
        shell = ssh.invoke_shell()

        # Enter system-view mode
        shell.send('system-view\n')
        shell.recv(1000)  # Receive any initial output

        # Run the command to display SSH user configurations
        shell.send('display current-configuration | include ssh user\n')
        output = ""
        while not output.endswith('<Huawei>'):
            output += shell.recv(1000).decode('utf-8')
            print(output)

        # Check for "authentication-type password" in the output
        if 'authentication-type password' in output:
            result = 'Compliant'
        else:
            result = 'Non-Compliant'

        # Close the SSH connection
        ssh.close()
        return result

    except Exception as e:
        return f"Error: {str(e)}"

# Usage example
host = '192.168.1.250'
username = 'kshitij'
password = 'Password@1234'

result = check_ssh_authentication_type(host, username, password)
print(result)
