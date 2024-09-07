from netmiko import ConnectHandler

def check_ssh_authentication_type(host, username, password):
    # Define Huawei router connection details
    huawei_router = {
        'device_type': 'huawei',
        'host': host,
        'username': username,
        'password': password,
    }

    try:
        # Establish an SSH connection to the Huawei router
        connection = ConnectHandler(**huawei_router)
        
        # Enter system-view mode
        connection.send_command('system-view')
        
        # Run the command to display SSH user configurations
        command = 'display current-configuration | include ssh user'
        output = connection.send_command(command)

        # Check if the output contains 'authentication-type password'
        if 'authentication-type password' in output:
            return 'Compliant'
        return 'Non-Compliant'

    except Exception as e:
        return f"Error: {str(e)}"

# Usage example
host = '192.168.1.250'   # Replace with your router's IP
username = 'kshitij'       # Replace with your username
password = 'Password@1234'    # Replace with your password

result = check_ssh_authentication_type(host, username, password)
print(result)
