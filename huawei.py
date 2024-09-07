from netmiko import ConnectHandler

def check_ssh_authentication_type(host, username, password):
    # Define Huawei router connection details
    huawei_router = {
        'device_type': 'huawei',
        'host': host,
        'username': username,
        'password': password,
        'global_delay_factor': 2,  # Adjust if there's a delay issue
    }

    connection = None
    try:
        # Establish an SSH connection to the Huawei router
        connection = ConnectHandler(**huawei_router)

        # Explicitly set the expected prompt as <Huawei>
        connection.send_command('system-view', expect_string=r'<Huawei>')
        
        # Run the command to display SSH user configurations
        command = 'display current-configuration | include ssh user'
        output = connection.send_command(command, expect_string=r'<Huawei>')

        # Check for "authentication-type password" in the output
        if 'authentication-type password' in output:
            return 'Compliant'
        return 'Non-Compliant'

    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        # Disconnect if the connection was successfully established
        if connection:
            connection.disconnect()

# Usage example
host = '192.168.1.250'   
username = 'kshitij'      
password = 'Password@1234'  

result = check_ssh_authentication_type(host, username, password)
print(result)
