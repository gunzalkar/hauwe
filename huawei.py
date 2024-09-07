import paramiko # type: ignore
import time
import csv

host = '192.168.1.250'
username = 'kshitij'
password = 'Password@1234'

def connect_to_router(host, username, password):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(host, username=username, password=password)
    return ssh_client, ssh_client.invoke_shell()

# MBSS 2.1
def check_ssh_authentication_type(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include ssh user\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'authentication-type password' in output

# MBSS 2.2
def check_password_irreversible_cipher(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include user\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'password irreversible-cipher' in output

# MBSS 2.3
def multi_factor_authentiction(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include radius-server\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'password radius-server' in output













results = []

# MBSS 2.1
auth_result = check_ssh_authentication_type(host, username, password)
results.append({
    'Serial Number': 4,
    'Category' : 'Management Pane: Device Login Security',
    'Objective': 'Check if SSH authentication type is password.',
    'Comments': 'Login via password' if auth_result else 'Login not set',
    'Compliance': 'Compliant' if auth_result else 'Non-Compliant'
})
print(f"Check Passed: SSH authentication type is correctly set." if auth_result else "Check Failed: SSH authentication type is not correctly set.")

# MBSS 2.2
cipher_result = check_password_irreversible_cipher(host, username, password)
results.append({
    'Serial Number': 5,
    'Category' : 'Management Pane: Device Login Security',
    'Objective': 'Check if password is set with irreversible cipher.',
    'Comments': 'Password set via irreversible cipher' if cipher_result else 'Password not set via irreversible cipher',
    'Compliance': 'Compliant' if cipher_result else 'Non-Compliant'
})
print(f"Check Passed: Password is set with irreversible cipher." if cipher_result else "Check Failed: Password is not set with irreversible cipher.")

# MBSS 2.3
mfa_result = multi_factor_authentiction(host, username, password)
results.append({
    'Serial Number': 6,
    'Category' : 'Management Pane: Device Login Security',
    'Objective': 'Check if Multi Factor Authentication is set.',
    'Comments': 'MFA is set on Server' if mfa_result else 'MFA is not set on the Radius Server (NEEDS PHYSICAL SERVER AND MANUAL INTERVENTION)',
    'Compliance': 'Compliant' if mfa_result else 'Non-Compliant'
})
print(f"Check Passed: MFA is set on the Radius Server." if mfa_result else "Check Failed: MFA is not set on the Radius Server (NEEDS PHYSICAL SERVER AND MANUAL INTERVENTION).")



















# Write results to CSV
with open('compliance_report.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=['Serial Number','Category','Objective','Comments', 'Compliance'])
    writer.writeheader()
    writer.writerows(results)
