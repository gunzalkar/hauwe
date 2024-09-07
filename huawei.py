import paramiko # type: ignore
import time
import csv

def connect_to_router(host, username, password):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(host, username=username, password=password)
    return ssh_client, ssh_client.invoke_shell()

def check_ssh_authentication_type(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include ssh user\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'authentication-type password' in output

def check_password_irreversible_cipher(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include user\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'password irreversible-cipher' in output

# Usage example
host = '192.168.1.250'
username = 'kshitij'
password = 'Password@1234'

result = []

result = check_ssh_authentication_type(host, username, password)
print(f"Check Passed: SSH authentication type is correctly set." if result else "Check Failed: SSH authentication type is not correctly set.")
results = [{
    'Serial Number': 1,
    'Objective': 'Check if SSH authentication type is password.',
    'Result': 'Pass' if result else 'Fail',
    'Compliance': 'Compliant' if result else 'Non-Compliant'
}]
print(results)

result = check_password_irreversible_cipher(host, username, password)
print(f"Check Passed: Password is set with irreversible cipher." if result else "Check Failed: Password is not set with irreversible cipher.")
results.append({
    'Serial Number': 2,
    'Objective': 'Check if password is set with irreversible cipher.',
    'Result': 'Pass' if result else 'Fail',
    'Compliance': 'Compliant' if result else 'Non-Compliant'
})
print(results)

with open('compliance_report.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=['Serial Number', 'Objective', 'Result', 'Compliance'])
    writer.writeheader()
    writer.writerows(results)
