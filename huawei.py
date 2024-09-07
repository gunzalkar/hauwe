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

# MBSS 3.1
def check_encryption_setting(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include encryption\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'aes 256' in output

# MBSS 3.2
def block_fail_interval_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include fail\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'state block fail-times 3 interval 5' in output

# MBSS 3.3
def user_privilege_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include level\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'user privilege level 3' in output

#MBSS 4.1
def snmp_password_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include ssh user\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'authentication-type password' in output

# MBSS 4.2
def complexity_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include complexity\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'complexity-check' in output

#MBSS 4.3
def multi_factor_authentiction_SNMP(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include radius-server\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'password radius-server' in output

#MBSS 5.1
def correct_SNMP_auth_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include snmp-agent\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'authentication-mode sha cipher' in output


#MBSS 5.2
def SNMP_ASL_CHECK(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display snmp-agent group\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'Acl: 2001' in output


#MBSS 5.3
def correct_SNMP_version_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display snmp-agent sys-info\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'SNMPv3' in output

results = []


# MBSS 2.1
auth_result = check_ssh_authentication_type(host, username, password)
results.append({
    'Serial Number': 4,
    'Category' : 'Management Pane : Device Login Security',
    'Objective': 'Check if SSH authentication type is password.',
    'Comments': 'Login via password' if auth_result else 'Login not set',
    'Compliance': 'Compliant' if auth_result else 'Non-Compliant'
})
print(f"Check Passed: SSH authentication type is correctly set." if auth_result else "Check Failed: SSH authentication type is not correctly set.")

# MBSS 2.2
cipher_result = check_password_irreversible_cipher(host, username, password)
results.append({
    'Serial Number': 5,
    'Category' : 'Management Pane : Device Login Security',
    'Objective': 'Check if password is set with irreversible cipher.',
    'Comments': 'Password set via irreversible cipher' if cipher_result else 'Password not set via irreversible cipher',
    'Compliance': 'Compliant' if cipher_result else 'Non-Compliant'
})
print(f"Check Passed: Password is set with irreversible cipher." if cipher_result else "Check Failed: Password is not set with irreversible cipher.")

# MBSS 2.3
mfa_result = multi_factor_authentiction(host, username, password)
results.append({
    'Serial Number': 6,
    'Category' : 'Management Pane : Device Login Security',
    'Objective': 'Check if Multi Factor Authentication is set.',
    'Comments': 'MFA is set on Server' if mfa_result else 'MFA is not set on the Radius Server (NEEDS PHYSICAL SERVER AND MANUAL INTERVENTION)',
    'Compliance': 'Compliant' if mfa_result else 'Non-Compliant'
})
print(f"Check Passed: MFA is set on the Radius Server." if mfa_result else "Check Failed: MFA is not set on the Radius Server (NEEDS PHYSICAL SERVER AND MANUAL INTERVENTION).")

#MBSS 3.1
encryption_result = check_encryption_setting(host, username, password)
results.append({
    'Serial Number': 7,
    'Category': 'Management Pane : AAA User Management Security',
    'Objective': 'Check if encryption setting includes AES 256.',
    'Comments': 'Encryption setting includes AES 256' if encryption_result else 'Encryption setting does not include AES 256',
    'Compliance': 'Compliant' if encryption_result else 'Non-Compliant'
})
print(f"Check Passed: Encryption setting includes AES 256." if encryption_result else "Check Failed: Encryption setting does not include AES 256.")

#MBSS 3.2
retry_result = block_fail_interval_check(host, username, password)
results.append({
    'Serial Number': 8,
    'Category': 'Management Pane : AAA User Management Security',
    'Objective': 'Check if password has Fail and Retry interval set check enable.',
    'Comments': 'maximum number of consecutive authentication failures is 3, and the account locking period is 5 minutes. ' if retry_result else 'Retry and Lockin interval not set according to compilance',
    'Compliance': 'Compliant' if retry_result else 'Non-Compliant'
})
print(f"Check Passed: Retry interval Set." if retry_result else "Check Failed: Retry interval not Set.")

#MBSS 3.3
priv_result = user_privilege_check(host, username, password)
results.append({
    'Serial Number': 9,
    'Category': 'Management Pane : AAA User Management Security',
    'Objective': 'Check user privilege level.',
    'Comments': 'User has appropriate privilege level.' if priv_result else 'User does not has appropriate privilege level.',
    'Compliance': 'Compliant' if priv_result else 'Non-Compliant'
})
print(f"Check Passed: User has appropriate privilege level." if priv_result else "Check Failed: User does not has appropriate privilege level.")

#MBSS 4.1
snmp_password_result = snmp_password_check(host, username, password)
results.append({
    'Serial Number': 10,
    'Category' : 'Management Pane : SNMP Device Management Security',
    'Objective': 'Check if SSH authentication type is password for SNMP.',
    'Comments': 'Login via password for SNMP' if snmp_password_result else 'Login not set for SNMP',
    'Compliance': 'Compliant' if snmp_password_result else 'Non-Compliant'
})
print(f"Check Passed: Password authentication type is correctly set for SNMP." if snmp_password_result else "Check Failed: Password authentication type is not correctly set for SNMP.")

#MBSS 4.2
complexity_result = check_encryption_setting(host, username, password)
results.append({
    'Serial Number': 11,
    'Category': 'Management Pane : SNMP Device Management Security',
    'Objective': 'Check if password has complexity check enable.',
    'Comments': 'Encryption setting includes Complexity' if complexity_result else 'Encryption setting does not includes Complexity',
    'Compliance': 'Compliant' if complexity_result else 'Non-Compliant'
})
print(f"Check Passed: Encryption setting includes Complexity Check." if complexity_result else "Check Failed: Encryption setting does not include Complexity Check.")

#MBSS 4.3
mfa_result_snmp = multi_factor_authentiction_SNMP(host, username, password)
results.append({
    'Serial Number': 12,
    'Category' : 'Management Pane : SNMP Device Management Security',
    'Objective': 'Check if Multi Factor Authentication is set.',
    'Comments': 'MFA is set on SNMP Server' if mfa_result_snmp else 'MFA is not set on the Radius Server (NEEDS PHYSICAL SERVER AND MANUAL INTERVENTION)',
    'Compliance': 'Compliant' if mfa_result_snmp else 'Non-Compliant'
})
print(f"Check Passed: MFA is set on the SNMP Radius Server." if mfa_result_snmp else "Check Failed: MFA is not set on the SNMP Radius Server (NEEDS PHYSICAL SERVER AND MANUAL INTERVENTION).")


#MBSS 5.1
snmp_sha_check = correct_SNMP_auth_check(host, username, password)
results.append({
    'Serial Number': 13,
    'Category' : 'Management Pane : Service Plane Access Prohibition of Insecure Management Protocols',
    'Objective': 'Check if SNMP authentication-mode sha cipher is set.',
    'Comments': 'SNMP authentication-mode  set to sha cipher' if snmp_sha_check else 'SNMP authentication-mode is not set to sha cipher',
    'Compliance': 'Compliant' if snmp_sha_check else 'Non-Compliant'
})
print(f"Check Passed: SNMP authentication-mode  set to sha cipher." if snmp_sha_check else "Check Failed: SNMP authentication-mode is not set to sha cipher.")

#MBSS 5.2
snmp_acl_check = SNMP_ASL_CHECK(host, username, password)
results.append({
    'Serial Number': 14,
    'Category' : 'Management Pane : Service Plane Access Prohibition of Insecure Management Protocols',
    'Objective': 'Check if SNMP ACL is 2001 is set.',
    'Comments': 'SNMP ACL is set to 2001 firewall' if snmp_acl_check else 'SNMP ACL is not set to 2001 firewall',
    'Compliance': 'Compliant' if snmp_acl_check else 'Non-Compliant'
})
print(f"Check Passed: SNMP ACL IS 2001." if snmp_acl_check else "Check Failed: SNMP ACL is not 2001.")

#MBSS 5.3
snmp_version = correct_SNMP_version_check(host, username, password)
results.append({
    'Serial Number': 15,
    'Category' : 'Management Pane : Service Plane Access Prohibition of Insecure Management Protocols',
    'Objective': 'Check if SNMP Version is V3 is set.',
    'Comments': 'SNMP Server is V3' if snmp_version else 'SNMP Server is not V3',
    'Compliance': 'Compliant' if snmp_version else 'Non-Compliant'
})
print(f"Check Passed: SNMP Server is V3." if snmp_version else "Check Failed: SNMP Server is not V3.")


# Write results to CSV
with open('compliance_report.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=['Serial Number','Category','Objective','Comments', 'Compliance'])
    writer.writeheader()
    writer.writerows(results)
