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

#MBSS 6.1
def telnet_disable_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include telnet\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'undo telnet server enable' in output

#MBSS 6.2
def snmp_v3_on(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include snmp-agent sys-info version\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'snmp-agent sys-info version v3' in output

#MBSS 6.3
def snmp_ssh_on(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display ssh server status | include SSH server keepalive\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'Enable' in output

#MBSS 7.1
def ip_routing(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display ip routing-table\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return '192.168.1.0/24' in output


#MBSS 7.2
def acl_rules(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display acl 2001\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'Basic ACL 2001, 3 rules' in output

#MBSS 8.1
def vlan_setup(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display vlan\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'The total number of vlans is' in output

#MBSS 9.1
def igmp_setup(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include igmp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'igmp-snooping enable' in output

#MBSS 10.1
def wlan_psk_security(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display wlan\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'WLAN' in output

#MBSS 11.1
def acl_rule_permit(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display acl 2001\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'permit source 192.168.32.1 0' in output


#MBSS 12.1
def supression_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display interface Ethernet1/0/0 | include Unicast\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'Unicast' in output


#MBSS 13.1
def sha256_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display this\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'authentication-mode hmac-sha256' in output

#MBSS 13.2
def acl_rules_all_3(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display acl all\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'Basic ACL 2001, 3 rules' in output

#MBSS 14.1
def log_host_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display info-center\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'channel name loghost' in output

#MBSS 14.2
def transport_ssl_policy(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display info-center\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'transport tcp ssl-policy' in output

#MBSS 14.3
def acl_rules_all_2001(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display acl allr\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'Basic ACL 2001, 3 rules' in output

#MBSS 15.1
def hwtacacs_cipher_setup(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration configuration | include hwtacacs\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'hwtacacs server shared-key cipher' in output

#MBSS 16.1
def arp_mac_validate(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include arp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'arp validate source-mac' in output

#MBSS 16.2
def arp_static_validate(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include arp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'arp static' in output

#MBSS 16.3
def arp_expiry_validate(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include arp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'arp expire-time' in output

#MBSS 17.1
def dhcp_server(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include dhcp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'dhcp server database enable' in output

#MBSS 18.1
def bgp_configuration(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration configuration bgp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'bgp 100' in output

#MBSS 18.2
def bgp_router_policy_check(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display bgp peer verbose | include Export\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'Export route policy is:' in output

 
#MBSS 18.3
def bgp_keep_alive(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display bgp peer verbose | include 30\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return '30 seconds' in output

#MBSS 19.1
def keychain(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include key-cha\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'authentication key-chain all name kc1' in output

#MBSS 19.2
def mpls_ldp(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include mpls\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'mpls ldp' in output

# MBSS 19.3
def mpls_vpn_instance(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display ip vpn-instance\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()

    # Extract the number of configured VPN instances
    for line in output.splitlines():
        if 'Total VPN-Instances configured' in line:
            vpn_count = int(line.split(':')[-1].strip())
            return vpn_count >= 1
    return False

#MBSS 20.1
def igmp_snooping(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include igmp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'igmp-snooping enable' in output

#MBSS 20.2
def igmp_group_policy(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include igmp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'igmp-snooping group-policy 2000' in output

#MBSS 20.3
def acl_rule_2000_verification(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display acl 2000\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'rule 5 permit source 225.0.0.0 0.0.0.255' in output

#MBSS 21.1
def dhcp_snooping_enable(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include dhcp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'dhcp snooping enable' in output

#MBSS 21.2
def dhcp_snooping_trusted(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include dhcp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'dhcp snooping trusted' in output

#MBSS 21.3
def ntp_authentication_enable(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration | include ntp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'ntp-service authentication enable' in output

#MBSS 22.1
def ntp_key_id(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration  | include ntp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'authentication-keyid 10' in output

#MBSS 23.1
def stp_bpdu_root(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration  | include stp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'stp root-protection' in output

#MBSS 23.2
def stp_bpdu(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration  | include stp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'stp bpdu-filter enable' in output

#MBSS 23.3
def stp_bpdu_transmit_limit(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display stp global\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()


    # Extract the number of configured VPN instances
    for line in output.splitlines():
        if 'Transmit-limit' in line:
            vpn_count = int(line.split(':')[-1].strip())
            return vpn_count <= 30
    return False


#MBSS 24.1
def vrrp_authentication(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration  | include vrrp\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'authentication-mode md5' in output

#MBSS 25.1
def easy_deploy(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration  | include easydeploy\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'cipher' in output

#MBSS 26.1
def easy_deploy_security(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration  | include easydeploy\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'shared-key cipher' in output

#MBSS 27.1
def Defense_Against_ICMPv6_Attacks(host, username, password):
    ssh_client, shell = connect_to_router(host, username, password)
    shell.send('system-view\n')
    time.sleep(1)
    shell.send('display current-configuration  | include ipv6\n')
    time.sleep(1)
    output = shell.recv(65536).decode()
    ssh_client.close()
    return 'undo ipv6 icmp echo-reply receive' and 'undo ipv6 icmp port-unreachable receive' and 'undo ipv6 icmp host-unreachable receive' in output

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

#MBSS 6.1
telnet_check = telnet_disable_check(host, username, password)
results.append({
    'Serial Number': 16,
    'Category' : 'Management Pane : MPAC',
    'Objective': 'Check Telnet is disable.',
    'Comments': 'TELNET is disable' if telnet_check else 'TELNET is not diable',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: TELNET is disable." if telnet_check else "Check Failed: TELNET is enabled.")

#MBSS 6.2
telnet_check = snmp_v3_on(host, username, password)
results.append({
    'Serial Number': 17,
    'Category' : 'Management Pane : MPAC',
    'Objective': 'Check SNMP V3 is enable.',
    'Comments': 'SNMP V3 is enable' if telnet_check else 'SNMP V3 is not enable',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: SNMP V3 is enable." if telnet_check else "Check Failed: SNMP V3 is not enable.")

#MBSS 6.3
telnet_check = snmp_ssh_on(host, username, password)
results.append({
    'Serial Number': 18,
    'Category' : 'Management Pane : MPAC',
    'Objective': 'Check SSH is enable.',
    'Comments': 'SSH is Enable' if telnet_check else 'SSH is diable',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: SSH is Enable." if telnet_check else "Check Failed: SSH is diable.")

#MBSS 7.1
telnet_check = ip_routing(host, username, password)
results.append({
    'Serial Number': 19,
    'Category' : 'Control Plane : Local Attack Defense',
    'Objective': 'Check IP Router Table.',
    'Comments': 'IP Router is enable' if telnet_check else 'No IP router not enable',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: IP Router is enable." if telnet_check else "Check Failed: IP Router is not enable.")

#MBSS 7.2
telnet_check = acl_rules(host, username, password)
results.append({
    'Serial Number': 20,
    'Category' : 'Control Plane : Local Attack Defense',
    'Objective': 'ACL Rules.',
    'Comments': 'ACL Rules is set' if telnet_check else 'No ACL Rules is set',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: ACL Rules is set." if telnet_check else "Check Failed: No ACL Rules is set.")

#MBSS 8.1
telnet_check = vlan_setup(host, username, password)
results.append({
    'Serial Number': 21,
    'Category' : 'Control Plane : Attack Defense Through Service and Management Isolation',
    'Objective': 'VLAN Setup.',
    'Comments': 'VLAN is set up' if telnet_check else 'No VLAN is set up',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: VLAN is setup." if telnet_check else "Check Failed: VLAN is not setup.")

#MBSS 9.1
telnet_check = igmp_setup(host, username, password)
results.append({
    'Serial Number': 22,
    'Category' : 'Control Plane : Attack Defense Through Service and Management Isolation',
    'Objective': 'IGMP is Setup.',
    'Comments': 'IGMP is set up' if telnet_check else 'IGMP is not set up',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: IGMP is set up." if telnet_check else "Check Failed: IGMP is not set up.")

#MBSS 10.1
telnet_check = wlan_psk_security(host, username, password)
results.append({
    'Serial Number': 23,
    'Category' : 'Control Plane : Wireless User Access Security',
    'Objective': 'WLAN Setup.',
    'Comments': 'WLAN is set up Still need manual intervention' if telnet_check else 'WLAN Security is not setup Need physical hardware and Manual Checkup',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: WLAN is setup." if telnet_check else "Check Failed: WLAN is not setup Need physical hardware and Manual Checkup.")

#MBSS 11.1
telnet_check = acl_rule_permit(host, username, password)
results.append({
    'Serial Number': 24,
    'Category' : 'Forwarding Plane : ACL',
    'Objective': 'ACL 2001 Permit.',
    'Comments': 'ACL 2001 Permit it set.' if telnet_check else 'ACL 2001 Permit is not set.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: ACL 2001 Permit." if telnet_check else "Check Failed: ACL 2001 Permit not set.")

#MBSS 12.1
telnet_check = supression_check(host, username, password)
results.append({
    'Serial Number': 25,
    'Category' : 'Forwarding Plane : Traffic Suppression and Storm Control',
    'Objective': 'Check UNICAST in Ethernet.',
    'Comments': 'UNICAST is setpup.' if telnet_check else 'UNICAST is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: UNICAST Permit is set." if telnet_check else "Check Failed: UNICAST permit it not set.")

#MBSS 13.1
telnet_check = supression_check(host, username, password)
results.append({
    'Serial Number': 26,
    'Category' : 'Forwarding Plane : Trusted Path-based Forwarding',
    'Objective': 'Check if SHA256.',
    'Comments': 'SHA256 is setup.' if telnet_check else 'SHA256 is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: SHA256 is setup." if telnet_check else "Check Failed: SHA256 is not setup.")

#MBSS 13.2
telnet_check = supression_check(host, username, password)
results.append({
    'Serial Number': 27,
    'Category' : 'Forwarding Plane : Trusted Path-based Forwarding',
    'Objective': 'Check if All ACL rules as set.',
    'Comments': 'ACL Rules is setup.' if telnet_check else 'ACL Rules is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: ACL Rule is setup." if telnet_check else "Check Failed: ACL Rule is not setup.")

#MBSS 14.1
telnet_check = log_host_check(host, username, password)
results.append({
    'Serial Number': 28,
    'Category' : 'Management Pane : Information Center Security',
    'Objective': 'Check if loghost is set.',
    'Comments': 'Loghost is setup.' if telnet_check else 'Loghost is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: Loghost is setup." if telnet_check else "Check Failed: Loghost is not setup.")

#MBSS 14.2
telnet_check = transport_ssl_policy(host, username, password)
results.append({
    'Serial Number': 29,
    'Category' : 'Management Pane : Information Center Security',
    'Objective': 'Check if SSL Policy is set.',
    'Comments': 'SSL Policy is setup.' if telnet_check else 'SSL Policy is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: SSL Policy is setup." if telnet_check else "Check Failed: SSL Policy not setup.")

#MBSS 14.3
telnet_check = transport_ssl_policy(host, username, password)
results.append({
    'Serial Number': 30,
    'Category' : 'Management Pane : Information Center Security',
    'Objective': 'Check if ACL Rules is set.',
    'Comments': 'ACL Rules is setup.' if telnet_check else 'ACL Rules is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: ACL Rules is setup." if telnet_check else "Check Failed: ACL Rules not setup.")

#MBSS 15.1/.2/.3
telnet_check = transport_ssl_policy(host, username, password)
results.append({
    'Serial Number': 31,
    'Category' : 'Management Pane : HWTACACS User Management Security',
    'Objective': 'Check if HWTACACS User Management Security is set.',
    'Comments': 'HWTACACS User Management Security is setup.' if telnet_check else 'HWTACACS User Management Security is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: HWTACACS User Management Security is setup." if telnet_check else "Check Failed: HWTACACS User Management Security not setup.")

#MBSS 16.1
telnet_check = arp_mac_validate(host, username, password)
results.append({
    'Serial Number': 32,
    'Category' : 'Control Plane : ARP Security',
    'Objective': 'Check if ARP MAC Validation is set.',
    'Comments': 'ARP MAC Validation is setup.' if telnet_check else 'ARP MAC Validation is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: ARP MAC Validation is setup." if telnet_check else "Check Failed: ARP MAC Validation is not setup.")

#MBSS 16.2
telnet_check = arp_static_validate(host, username, password)
results.append({
    'Serial Number': 33,
    'Category' : 'Control Plane : ARP Security',
    'Objective': 'Check if ARP Static IP is set.',
    'Comments': 'ARP Static IP is setup.' if telnet_check else 'ARP Static IP is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: ARP Static IP is setup." if telnet_check else "Check Failed: ARP Static IP is not setup.")

#MBSS 16.3
telnet_check = arp_expiry_validate(host, username, password)
results.append({
    'Serial Number': 34,
    'Category' : 'Control Plane : ARP Security',
    'Objective': 'Check if ARP Expiry is set.',
    'Comments': 'ARP Expiry is setup.' if telnet_check else 'ARP Expiry is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: ARP Expiry is setup." if telnet_check else "Check Failed: ARP Expiry is not setup.")

#MBSS 17.1
telnet_check = dhcp_server(host, username, password)
results.append({
    'Serial Number': 35,
    'Category' : 'Control Plane : DHCP Security',
    'Objective': 'Check if DHCP Server is set.',
    'Comments': 'DHCP Server is setup.' if telnet_check else 'DHCP Server is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: DHCP Server is setup." if telnet_check else "Check Failed: DHCP is not setup.")

#MBSS 18.1
telnet_check = bgp_configuration(host, username, password)
results.append({
    'Serial Number': 36,
    'Category' : 'Control Plane : Routing Protocol Security',
    'Objective': 'Check if BGP is set.',
    'Comments': 'BGP is setup.' if telnet_check else 'BGP is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: BGP is setup." if telnet_check else "Check Failed: BGP not setup.")

#MBSS 18.2
telnet_check = bgp_router_policy_check(host, username, password)
results.append({
    'Serial Number': 37,
    'Category' : 'Control Plane : Routing Protocol Security',
    'Objective': 'Check if BGP Route Policy is set.',
    'Comments': 'BGP Route Policy is setup.' if telnet_check else 'BGP Route Policy is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: BGP Route Policy is setup." if telnet_check else "Check Failed: BGP Route Policy not setup.")

#MBSS 18.3
telnet_check = bgp_keep_alive(host, username, password)
results.append({
    'Serial Number': 38,
    'Category' : 'Control Plane : Routing Protocol Security',
    'Objective': 'Check if BGP timer is set.',
    'Comments': 'BGP timer is setup.' if telnet_check else 'BGP timer is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: BGP timer is setup." if telnet_check else "Check Failed: BGP timer not setup.")

#MBSS 19.1
telnet_check = keychain(host, username, password)
results.append({
    'Serial Number': 39,
    'Category' : 'Control Plane : MPLS Security',
    'Objective': 'Check if Key Chain is set.',
    'Comments': 'Key Chain is setup.' if telnet_check else 'Key Chain is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: Key Chain is setup." if telnet_check else "Check Failed: Key Chain not setup.")

#MBSS 19.2
telnet_check = mpls_ldp(host, username, password)
results.append({
    'Serial Number': 40,
    'Category' : 'Control Plane : MPLS Security',
    'Objective': 'Check if MPLS LDP is set.',
    'Comments': 'MPLS LDP is setup.' if telnet_check else 'MPLS LDP is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: MPLS LDP is setup." if telnet_check else "Check Failed: MPLS LDP is not set up.")

#MBSS 19.3
telnet_check = mpls_vpn_instance(host, username, password)
results.append({
    'Serial Number': 41,
    'Category' : 'Control Plane : MPLS Security',
    'Objective': 'Check if MPLS VPN Instance is set.',
    'Comments': 'MPLS VPN Instance is setup.' if telnet_check else 'MPLS VPN Instance is not set up.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: VPN Instance is setup." if telnet_check else "Check Failed: VPN Instance not setup.")

#MBSS 20.1
telnet_check = igmp_snooping(host, username, password)
results.append({
    'Serial Number': 42,
    'Category' : 'Control Plane : Multicast Security',
    'Objective': 'IGMP Snooping is Setup.',
    'Comments': 'IGMP Snooping is set up' if telnet_check else 'IGMP Snooping is not set up',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: IGMP Snooping is set up." if telnet_check else "Check Failed: IGMP Snooping is not set up.")

#MBSS 20.2
telnet_check = igmp_group_policy(host, username, password)
results.append({
    'Serial Number': 43,
    'Category' : 'Control Plane : Multicast Security',
    'Objective': 'IGMP Snooping Group Policy is Setup.',
    'Comments': 'IGMP Snooping Group Policy is set up' if telnet_check else 'IGMP Snooping Group Policy is not set up',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: IGMP Snooping Group Policy is set up." if telnet_check else "Check Failed: IGMP Snooping Group Policy is not set up.")

#MBSS 20.3
telnet_check = acl_rule_2000_verification(host, username, password)
results.append({
    'Serial Number': 44,
    'Category' : 'Control Plane : Multicast Security',
    'Objective': 'ACL Rule 2000.',
    'Comments': 'ACL Rule 2000 is set up' if telnet_check else 'ACL Rule 2000 is not set up',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: ACL Rule 2000 is set up." if telnet_check else "Check Failed: ACL Rule 2000 is not set up.")

#MBSS 21.1
telnet_check = dhcp_snooping_enable(host, username, password)
results.append({
    'Serial Number': 45,
    'Category' : 'Control Plane : SVF System Security',
    'Objective': 'DHCP Snooping Enable.',
    'Comments': 'DHCP Snooping set up' if telnet_check else 'DHCP Snooping is not set up',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: DHCP Snooping is set up." if telnet_check else "Check Failed: DHCP Snooping is not set up.")

#MBSS 21.2
telnet_check = dhcp_snooping_trusted(host, username, password)
results.append({
    'Serial Number': 46,
    'Category' : 'Control Plane : SVF System Security',
    'Objective': 'DHCP Snooping Trusted to a network.',
    'Comments': 'DHCP Snooping Trusted to a network.' if telnet_check else 'DHCP Snooping is not Trusted to a network.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: DHCP Snooping Trusted to a network." if telnet_check else "Check Failed: DHCP Snooping is not Trusted to a network.")

#MBSS 21.3
telnet_check = ntp_authentication_enable(host, username, password)
results.append({
    'Serial Number': 47,
    'Category' : 'Control Plane : SVF System Security',
    'Objective': 'NTP Authentication is enable.',
    'Comments': 'NTP Authentication is enable.' if telnet_check else 'NTP Authentication is not enable.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: NTP Authentication is enable." if telnet_check else "Check Failed: NTP Authentication is not enable.")

#MBSS 22.1
telnet_check = ntp_key_id(host, username, password)
results.append({
    'Serial Number': 48,
    'Category' : 'Control Plane : NTP Security',
    'Objective': 'NTP Key ID.',
    'Comments': 'NTP Key ID is set.' if telnet_check else 'NTP Key ID is not set.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: NTP Key ID is set." if telnet_check else "Check Failed: NTP Key ID is not set.")


#MBSS 23.1
telnet_check = stp_bpdu_root(host, username, password)
results.append({
    'Serial Number': 49,
    'Category' : 'Control Plane : MSTP Security',
    'Objective': 'STP root protection in set up.',
    'Comments': 'STP root protection is set up.' if telnet_check else 'STP root protection not set.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: STP root protection  is set up." if telnet_check else "Check Failed: STP root protection is not set.")
# Write results to CSV

#MBSS 23.2
telnet_check = stp_bpdu(host, username, password)
results.append({
    'Serial Number': 50,
    'Category' : 'Control Plane : MSTP Security',
    'Objective': 'STP BPDU is set up.',
    'Comments': 'STP BPDU is set up.' if telnet_check else 'STP BPDU is not set.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: STP BPDU is set up." if telnet_check else "Check Failed: STP BPDU is not set.")

#MBSS 23.3
telnet_check = stp_bpdu(host, username, password)
results.append({
    'Serial Number': 51,
    'Category' : 'Control Plane : MSTP Security',
    'Objective': 'Transmit Limit for BPDU is properly set up.',
    'Comments': 'Transmit Limit for BPDU is properly set up.' if telnet_check else 'Transmit Limit for BPDU is properly not set.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: Transmit Limit for BPDU is properly set up." if telnet_check else "Check Failed: Transmit Limit for BPDU is properly not set.")

#MBSS 24.1
telnet_check = stp_bpdu(host, username, password)
results.append({
    'Serial Number': 52,
    'Category' : 'Control Plane : VRRP Security',
    'Objective': 'VRRP authention MD5.',
    'Comments': 'VRRP authention is set up to MD5.' if telnet_check else 'VRRP authention is not set up to MD5.',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: VRRP authention is set up to MD5." if telnet_check else "Check Failed: VRRP authention is not set up to MD5.")

#MBSS 25.1
telnet_check = easy_deploy(host, username, password)
results.append({
    'Serial Number': 53,
    'Category' : 'Control Plane : E-Trunk Security',
    'Objective': 'Easy Deploy Function.',
    'Comments': 'Easy Deploy has proper authentication set up.' if telnet_check else 'Easy Deploy has no proper authentication set up (THIS FUNCTION MAY BE NOT AVAILABLE IN ALL DEVICES).',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: Easy Deploy has proper authentication set up." if telnet_check else "Check Failed: Easy Deploy has no proper authentication set up (THIS FUNCTION MAY BE NOT AVAILABLE IN ALL DEVICES)")

#MBSS 26.1
telnet_check = easy_deploy_security(host, username, password)
results.append({
    'Serial Number': 54,
    'Category' : 'Control Plane : EasyDeploy System Security',
    'Objective': 'Easy Deploy Function security.',
    'Comments': 'Easy Deploy security is set up.' if telnet_check else 'Easy Deploy security is not set up (THIS FUNCTION MAY BE NOT AVAILABLE IN ALL DEVICES).',
    'Compliance': 'Compliant' if telnet_check else 'Non-Compliant'
})
print(f"Check Passed: Easy Deploy security is set up." if telnet_check else "Check Failed: Easy Deploy security is not set up (THIS FUNCTION MAY BE NOT AVAILABLE IN ALL DEVICES)")


# Write results to CSV


with open('compliance_report.csv', 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=['Serial Number','Category','Objective','Comments', 'Compliance'])
    writer.writeheader()
    writer.writerows(results)
