# Internal Network Protocol Enumeration

Protocol-specific testing procedures for internal network assessments. Referenced by `internal-network.md` Phase 5 when discovered services require protocol-level testing.

For each protocol below, apply the per-service test matrix and CVE evaluation procedure from `internal-network.md` Phase 3.

(See `../vulnerability/README.md` for protocol-specific tool selection.)

## SMB

Share enumeration and sensitive file searching:

```bash
smbmap -H <ip>                           # anonymous share listing
smbmap -H <ip> -r                        # recursive listing of all shares
enum4linux-ng -A -oA enum4linux <ip>     # comprehensive SMB/NetBIOS enum
nbtscan <CIDR>                           # NetBIOS names across subnet
nxc smb <ip>                             # check SMB signing (unsigned = relay target)
# Search for sensitive files in accessible shares
smbclient //<ip>/<share> -N -c 'recurse ON; prompt OFF; ls'
# Look for: *.kdbx, *.config, *.xml, passwords.*, *.vmdk, *.key, *.pem
```

## MSRPC

RPC endpoint enumeration (see `../exploitation/tools/impacket.md`):

```bash
impacket-rpcdump <ip> | grep -E 'Protocol|Provider'                     # enumerate RPC interfaces
impacket-rpcdump <ip> | grep -i 'MS-RPRN\|MS-EFSR\|MS-DFSNM\|MS-SCMR'   # check for coercion-capable interfaces
```

## SNMP

Community string testing and full walk (see `../vulnerability/tools/onesixtyone.md` and `../vulnerability/tools/snmpwalk.md`):

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <ip>
snmpwalk -v2c -c public <ip> 1.3.6.1.2.1.1   # system info
snmpwalk -v2c -c public <ip> 1.3.6.1.2.1.25   # host resources (processes, software)
snmpwalk -v2c -c public <ip> 1.3.6.1.4.1.77.1.2.25   # Windows user accounts
```

## Kerberos

Cross-reference `active-directory.md` for full AD testing:

```bash
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='<domain>' <dc-ip>
```

## LDAP

Anonymous bind and directory enumeration:

```bash
nmap -p 389,636 --script ldap-rootdse <ip>
ldapsearch -x -H ldap://<ip> -b '' -s base namingContexts   # anonymous bind test
ldapsearch -x -H ldap://<ip> -b 'dc=<domain>,dc=<tld>' '(objectClass=person)' cn mail 2>&1 | head -50
```

## RDP

NLA, encryption, and known vulnerabilities:

```bash
nxc rdp <CIDR>
nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info <ip>
```

## WinRM

Remote management access and authentication:

```bash
nxc winrm <ip>                                      # check WinRM availability and OS info
nxc winrm <ip> -u '' -p ''                          # test null authentication
evil-winrm -i <ip> -u <user> -p <password>          # connect with valid credentials
```

Use `evil-winrm` for interactive PowerShell access via WinRM after obtaining credentials (see `../exploitation/tools/evil-winrm.md`).

## SSH

Algorithms, authentication methods, and configuration:

```bash
nmap -p 22 --script ssh2-enum-algos,ssh-auth-methods <ip>
ssh -o PreferredAuthentications=none -o StrictHostKeyChecking=no <ip> 2>&1 | grep -i 'authentication'
```

## FTP

Anonymous access, sensitive files, and writable directory testing:

```bash
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor <ip>
# Manual anonymous access verification (nmap scripts can give false negatives due to PASV issues)
curl -s ftp://anonymous:anonymous@<ip>/
# Recursive directory listing (discover subdirectories with backup files)
wget --spider -r --no-remove-listing ftp://anonymous:anonymous@<ip>/ 2>&1 | grep -E 'directory|listing'
# Search for sensitive files in accessible directories
curl -s ftp://anonymous:anonymous@<ip>/ | grep -iE '\.(tar|zip|gz|bak|sql|conf|env|key|pem|kdbx)'
# Writable directory test
curl -s -T /tmp/test_upload.txt ftp://anonymous:anonymous@<ip>/pub/ && echo "WRITABLE"
```

## Database Services

```bash
# MySQL enumeration
nmap --script mysql-enum -p 3306 <ip>
mysql -h <ip> -u root -e 'SELECT 1' 2>&1          # test direct connection (reveals ACL vs auth errors)
# MSSQL information gathering
nmap --script ms-sql-info -p 1433 <ip>
impacket-mssqlclient <user>:<password>@<ip> 2>&1  # interactive session (check sysadmin, xp_cmdshell, linked servers)
# PostgreSQL connection testing
nmap --script pgsql-brute -p 5432 <ip>
psql -h <ip> -U postgres -c '\l' 2>&1             # test direct connection
```

Use `mssqlpwner` for MSSQL linked server exploitation and privilege escalation when credentials are available (see `../exploitation/tools/mssqlpwner.md`).

## Mail

SMTP relay testing and user enumeration:

```bash
nmap --script smtp-open-relay -p 25 <ip>
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <ip>
# SMTP relay and auth testing with swaks
swaks --to test@<target> --from test@attacker.com --server <ip>
swaks --to test@<target> --server <ip> --auth LOGIN --auth-user <user> --auth-password <pass>
```

Use `swaks` for flexible SMTP relay and authentication testing (see `../vulnerability/tools/swaks.md`). Use `smtp-user-enum` for VRFY/EXPN/RCPT user enumeration (see `../vulnerability/tools/smtp-user-enum.md`).

## NFS

Export enumeration and access testing:

```bash
showmount -e <ip>                       # list exported shares
# Mount and enumerate (if accessible)
mkdir -p /tmp/nfs_mount && mount -t nfs <ip>:/<export> /tmp/nfs_mount
```

## IPMI

Baseboard management controller access:

```bash
nmap --script ipmi-version -p 623 -sU <ip>
ipmitool -I lanplus -H <ip> -U admin -P admin chassis status
ipmitool -I lanplus -H <ip> -U admin -P admin user list 1
```

## Redis / NoSQL

Unauthenticated access and data enumeration:

```bash
nmap -p 6379 --script redis-info,redis-brute <ip>
redis-cli -h <ip> ping                  # test unauthenticated command access
redis-cli -h <ip> INFO keyspace         # enumerate databases and key counts
redis-cli -h <ip> CONFIG GET requirepass # check authentication status
redis-cli -h <ip> CONFIG GET dir        # check write capability (dir writable = exploitable)
redis-cli -h <ip> CONFIG GET dbfilename # current dump filename
# If CONFIG is accessible with no auth: SSH key injection, webshell write, or cron exploitation possible
# See ../exploitation/README.md Path 3 (Redis writable) for exploitation steps
nmap -p 27017 --script mongodb-info,mongodb-databases <ip>
```

## Unlisted Services

For services not covered above (e.g., VNC, Telnet, Elasticsearch, Java RMI, Oracle TNS), apply the per-service test matrix: probe the service with `nmap` version detection and NSE scripts, test for unauthenticated access, check for known CVEs via `searchsploit` and `getsploit`, and attempt default credentials. For database services with credentials, check for OS command execution capabilities.

## Cross-References

- `internal-network.md` — parent playbook; this file is invoked from its Phase 5, and the per-service test matrix, CVE evaluation, and depth directives live in its Phase 3.
- `active-directory.md` — switch to it for full AD testing when Kerberos, LDAP, or SMB enumeration reveals a domain environment.
