# Writeups

Collection de walkthroughs de labs de pentest Active Directory, Windows et réseau — réalisés dans le cadre de ma formation en cybersécurité.

---

## Labs

| Plateforme | Lab | Difficulté | Techniques | Lien |
|---|---|---|---|---|
| HackSmarter | ShadowGate | Facile | SMB Null Session, AS-REP Roasting, ADCS ESC8, NTLM Relay, DCSync | [🇬🇧 EN](hacksmarter/shadowgate/README.md) · [🇫🇷 FR](hacksmarter/shadowgate/README.fr.md) |
| HackSmarter | MartiniAD | Facile | SMB Guest Access, Kerberoasting, Password Spraying, DCSync | [🇬🇧 EN](hacksmarter/martiniad/README.md) · [🇫🇷 FR](hacksmarter/martiniad/README.fr.md) |

---

## Structure

```
writeups/
└── <plateforme>/
    └── <nom-du-lab>/
        ├── README.md          # version anglaise
        ├── README.fr.md       # version française
        └── screenshots/
```

---

## Outils fréquemment utilisés

`nxc` (NetExec) · `impacket` · `certipy-ad` · `hashcat` / `john` · `smbclient` · `evil-winrm` · `BloodHound`
