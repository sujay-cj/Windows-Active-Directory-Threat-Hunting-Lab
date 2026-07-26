# Windows Active Directory Threat Hunting Lab

> **SOC Investigation Portfolio** — Threat hunting using Splunk SIEM against Windows Security Event Logs collected from an Active Directory environment.

---

## Overview

This repository documents a structured threat hunting exercise conducted in a home lab environment. Windows Security Event Logs from an Active Directory domain (`ATTACKRANGE.LOCAL`) were ingested into **Splunk Enterprise** and analyzed using **SPL (Search Processing Language)** queries to investigate five common attack hypotheses.

The goal is to demonstrate a **SOC analyst investigation methodology** — forming a hypothesis, building targeted queries, interpreting results honestly, and reaching an evidence-based conclusion. Not every hypothesis resulted in a confirmed attack; that is by design. A good SOC analyst knows when the data supports a conclusion and when it does not.

---

## Environment

| Component | Details |
|-----------|---------|
| **SIEM** | Splunk Enterprise 10.2.3 |
| **Index** | `soc_lab` |
| **Log Source** | Windows Security Event Log (`windows_security_text`) |
| **Domain** | `ATTACKRANGE.LOCAL` |
| **Domain Controller** | `win-dc-259.attackrange.local`, `win-dc-7216619.attackrange.local` |
| **Dataset** | Mordor/OTRF Attack Range datasets (simulated AD attack scenarios) |
| **Log Time Range** | November 2020 |

---

## Investigation Index

| # | Hypothesis | Key Event Codes | Conclusion |
|---|-----------|-----------------|------------|
| [01](./01-Brute-Force/README.md) | Brute Force Attack on Domain Account | 4625, 4624, 4740 | ⚠️ Evidence Found |
| [02](./02-Password-Spraying/README.md) | Password Spraying Attack | 4625 | ✅ No Evidence |
| [03](./03-Kerberoasting/README.md) | Kerberoasting (TGS Request Abuse) | 4769 | ⚠️ Inconclusive |
| [04](./04-DCSync/README.md) | DCSync Attack (Credential Dumping) | 4662 | ✅ No Confirmed Evidence |
| [05](./05-Golden-Ticket/README.md) | Golden Ticket / Privilege Escalation | 4624, 4732 | ⚠️ Suspicious Activity Found |

---

## Key Windows Security Event Codes Referenced

| Event Code | Description |
|------------|-------------|
| **4624** | An account was successfully logged on |
| **4625** | An account failed to log on |
| **4740** | A user account was locked out |
| **4769** | A Kerberos service ticket (TGS) was requested |
| **4662** | An operation was performed on an object (Directory Service access) |
| **4732** | A member was added to a security-enabled local group |

---

## Methodology

Each investigation follows this workflow:

```
Hypothesis
    ↓
Identify Relevant Event Codes
    ↓
Write SPL Query
    ↓
Analyze Results
    ↓
Drill Down / Pivot
    ↓
Evidence-Based Conclusion
    ↓
MITRE ATT&CK Mapping
```

---

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Investigation |
|-------------|---------------|---------------|
| T1110.001 | Brute Force: Password Guessing | [01-Brute-Force](./01-Brute-Force/README.md) |
| T1110.003 | Brute Force: Password Spraying | [02-Password-Spraying](./02-Password-Spraying/README.md) |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | [03-Kerberoasting](./03-Kerberoasting/README.md) |
| T1003.006 | OS Credential Dumping: DCSync | [04-DCSync](./04-DCSync/README.md) |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | [05-Golden-Ticket](./05-Golden-Ticket/README.md) |

---

## Skills Demonstrated

- Splunk SPL query development for Windows Security Events
- Windows authentication log analysis (NTLM, Kerberos, Logon Types)
- Active Directory attack pattern recognition
- Evidence-based SOC investigation methodology
- MITRE ATT&CK framework mapping
- Honest reporting — documenting negative findings alongside positive ones

---

## Important Note on Results

This lab uses **publicly available simulated attack datasets** (Mordor/OTRF Attack Range). Some investigations returned no results because the specific attack technique's log artifacts were either not present in the dataset or required additional data sources not available in the current index. Where this is the case, it is documented transparently in each investigation's README.

---

*Repository by Sujay C J | Cybersecurity Portfolio*
