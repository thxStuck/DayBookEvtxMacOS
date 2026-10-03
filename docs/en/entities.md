---
title: Entities, sessions, processes
parent: English
nav_order: 6
---

# Hosts, users, IPs, sessions and processes
{: .no_toc }

[Русская версия](../ru/entities.html)

1. TOC
{:toc}

## Entity registry

During import the app builds a registry of hosts, users and IP addresses from every log of the case.
The Hosts, Users and IP addresses sections show it as tables.

### Where entities come from

An entity's role in an event is set by the field name (exact, case-sensitive match):

| Fields | Entity | Role |
|---|---|---|
| `Computer` (System) | host | log (the computer that wrote the event) |
| The SID from System/Security | user | event context |
| `Target*`, `TargetUserSid`, `TargetOutbound*`, `AccountName`/`AccountDomain` | user | target |
| `Subject*`, `User`, `ParentUser` | user | subject |
| `WorkstationName`, `Workstation`, `ClientName`, `SourceHostname` | host | source |
| `DestinationHostname`, `TargetServerName` | host | destination |
| `IpAddress`, `ClientAddress`, `SourceIp`, `SourceAddress`, `Address`, `ClientIP` | IP | source |
| `DestinationIp`, `DestAddress` | IP | destination |

Special cases: in the RDP event RCM 1149, `Param1` and `Param2` are the user and `Param3` the IP;
EventLog 6011 (computer renamed) adds the previous host name to the host's other spellings.

### Normalisation

- **Hosts.** Leading `\\` is removed; `-`, `LOCALHOST`, `LOCAL`, `UNKNOWN`, `N/A` and IP addresses are
  dropped; a trailing `$` is removed; a fully qualified name is cut to its first label and upper-cased.
  `DC01.corp.local`, `dc01` and `DC01$` are one host.
- **Users.** `DOMAIN\name` and `name@domain` are understood. `NAME$` in a user field is a computer
  account: it becomes a host with the "computer account" role. A user is identified by SID when it is
  known, otherwise by `DOMAIN\name`. A name without a domain joins its only variant with a domain.
- **IP addresses.** Canonical form; the `::ffff:` prefix is removed; `127.0.0.0/8`, `::1`, `0.0.0.0`
  and `::` are dropped.
- **Built-in accounts** (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM-\*, UMFD-\*, NT SERVICE and
  BUILTIN accounts and so on) are marked with a gear. In Users they can be hidden with a switch.

### Table and card

- Columns: Name, other spellings (and SIDs for users), first and last seen, number of events, roles
  with the number of events in each.
- Search by name, other spelling or SID.
- Double-click shows every event of the entity. Context menu: Show all events, Show in timeline,
  Exclude from events, Copy name, Copy SID.
- The card on the right: first and last seen, number of events, All events and Timeline buttons.
- **Links** — entities of other kinds that appear in the same events (up to 150), with the number of
  shared events and the period. The Events button of a link shows the events where both appear.

{: .note }
Jumping to events from the registry always starts a **new search**: the previous query, filters and
time range are cleared and do not narrow the result. The previous query stays in the history.

In queries, entities are matched with `anyhost`, `anyuser` and `anyip` in every role and spelling.

## Logon sessions

Sessions, the Logons 4624 tab.

### How a session is built

- Security log events: logon 4624, logoff 4634 or 4647.
- Logon and logoff are matched by "host + boot + TargetLogonId". A LogonId is unique only within one
  boot of the system, so the boot is part of the key.
- The session ends at the earliest unused logoff that is not earlier than the logon.
- **Boots** are found from Kernel-General 12, EventLog 6005 and Security 4608. Marks less than 300
  seconds apart count as one boot. If a host has no such marks, all its logons are treated as one boot
  and the host is listed in the footer under "no boot information".
- **A privileged session** has a 4672 event with the same SubjectLogonId on the same host in the same
  boot.

### Table

| Column | Shows |
|---|---|
| Start, End, Duration | Logon and logoff time; "not closed" in orange if there is no logoff |
| User | `DOMAIN\name` |
| Type | Logon type with its name: 2 interactive, 3 network, 10 RDP and so on |
| Source | Workstation and/or IP |
| Priv. | "4672" if the session is privileged |
| Host, LogonId | |

- Filter by logon type and search by user, source, host and LogonId.
- Selecting a row shows the logon event in the details panel. Double-click shows the session events.
- Context menu: Session events, Session events in timeline, Logon event (4624), Logoff event.
- Session events are a query: the same host, the LogonId in `TargetLogonId`, `SubjectLogonId` or
  `LogonId`, time from logon to logoff. You can see and change it in the query bar.
- The footer explains the matching rule and gives counts: sessions, not closed, logoffs without a
  logon.

## RDP

The RDP tab of Sessions.

- Source: the `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` log, events 21, 22,
  23, 24, 25, 39, 40.
- Events are chained by computer and session number (SessionID). Event 21 starts a chain, 23 closes
  it. A new 21 while a chain is open closes that chain as not closed.
- Columns: Start, End, Host, Session, User, Address, Steps. Steps are a sequence such as
  "21 logon → 22 shell → 24 disconnect → 25 reconnect → 23 logoff" (currently shown in Russian in
  both interface languages).
- Context menu: first event of the chain, LSM events of this session.
- RCM 1149 and Security 4778/4779 are not part of the chains; they appear in the event table with
  descriptions and feed the entity registry. RDP logons in the Security log are type 10 sessions on
  the Logons 4624 tab.

## Process trees

Processes, with a Sysmon 1/5 / Security 4688 switch.

### Sysmon

- Sysmon events 1 (process created) and 5 (process terminated).
- A node is a ProcessGuid; the parent is the ParentProcessGuid. The link is **exact**: Sysmon itself
  recorded it.
- If the parent's creation event is missing, a synthetic node is built from ParentImage,
  ParentCommandLine and ParentProcessId (orange "?" mark).
- A repeated creation event with the same GUID is counted in the footer as a repeated GUID.

### Security 4688

- Events 4688 (created) and 4689 (exited).
- The parent is found **heuristically** by PID: a process whose PID equals the ProcessId field of the
  4688, on the same host and in the same boot; of those, the last one started no later than the child
  and not exited before it started. Hexadecimal and decimal PIDs are treated as equal.
- Such a link is marked with 🔗 and explained: PIDs are reused, check the times.
- If no parent is found, a synthetic node is built from ParentProcessName and the PID.

### Table

| Column | Shows |
|---|---|
| Process | Image name; full path in the tooltip |
| PID, Start, End | |
| User, Host | |
| Command line | |

- Searching by image or command line turns the tree into a flat list (up to 5,000 rows) with an
  Ancestors column.
- Selecting a node shows its creation event in the details panel.
- Context menu: Go to creation event, Events of this process (Sysmon — by ProcessGuid, 4688 — by PID
  within the process lifetime), the same in the timeline, Copy command line, Copy path.
- The footer says which linking rule is used and gives counts: processes, without a creation event,
  linked by PID, repeated GUIDs.
