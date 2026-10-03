---
title: DQL query language
parent: English
nav_order: 5
---

# DQL query language
{: .no_toc }

[Русская версия](../ru/dql.html)

1. TOC
{:toc}

## In short

```
EventID = 4624 and LogonType in (3, 10) and not TargetUserName endswith "$"
| group by TargetUserName, IpAddress
| sort count desc
| limit 50
```

- Type the query in the bar above the table and run it with Return or ⌘↩. Stop interrupts a long
  query; a new query cancels the previous one.
- The query runs **together with** the filter chips and the chosen time range: those apply first,
  then the query.
- The clear button empties the query; Reset All (⌘K) clears the query, filters and time range.
- The last 50 queries are kept in the history (the clock button).
- The "?" button opens a short reference.

## Conditions

A condition is `field operator value`. Conditions are combined with `and`, `or`, `not` and
parentheses.

- Precedence: `not` binds tighter than `and`, `and` tighter than `or`.
- Two conditions in a row without a connective mean `and`: `EventID = 4624 LogonType = 3` equals
  `EventID = 4624 and LogonType = 3`.
- Keywords can be written in any case.

### Values and quotes

- Values without spaces and without the characters `( ) , | " ' = ! < > ~` can be written without
  quotes: `10.20.30.40`, `S-1-5-18`, `0x17`, `ADMIN$`, `C:\Windows\x.exe`, `*\powershell.exe`,
  `10.0.0.0/8`.
- Values with spaces go in double or single quotes.
- Inside quotes only the quote itself and `\\` are escaped. Any other `\` stays as is, so Windows paths
  can be pasted unchanged: `Image = "C:\Windows\System32\cmd.exe"`.
- A field name with spaces, or one that clashes with a keyword, goes in backticks:
  `` `Threat Name` contains Trojan ``.

### Case

- **Field names** are case-insensitive: `eventid`, `EventID` and `@EventID` are the same. If the case
  has a field with exactly that spelling, it wins over an alias of the same name: `User` is the
  Sysmon field, `user` is the alias for the user SID.
- **Values** are compared case-insensitively, except with `==`.

## Operators

| Operator | Meaning |
|---|---|
| `=` | The whole value matches, case-insensitive. A value with `*` or `?` works as a `like` mask |
| `==` | The whole value matches, case-sensitive (with `*` or `?` — a case-insensitive mask) |
| `!=` | Everything that is not `=`, **including events without the field** |
| `<` `<=` `>` `>=` | Numbers or time |
| `between a and b` | Numbers or time in a range, both bounds included |
| `in (a, b, …)` / `not in (…)` | One of the values (up to 10,000 values) |
| `contains` or `~` | Substring |
| `not contains` or `!~` | No such substring (including events without the field) |
| `startswith`, `endswith` | Start or end of the value |
| `like` | Mask: `*` any characters, `?` one character; the mask covers the whole value |
| `matches` or `regex` | Regular expression |
| `cidr` | Address in a subnet: `IpAddress cidr 10.0.0.0/8` |
| `exists` / `not exists` | The field is present / absent |

After a field name, `not` is allowed only before `in`, `contains` and `exists`. Otherwise put `not`
before the condition: `not Image endswith "\explorer.exe"`.

### Substrings and masks

- `contains`, `startswith` and `endswith` match literally: `*`, `?`, `%`, `_` are ordinary characters.
  An empty value matches nothing.
- `like` and `=` with `*`/`?` are masks. There is no way to escape `*` and `?` themselves.
- All of them are case-insensitive.

### Regular expressions

- The ICU engine (`NSRegularExpression`), case-insensitive.
- A match anywhere in the value counts. Anchor with `^` and `$`.
- The expression is run on every unique value of the field, in parallel.
- Each value gets 2 seconds of CPU time. A value that takes longer is skipped. Detections report this
  as a note on the rule; the query bar does not show such a warning yet.

### Subnets

`cidr` accepts IPv4 and IPv6: `address/prefix`, or a single address without a prefix. Field values
such as `::ffff:10.1.2.3`, `[192.168.1.1]` and `fe80::1%12` are understood.

## Numbers

- `<`, `<=`, `>`, `>=` and `between` work only with numbers: decimal (a minus sign is allowed) or
  hexadecimal `0x…`. Non-numeric values are left out of such selections.
- `=` compares **text**: `TicketEncryptionType = 0x17` finds `0x17` but not `23`;
  `LogonType = 03` does not find `3`.

## Time

The `time` field (also `timestamp`, `timecreated`) is the event's TimeCreated, or the write time if
there is none.

```
time >= "2026-09-30 10:00" and time < "2026-09-30 12:00"
time between "2026-09-30 10:00" and "2026-09-30 12:00:30.5"
time >= 2026-09-30T07:00Z
```

- Format: `YYYY-MM-DD[ HH:MM[:SS[.fffffff]]]`, a space or `T` between date and time. A date alone
  means 00:00; up to 7 fraction digits.
- Without a suffix the time is read **in the chosen display time zone**. `Z` means UTC; `+03:00` or
  `-05:00` is an explicit offset (with a colon).
- A value with a space goes in quotes.
- `time = …` means "within this second".
- `between` includes both bounds, in any order.
- `time` supports `<`, `<=`, `>`, `>=`, `between`, `=`, `!=`. `in`, grouping and `exists` are not
  supported for time.

{: .note }
Changing the time zone does not re-run the current query: its times were read in the previous zone.
Run the query again.

A time range is easier to set on the histogram: drag across it and click Filter by selection. The
range appears as an orange chip.

## Searching all fields

A quoted string without a field name looks for a substring in every field of the event, including
system ones:

```
"mimikatz"
"mimikatz" "sekurlsa"            — both substrings (implicit and)
EventID = 4104 | search "Invoke-WebRequest"
```

It is a case-insensitive substring search, not a word search. An unquoted word is a field name.

## Comparing two fields

A right-hand side in backticks is another field:

```
Image endswith `OriginalFileName`
TargetUserName != `SubjectUserName`
```

- Operators: `=`, `==`, `!=`, `contains`/`~`, `startswith`, `endswith`.
- The first value of each field is used, among events that have both fields (`!=` also includes
  events missing one of them).
- Event data fields (EventData/UserData) are compared, not system fields.

## Fields

### Event data fields

- `<Data Name="X">` gives field `X`; an unnamed `<Data>` gives field `Data` (it may repeat).
- For UserData the name is the path below the root element joined with dots; an attribute is
  `path.attribute`.
- When a record's template is missing, fields are named `Value[0]`, `Value[1]`, …
- An unknown field name is an error that suggests similar names.

### System fields and aliases

| Write | Key | Contains |
|---|---|---|
| `EventID`, `id`, `event_id` | `@EventID` | The event code as a decimal number (without Qualifiers) |
| `channel`, `log` | `@Channel` | The log, e.g. `Security`, `Microsoft-Windows-Sysmon/Operational` |
| `provider`, `provider_name` | `@Provider` | The provider name |
| `host`, `computer` | `@Computer` | The Computer field as written in the event |
| `level` | `@Level` | Level as a number or a word (see below) |
| `user`, `userid`, `sid` | `@UserID` | The SID from System/Security |
| `file`, `source` | `@Source` | The source file name (with folders if names clash) |
| `flag`, `flags` | `@Flag` | Record flags, see [Cases and import](cases-import.html#record-flags) |
| `task`, `opcode` | `@Task`, `@Opcode` | Numbers from System |
| `keywords` | `@Keywords` | 16 hex digits: `0x8020000000000000` |

The level can be a number or a word with `=`, `!=`, `in`: `critical` = 1, `error` = 2, `warning` = 3,
`information`/`info` = 4 (also matches 0), `verbose` = 5. Russian words work too.

Audit results in the Security log are in `keywords`: success is `0x8020000000000000`, failure is
`0x8010000000000000`.

{: .warning }
The record number (EventRecordID), ProcessID and ThreadID are stored in the case and shown in the
details, but cannot be queried yet.

### Entities, bookmarks and detections

| Field | Operators | Finds |
|---|---|---|
| `anyhost`, `anyuser`, `anyip` | `=`, `!=`, `in` | Events of an entity in every role: a host in any spelling, an IP in any form, a user by name, `DOMAIN\name`, `name@domain` or SID |
| `tag` (`bookmark`) | `=`, `!=`, `in`, `exists` | Bookmarks by colour: `red`, `orange`, `yellow`, `green`, `blue`, `purple`; `tag = *` — any |
| `rule` | `=`, `!=`, `in`, `contains`, `exists` | Events matched by a rule, by id or title; `rule exists` — any rule |
| `rulelevel` | `=`, `!=`, `in`, `<`, `>`… | By level of matched rules: `informational`, `low`, `medium`, `high`, `critical` |

Examples: `anyip = 10.20.30.40`, `anyuser = "CORP\j.doe"`, `tag = red`, `rulelevel >= high`.

## Pipeline

Stages follow the conditions after `|`. The `|` before a stage keyword is optional, and a query can
start with a stage: `| group by IpAddress`.

| Stage | Does |
|---|---|
| `where <condition>` | Adds a condition with `and`. Can repeat |
| `search "text"` | Adds a substring search over all fields |
| `select f1, f2` (`project`) | Sets the table columns: time first, then these fields, then the description. Does not filter events |
| `group by f1, f2` | Groups with counts, largest first by default. Events without the field fall into the "—" group. Up to 20,000 groups |
| `sort f [asc\|desc]` (`order by`) | Sorting. Only the **first** key is used |
| `limit n` (`take`) | The first n rows or groups |

### Sorting

- `sort time desc` / `sort time` — newest first / oldest first. Without `sort time` the table keeps
  its current order.
- By another field: numbers compare as numbers, text compares "naturally" (`file2` < `file10`).
  Ties are ordered by time; events without the field come last.
- With `group by`: `sort count` — ascending, `sort count desc` — descending (the default),
  `sort <group field>` — by value.

### Limit

- Without sorting `limit n` gives the **n earliest** events; with `sort time desc` — the n newest.
- The histogram uses the result before `sort` and `limit`.

### Groups

Click a group to see its events. Double-click or Turn into filters and show events turns the group
values into filter chips and removes the `group by` stage.

## Limits

| What | Limit |
|---|---|
| Query length | 199,999 tokens |
| Parenthesis depth | about 62 levels |
| `in` list | 10,000 values |
| Regular expression | 2 s of CPU time per value |
| Groups | 20,000 |
| Query history | 50 (25 shown in the menu) |

There is no overall query timeout: stop a long query with Stop.

## Errors

An error is shown under the query bar with the character position:

| Query | Message |
|---|---|
| `EventID = "4624` | Unclosed quote (position 11) |
| `(EventID = 1` | Expected “)” (position 13) |
| `EventID =` | Expected a value |
| `EventID = 4624 foo` | An operator is expected after “foo” (=, !=, <, >, contains, in, …) |
| `EventID = 1 \| limit x` | A number is expected after limit |
| `Foo = 1` | Unknown field “Foo” with suggestions of similar names |

## How a query runs

- During import every unique string — a value or a field name — goes into a dictionary once. Events
  are numbered in time order. For every "field = value" pair the case keeps a sorted list of event
  numbers, a posting list. System properties are stored the same way, as fields `@EventID`,
  `@Channel` and so on.
- A query is parsed into a tree and **never becomes SQL**: your text reaches the fixed dictionary
  queries only as a parameter. An SQL injection attempt in a value simply finds nothing.
- Each condition finds the matching dictionary values: a hash for `=`, a trigram full-text index for
  substrings, a numeric index for `<` and `>`, a scan for regular expressions and subnets. Their
  posting lists are then merged.
- `and`, `or` and `not` are intersection, union and difference of sorted sets. Negation never
  materialises every event. Time conditions are a binary search over the array of timestamps.

## Ready-made queries

These are the presets in the Events sidebar. You can open, change and run them.

**Logons and accounts**

```
EventID = 4624 | group by LogonType, TargetUserName
EventID = 4625 | group by TargetUserName, IpAddress, SubStatus
EventID = 4625 | group by IpAddress | sort count desc
EventID = 4624 and LogonType = 3 and not TargetUserName endswith "$" | group by IpAddress, TargetUserName
EventID = 4624 and LogonType in (10, 7) | group by IpAddress, TargetUserName
EventID = 4648 | group by SubjectUserName, TargetUserName, TargetServerName
EventID = 4672 and not SubjectUserName in (SYSTEM, "LOCAL SERVICE", "NETWORK SERVICE") and not SubjectUserName endswith "$"
EventID in (4720, 4722, 4724, 4725, 4726, 4728, 4732, 4756, 4738) | group by EventID, TargetUserName
```

**Kerberos and NTLM**

```
EventID = 4769 and TicketEncryptionType = 0x17 and not ServiceName endswith "$"
EventID = 4768 and PreAuthType = 0
EventID = 4776 | group by TargetUserName, Workstation
```

**Execution and persistence**

```
EventID = 4688 or (provider = "Microsoft-Windows-Sysmon" and EventID = 1)
(EventID = 7045 and channel = System) or EventID = 4697
EventID = 4698 or (channel = "Microsoft-Windows-TaskScheduler/Operational" and EventID = 106)
EventID = 4104 and (ScriptBlockText contains FromBase64String or ScriptBlockText contains "Invoke-Expression" or ScriptBlockText contains DownloadString or ScriptBlockText contains "-enc" or ScriptBlockText contains IEX)
provider = "Microsoft-Windows-Sysmon" and EventID = 3 | group by Image, DestinationIp, DestinationPort
provider = "Microsoft-Windows-Sysmon" and EventID = 13 and TargetObject contains "\CurrentVersion\Run"
```

**Covering tracks**

```
(EventID = 1102 and channel = Security) or (EventID = 104 and channel = System) or (EventID = 1100 and channel = Security)
EventID = 4616 or (provider = "Microsoft-Windows-Kernel-General" and EventID = 1)
provider = "Microsoft-Windows-Windows Defender" and EventID in (1116, 1117, 5001, 5007)
```

**Resource access and log artefacts**

```
EventID in (5140, 5145) and ShareName in ("\\\\*\\ADMIN$", "\\\\*\\C$", "\\\\*\\IPC$") | group by IpAddress, ShareName, SubjectUserName
flag = carved
flag = beyondHeader and not flag = stale
flag = timeSkew
flag = parseError
```
