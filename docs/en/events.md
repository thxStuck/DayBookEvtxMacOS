---
title: Working with events
parent: English
nav_order: 4
---

# Working with events
{: .no_toc }

[Русская версия](../ru/events.html)

1. TOC
{:toc}

## The case window

The sidebar is on the left; the chosen section and, where it applies, the event details panel are on
the right. The window title shows the case name and "N events · M files".

| Section | Shows |
|---|---|
| Events | The event table with the query, filters, histogram and grouping |
| Timeline | The same events as one stream with day and gap separators |
| Logs | One log, like Windows Event Viewer |
| Detections | Sigma rule matches — see [Sigma detections](detections.html) |
| Hosts, Users, IP addresses | The entity registry — see [Entities](entities.html) |
| Sessions | Logon sessions and RDP chains |
| Processes | Sysmon and Security 4688 process trees |

Counters next to the sections: Logs — logs with events, Detections — matched rules, registries —
number of entities.

Toolbar on the right: Case Information (ⓘ), time zone, Export, Histogram, Details.

## Events

From top to bottom: the query bar, the filter bar, the histogram, the table. A group panel appears on
the left when the query groups events.

### Query bar

- A query in [DQL](dql.html). Run it with Return or ⌘↩; Stop interrupts it.
- The clear button empties the query.
- The clock menu holds the query history.
- "?" opens a short language reference.

### Filters

A filter is a chip under the query bar: "Field = value" or "Field ≠ value" (red). An orange chip is a
time range. The query runs on top of the chips.

To add a filter:

- **Table** — right-click a cell: Filter = … or Exclude ≠ …. The description cell has a submenu for
  every field of the event.
- **Details** — right-click a field row.
- **Sidebar** — click a value for =, Option-click for ≠.
- **Histogram** — drag across it and click Filter by selection.

A chip can be clicked to turn it off and on, switched between = and ≠ or removed from its menu, or
removed with its × button.

Reset All (⌘K) clears the query, every filter and the time range. Earlier queries stay in the history.

### Table

- Default columns: Time, Computer, Log, ID, Level, Description / event data.
- The Columns menu (right-click) adds User, Provider, User (SID), File and RecordID. Any event field
  can be added with Add column. A `| select` stage sets the columns entirely.
- Columns can be reordered and resized; clicking the Time header flips the order.
- **Level** for audit events is Audit Success / Audit Failure (from Keywords), otherwise Critical,
  Error, Warning, Information, Verbose.
- **Description.** Common events get readable text in English or Russian: logons, Kerberos, processes,
  services, tasks, PowerShell, Sysmon, RDP, Defender and more. The text includes decoded values:
  logon types, NTSTATUS and Kerberos error codes, encryption types, `%%NNNN` codes. Risky signs are
  marked ⚠ (lsass access, RC4, logon without pre-authentication, DCSync signs, log clearing). Other
  events show "Field: value · …".
- **Time colour:** red — the record has a parse error; orange — recovered from slack, from a stale
  chunk or after a damaged area.
- A bookmarked row is tinted with the bookmark colour.
- Clicking a row opens the event in the details panel.
- Right-click: filters, Bookmark, Copy row (tab-separated values), Columns.

### Grouping

A query with `| group by` shows a group panel on the left: event count and field values. "—" means
the events have no such field. Over 20,000 groups the count is marked with "+".

- Click a group to see its events.
- Double-click or Turn into filters and show events turns the group values into filter chips and
  removes `group by` from the query.
- Groups are sorted by event count, largest first.

### Sidebar

**Presets** are ready-made queries by topic: logons and accounts, Kerberos/NTLM, execution and
persistence, covering tracks, resource access, log artefacts. A click replaces the query text and
keeps the chips. Every preset is listed in [DQL](dql.html#ready-made-queries).

Then come facets with counts over the **whole case**:

| Section | Click |
|---|---|
| Detections | Matches by rule level; a click runs `rulelevel = …`, All matched rules… opens Detections |
| Log files | Filter by file; `dirty` mark, path and SHA-256 in the tooltip |
| Bookmarks | Go to the event |
| Hosts, Users, IP addresses | Filter "… (any role) = …"; Option-click excludes |
| Logs, Computers, Event ID, Record flags | Filter =, Option-click ≠; "all values…" runs `group by` on the field |

Sidebar clicks **narrow the current search**. Jumps from other sections (entities, sessions,
processes, detections, logs) start a new search.

## Histogram

- The distribution of the current result over time (before `sort` and `limit`), about 160 bars. The
  bar width is chosen automatically, from 1 second to 1 year.
- Drag across the chart and click Filter by selection to add an orange time-range chip.
- **Outliers.** With more than 1,000 events the axis spans the 0.1–99.9th percentile, so a single
  record dated 1601 or 2099 does not flatten the chart. A line under the chart says how many events
  are off the axis and has a "show all" link. The choice is remembered.
- Show or hide it with the Histogram toolbar button.

## Timeline

One stream of events with the same query and filters as Events.

- Columns: Time, Log (with a coloured dot per channel), Computer, User, ID, Description.
- User takes the first available of: User, TargetDomainName\TargetUserName,
  SubjectDomainName\SubjectUserName, AccountDomain\AccountName, Param1, the SID from System.
- A new day is marked with a line; a gap of more than an hour between neighbouring events with a
  dashed line and a "⏸ gap …" note.

## Logs

One log at a time, like Windows Event Viewer. The query and filters of Events are not touched.

- **Sidebar tree:** Windows Logs (Application, Security, Setup, System, ForwardedEvents) and
  Applications and Services Logs grouped by vendor. The log is derived from the file name. Hide empty
  hides logs without events.
- **Header:** the log, number of records (and how many were recovered from slack), the file path,
  Open in Events.
- **Filter:** level chips (Critical, Error, Warning, Information, Verbose), plus Audit Success and
  Audit Failure for Security, a DQL filter field (Return) and Reset.
- Newest events on top. The details panel is below the table; drag the divider to resize it.
- Open in Events starts a new search in Events for this log with the same levels and DQL filter.

## Details panel

On the right in Events, Timeline, Sessions and Processes; at the bottom in Logs. The Details button
shows and hides it; drag its edge to resize.

### Fields tab

1. **Matched rules** — level, title, author and rule set; a click opens the rule.
2. **System:** description, bookmark, time in the chosen zone and in UTC (7 digits), the write time if
   it differs, EventID, log, provider, computer, level, user SID, EventRecordID, Task, Opcode,
   Keywords, ProcessID / ThreadID, file and path, flags in words.
3. **Event data** — every EventData and UserData field in record order. `%%NNNN` codes are shown as
   "text (code)".
4. **Copies of this record** — if copies were merged: file, chunk and offset of each.

Right-click a field: Filter = …, Exclude ≠ …, Add column, Copy value, Copy "name: value".

The Fields tab uses the case and works even if the source file is gone.

### XML and Hex tabs

The record's XML and bytes (16 per line with offset and ASCII) are read from the source log. While it
is being read, or if it cannot be, the tab explains why:

| Message | Meaning |
|---|---|
| Reading the record from the source file… | The file is being opened |
| The file has not responded for more than 3 seconds… | A network share is unavailable, a disk is asleep, or macOS is waiting for permission to access the folder |
| Source file not found… | The log was moved or deleted after import |
| macOS denied access to the source file… | Allow access in Files and Folders |
| A different record is at the stored position… | The file changed after import |

The path where the file is expected is shown under the message.

## Time zone

The clock menu on the toolbar:

- UTC (default);
- UTC± offset — 37 fixed offsets from −12:00 to +14:00, including +05:45 and −09:30;
- Time zone (with daylight saving) — 24 IANA zones;
- Mac local time.

The case stores time in UTC. The zone changes times in the table and details, the time column header,
the histogram axis, the day separators of the timeline, how times in queries are read and the time
column of exports. The details always show UTC too. The table shows milliseconds (extra digits are
cut, not rounded).

## Bookmarks and notes

- ⌘B (Event → Bookmark) puts a red bookmark on the selected event or removes it.
- Right-click → Bookmark: six colours, Note…, Remove bookmark. A note without a bookmark adds a yellow
  one. An event has one bookmark.
- Bookmarks show as the row colour, in the details and in the Bookmarks section of the sidebar; a
  click there goes to the event.
- Search: `tag = red`, `tag in (red, blue)`, `tag = *`.
- Bookmarks are stored in the case. Note text is not searchable and not exported.

## Keyboard shortcuts

| Keys | Action |
|---|---|
| ⌘N | New case from logs |
| ⌘O | Open a case |
| ⇧⌘W | Close the case |
| ⌘↩ or Return in the query bar | Run the query |
| ⌘K | Reset the query, filters and time range |
| ⌘B | Bookmark the selected event |
| Option-click in the sidebar | Exclude a value (≠) |
| Return / Esc in sheets | Confirm / cancel |
