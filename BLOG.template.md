# Beyond the Banner: Enhancing Nmap's `banner.nse` with Field Parsing and Timing Observations

**Author:** Esha Srivastava

---

## 1. Introduction to Nmap

Nmap ("Network Mapper") is a free, open-source tool for discovering hosts and services on a
network. It sends carefully built packets, looks at the replies, and reports which hosts are
up, which ports are open, and which services are listening.

Nmap also contains the **Nmap Scripting Engine (NSE)**. NSE runs small scripts written in the
Lua language. Each script has a *rule* (when should I run?) and an *action* (what should I do?).
Scripts are stored in `/usr/share/nmap/scripts/` and are chosen with `--script <name>`.

Nmap is a scanning tool, not an invisibility tool. Even a single connection to a port can be
recorded in logs or seen by network monitoring. All tests in this blog were run only against
`127.0.0.1` (my own machine) and my own lab services.

This blog takes one of Nmap's own scripts, `banner.nse`, and extends it in two different ways.

---

## 2. Reference script: `banner.nse`

The reference script is Nmap's `banner.nse` (author: jah). It is reproduced below unchanged.

```lua
{{FILE:reference/banner.nse}}
```

### Description of the reference script

`banner.nse` is a simple banner grabber. For each TCP port it:

1. **portrule** – runs on any TCP port (or only on ports given with `banner.ports`).
2. **grab_banner()** – asks Nmap's `comm` library to connect and read whatever the service
   sends on its own, waiting up to 5 seconds (`banner.timeout`). If service detection already
   captured a banner, it reuses that instead of opening a new connection.
3. **output()** – replaces non-printable bytes with `\xNN`, trims the text, and shortens it to
   fit one line (more lines are allowed with `-v`).
4. If nothing arrives, `grab_banner()` returns `nil`, so **nothing is printed** for that port.

### Output of the reference script

Environment used:

```text
{{FILE:outputs/environment.txt}}
```

```text
{{FILE:outputs/banner.txt}}
```

### Enhancement options identified

Reading the script shows two things it does not do:

- **Enhancement option 1 – parse the banner.** The banner is shown as one block of text. The
  reader must interpret it. Option 1 splits recognised banners into named fields (protocol
  version, software, reply code, and so on).
- **Enhancement option 2 – timing and failure reasons.** The script does not say how long the
  banner took, how much data arrived, or why nothing was printed when a port stayed silent.
  Option 2 adds those observations.

---

## 3. Enhancement option 1: `banner-parsed.nse`

```lua
{{FILE:banner-parsed.nse}}
```

### Description

The original grabbing and formatting code is kept as is. Two things change:

- `action()` now builds a table (`stdnse.output_table`) with the formatted `banner` and a
  `type` field.
- A new function, `parse_banner()`, looks at the first line of the banner:
  - If it matches `SSH-<protocol>-<software> <comments>`, it reports `protocol_version`,
    `software` and `comments`.
  - If it matches a three-digit code followed by text (such as `220 ...`), it reports
    `reply_code`, `multiline` (a `-` after the code) and `text`.
  - Otherwise it reports `type: unrecognised`.

It reads only what the service sends and sends nothing itself. The `type` value is based on the
shape of the text only. It does not prove which protocol the service really speaks.

### Output

```text
{{FILE:outputs/banner-parsed.txt}}
```

---

## 4. Enhancement option 2: `banner-timing.nse`

```lua
{{FILE:banner-timing.nse}}
```

### Description

Again the formatting code is unchanged. The changes are:

- `grab_banner()` now returns a **table of observations** instead of a bare string. It records
  `nmap.clock_ms()` before and after the read to get `elapsed_ms`, and counts `bytes` and
  `lines`.
- It records the `source`: a new connection, or data already collected by service detection
  (in which case no new timing exists, so none is shown).
- When no banner arrives, it returns the reason (`TIMEOUT`, `EOF`, `ERROR`) instead of `nil`.
  `action()` prints this as `result` and `reason`.

The reported time is a single measurement and includes local scheduling noise.

### Output

```text
{{FILE:outputs/banner-timing.txt}}
```

---

## 5. Learning outcomes

- How Nmap's NSE is structured: metadata, `portrule`, and `action`.
- How to read an existing script and find what it leaves out.
- How to use NSE libraries: `comm`, `stdnse`, `shortport` and `nmap`.
- How to turn raw text into structured output with Lua patterns and `stdnse.output_table`.
- How to measure elapsed time in a script and report failure reasons instead of failing silently.
- How to test a script safely against localhost and small lab services, and to run only one
  named script instead of the whole default set.
- How to respect the original author's licence and credit when extending someone else's code.

---

## 6. GitHub repository

The two enhanced scripts (`banner-parsed.nse` and `banner-timing.nse`) are available here:

**[https://github.com/pov3sha/nmapscripts](https://github.com/pov3sha/nmapscripts)**

---

## 7. Conclusion

`banner.nse` shows what a service says when it is contacted. The two enhancements keep that
behaviour and add information from the same single connection: option 1 turns the banner into
fields, and option 2 adds timing, size and the reason for a missing banner. Both still only
listen, so no extra probes are sent. Their limits are that field parsing recognises only two
banner shapes, and that a banner is whatever the service chooses to send.

Possible future work: more banner shapes (POP3, IMAP, FTP multi-line replies), output in
a machine-readable format, and a repeat-measurement mode for timing.

---

## 8. Acknowledgements

- The Nmap project and its contributors, for Nmap and the NSE documentation.
- jah, the author of the original `banner.nse`, on which both enhancements are based.
- My course faculty, for the assignment and guidance.
