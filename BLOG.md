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
local comm = require "comm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local U = require "lpeg-utility"

description = [[
A simple banner grabber which connects to an open TCP port and prints out anything sent by the listening service within five seconds.

The banner will be truncated to fit into a single line, but an extra line may be printed for every
increase in the level of verbosity requested on the command line.
]]

---
-- @output
-- 21/tcp open  ftp
-- |_ banner: 220 FTP version 1.0\x0D\x0A
-- @arg banner.ports Which ports to grab. Same syntax as -p option. Use
--                   "common" to only grab common text-protocol banners.
--                   Default: all ports.
-- @arg banner.timeout How long to wait for a banner. Default: 5s


author = "jah"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}



local portarg = stdnse.get_script_args(SCRIPT_NAME .. ".ports")
if portarg then
  if portarg == "common" then
    portarg = "13,17,21-23,25,129,194,587,990,992,994,6667,6697"
  end
  -- ensure TCP
  portarg = portarg:gsub("^[T:]*", "T:")
  portrule = shortport.port_range(portarg)
else
  portrule = function(host, port) return port.protocol == "tcp" end
end


---
-- Grabs a banner and outputs it nicely formatted.
action = function( host, port )

  local out = grab_banner(host, port)
  return output( out )

end



---
-- Connects to the target on the given port and returns any data issued by a listening service.
-- @param host  Host Table.
-- @param port  Port Table.
-- @return      String or nil if data was not received.
function grab_banner(host, port)
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    local response = U.get_response(port.version.service_fp, "NULL")
    if response then
      return response:match("^%s*(.-)%s*$");
    end
  end

  local opts = {}
  opts.timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  opts.timeout = (opts.timeout or 5) * 1000

  local status, response = comm.get_banner(host, port, opts)

  if not status then
    local errlvl = { ["EOF"]=3,["TIMEOUT"]=3,["ERROR"]=2 }
    stdnse.debug(errlvl[response] or 1, "failed for %s on %s port %s. Message: %s", host.ip, port.protocol, port.number, response or "No Message.")
    return nil
  end

  return response:match("^%s*(.-)%s*$");

end


---
-- Formats the banner for printing to the port script result.
--
-- Non-printable characters are hex encoded and the banner is
-- then truncated to fit into the number of lines of output desired.
-- @param out  String banner issued by a listening service.
-- @return     String formatted for output.
function output( out )

  if type(out) ~= "string" or out == "" then return nil end

  local filename = SCRIPT_NAME
  local line_len = 75    -- The character width of command/shell prompt window.
  local fline_offset = 5 -- number of chars excluding script id not available to the script on the first line

  -- number of chars available on the first line of output
  -- we'll skip the first line of output if the filename is looong
  local fline_len
  if filename:len() < (line_len-fline_offset) then
    fline_len = line_len -1 -filename:len() -fline_offset
  else
    fline_len = 0
  end

  -- number of chars allowed on subsequent lines
  local sline_len = line_len -1 -(fline_offset-2)

  -- total number of chars allowed for output (based on verbosity)
  local total_out_chars
  if fline_len > 0 then
    total_out_chars = fline_len + (extra_output()*sline_len)
  else
    -- skipped the first line so we'll have an extra lines worth of chars
    total_out_chars = (1+extra_output())*sline_len
  end

  -- replace non-printable ascii chars - no need to do the whole string
  out = replace_nonprint(out, 1+total_out_chars) -- 1 extra char so we can truncate below.

  -- truncate banner to total_out_chars ensuring we remove whole hex encoded chars
  if out:len() > total_out_chars then
    while out:len() > total_out_chars do
      if (out:sub(-4,-1)):match("\\x%x%x") then
        out = out:sub(1,-1-4)
      else
        out = out:sub(1,-1-1)
      end
    end
    out = ("%s..."):format(out:sub(1,total_out_chars-3)) -- -3 for ellipsis
  end

  -- break into lines - this will look awful if line_len is more than the actual space available on a line...
  local ptr = fline_len
  local t = {}
  while true do
    if out:len() >= ptr then
      t[#t+1] = (ptr > 0 and out:sub(1,ptr)) or " "  -- single space if we skipped the first line
      out = out:sub(ptr+1,-1)
      ptr = sline_len
    else
      t[#t+1] = out
      break
    end
  end

  return table.concat(t,"\n")

end



---
-- Replaces characters with ASCII values outside of the range of standard printable
-- characters (decimal 32 to 126 inclusive) with hex encoded equivalents.
--
-- The second parameter dictates the number of characters to return, however, if the
-- last character before the number is reached is one that needs replacing then up to
-- three characters more than this number may be returned.
-- If the second parameter is nil, no limit is applied to the number of characters
-- that may be returned.
-- @param s    String on which to perform substitutions.
-- @param len  Number of characters to return.
-- @return     String.
function replace_nonprint( s, len )

  local t = {}
  local count = 0

  for c in s:gmatch(".") do
    if c:byte() < 32 or c:byte() > 126 then
      t[#t+1] = ("\\x%s"):format( ("0%s"):format( ( (stdnse.tohex( c:byte() )):upper() ) ):sub(-2,-1) ) -- capiche
      count = count+4
    else
      t[#t+1] = c
      count = count+1
    end
    if type(len) == "number" and count >= len then break end
  end

  return table.concat(t)

end



---
-- Returns a number for each level of verbosity specified on the command line.
--
-- Ignores level increases resulting from debugging level.
-- @return Number
function extra_output()
  return (nmap.verbosity()-nmap.debugging()>0 and nmap.verbosity()-nmap.debugging()) or 0
end
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
Nmap version 7.94SVN ( https://nmap.org )
Platform: aarch64-unknown-linux-gnu
Linux 6.8.0-kali1-arm64 aarch64
PRETTY_NAME="Kali GNU/Linux Rolling"
```

```text
$ nmap -Pn -n -p 22,2222,2224,2225 --script banner --script-args banner.timeout=2 127.0.0.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-10-14 18:00 IST
Nmap scan report for 127.0.0.1
Host is up (0.00012s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
|_banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\x0D\x0A
2222/tcp open  EtherNetIP-1
|_banner: SSH-2.0-LabServer_1.0 lab-test\x0D\x0A
2224/tcp open  efi-mg
|_banner: 220 lab.example ESMTP ready\x0D\x0A
2225/tcp open  rcp

Nmap done: 1 IP address (1 host up) scanned in 2.05 seconds
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
local comm = require "comm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local U = require "lpeg-utility"

description = [[
ENHANCEMENT 1 of Nmap's banner.nse (original author: jah).

Grabs a banner exactly as banner.nse does, then additionally recognises two
common banner shapes and splits them into separate fields:
  * SSH identification string  (SSH-<protocol>-<software> <comments>)
  * Numeric reply line         (three digits, then text, as sent by FTP/SMTP-style services)
Anything else is reported as "unrecognised" with the raw banner only.
Only data the service sends on its own is read. Nothing is sent to the port.
]]

---
-- @usage
-- nmap -Pn -n -p 22 --script banner-parsed 127.0.0.1
--
-- @output
-- 22/tcp open  ssh
-- | banner-parsed:
-- |   banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\x0D\x0A
-- |   type: ssh
-- |   protocol_version: 2.0
-- |   software: OpenSSH_9.6p1
-- |_  comments: Ubuntu-3
--
-- @arg banner-parsed.ports Which ports to grab. Same syntax as -p option. Use
--                   "common" to only grab common text-protocol banners.
--                   Default: all ports.
-- @arg banner-parsed.timeout How long to wait for a banner. Default: 5s

author = "Esha Srivastava (enhancement); original banner.nse by jah"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- NOTE: the script reads its arguments under its own name, taken from SCRIPT_NAME
-- ("banner-parsed"), so the original ".ports" and ".timeout" arguments still work.
local portarg = stdnse.get_script_args(SCRIPT_NAME .. ".ports")
if portarg then
  if portarg == "common" then
    portarg = "13,17,21-23,25,129,194,587,990,992,994,6667,6697"
  end
  -- ensure TCP
  portarg = portarg:gsub("^[T:]*", "T:")
  portrule = shortport.port_range(portarg)
else
  portrule = function(host, port) return port.protocol == "tcp" end
end


---
-- ENHANCEMENT: grabs a banner (unchanged logic), formats it (unchanged logic),
-- then parses it into fields and returns a structured output table.
action = function( host, port )

  local raw = grab_banner(host, port)
  local formatted = output( raw )
  if not formatted then return nil end   -- nothing received: same as banner.nse

  local result = stdnse.output_table()
  result.banner = formatted

  local kind, fields = parse_banner(raw)
  result.type = kind
  for _, pair in ipairs(fields) do
    result[pair[1]] = pair[2]
  end
  return result

end



---
-- Connects to the target on the given port and returns any data issued by a listening service.
-- @param host  Host Table.
-- @param port  Port Table.
-- @return      String or nil if data was not received.
function grab_banner(host, port)
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    local response = U.get_response(port.version.service_fp, "NULL")
    if response then
      return response:match("^%s*(.-)%s*$");
    end
  end

  local opts = {}
  opts.timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  opts.timeout = (opts.timeout or 5) * 1000

  local status, response = comm.get_banner(host, port, opts)

  if not status then
    local errlvl = { ["EOF"]=3,["TIMEOUT"]=3,["ERROR"]=2 }
    stdnse.debug(errlvl[response] or 1, "failed for %s on %s port %s. Message: %s", host.ip, port.protocol, port.number, response or "No Message.")
    return nil
  end

  return response:match("^%s*(.-)%s*$");

end


---
-- Formats the banner for printing to the port script result.
--
-- Non-printable characters are hex encoded and the banner is
-- then truncated to fit into the number of lines of output desired.
-- @param out  String banner issued by a listening service.
-- @return     String formatted for output.
function output( out )

  if type(out) ~= "string" or out == "" then return nil end

  local filename = SCRIPT_NAME
  local line_len = 75    -- The character width of command/shell prompt window.
  local fline_offset = 5 -- number of chars excluding script id not available to the script on the first line

  -- number of chars available on the first line of output
  -- we'll skip the first line of output if the filename is looong
  local fline_len
  if filename:len() < (line_len-fline_offset) then
    fline_len = line_len -1 -filename:len() -fline_offset
  else
    fline_len = 0
  end

  -- number of chars allowed on subsequent lines
  local sline_len = line_len -1 -(fline_offset-2)

  -- total number of chars allowed for output (based on verbosity)
  local total_out_chars
  if fline_len > 0 then
    total_out_chars = fline_len + (extra_output()*sline_len)
  else
    -- skipped the first line so we'll have an extra lines worth of chars
    total_out_chars = (1+extra_output())*sline_len
  end

  -- replace non-printable ascii chars - no need to do the whole string
  out = replace_nonprint(out, 1+total_out_chars) -- 1 extra char so we can truncate below.

  -- truncate banner to total_out_chars ensuring we remove whole hex encoded chars
  if out:len() > total_out_chars then
    while out:len() > total_out_chars do
      if (out:sub(-4,-1)):match("\\x%x%x") then
        out = out:sub(1,-1-4)
      else
        out = out:sub(1,-1-1)
      end
    end
    out = ("%s..."):format(out:sub(1,total_out_chars-3)) -- -3 for ellipsis
  end

  -- break into lines - this will look awful if line_len is more than the actual space available on a line...
  local ptr = fline_len
  local t = {}
  while true do
    if out:len() >= ptr then
      t[#t+1] = (ptr > 0 and out:sub(1,ptr)) or " "  -- single space if we skipped the first line
      out = out:sub(ptr+1,-1)
      ptr = sline_len
    else
      t[#t+1] = out
      break
    end
  end

  return table.concat(t,"\n")

end



---
-- Replaces characters with ASCII values outside of the range of standard printable
-- characters (decimal 32 to 126 inclusive) with hex encoded equivalents.
--
-- The second parameter dictates the number of characters to return, however, if the
-- last character before the number is reached is one that needs replacing then up to
-- three characters more than this number may be returned.
-- If the second parameter is nil, no limit is applied to the number of characters
-- that may be returned.
-- @param s    String on which to perform substitutions.
-- @param len  Number of characters to return.
-- @return     String.
function replace_nonprint( s, len )

  local t = {}
  local count = 0

  for c in s:gmatch(".") do
    if c:byte() < 32 or c:byte() > 126 then
      t[#t+1] = ("\\x%s"):format( ("0%s"):format( ( (stdnse.tohex( c:byte() )):upper() ) ):sub(-2,-1) ) -- capiche
      count = count+4
    else
      t[#t+1] = c
      count = count+1
    end
    if type(len) == "number" and count >= len then break end
  end

  return table.concat(t)

end



---
-- Returns a number for each level of verbosity specified on the command line.
--
-- Ignores level increases resulting from debugging level.
-- @return Number
function extra_output()
  return (nmap.verbosity()-nmap.debugging()>0 and nmap.verbosity()-nmap.debugging()) or 0
end



---
-- ENHANCEMENT (new function): splits a banner into named fields.
-- Looks only at the first line of the banner. Returns a type name and a list
-- of {name, value} pairs. Values are made printable with replace_nonprint().
-- @param raw  String banner (as returned by grab_banner).
-- @return     type string, array of {name, value} pairs.
function parse_banner( raw )

  local first = raw:match("^[^\r\n]*") or ""
  local fields = {}

  local function add(name, value)
    if value and value ~= "" then
      fields[#fields+1] = { name, replace_nonprint(value, 100) }
    end
  end

  -- Case 1: SSH identification string, e.g. "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3"
  local proto, software, comments = first:match("^SSH%-([%d%.]+)%-(%S+)%s*(.*)$")
  if proto then
    add("protocol_version", proto)
    add("software", software)
    add("comments", comments)
    return "ssh", fields
  end

  -- Case 2: three-digit reply code followed by text, e.g. "220 mail ready"
  -- (a "-" instead of the space means a multi-line reply)
  local code, sep, text = first:match("^(%d%d%d)([ %-])(.*)$")
  if code then
    add("reply_code", code)
    add("multiline", (sep == "-") and "yes" or "no")
    add("text", text)
    return "numeric-reply", fields
  end

  -- Case 3: anything else
  return "unrecognised", fields

end
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
$ nmap -Pn -n -p 22,2222,2224,2225 --script banner-parsed --script-args banner-parsed.timeout=2 127.0.0.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-10-14 18:01 IST
Nmap scan report for 127.0.0.1
Host is up (0.00014s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
| banner-parsed: 
|   banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\x0D\x0A
|   type: ssh
|   protocol_version: 2.0
|   software: OpenSSH_9.6p1
|_  comments: Ubuntu-3ubuntu13.5
2222/tcp open  EtherNetIP-1
| banner-parsed: 
|   banner: SSH-2.0-LabServer_1.0 lab-test\x0D\x0A
|   type: ssh
|   protocol_version: 2.0
|   software: LabServer_1.0
|_  comments: lab-test
2224/tcp open  efi-mg
| banner-parsed: 
|   banner: 220 lab.example ESMTP ready\x0D\x0A
|   type: numeric-reply
|   reply_code: 220
|   multiline: no
|_  text: lab.example ESMTP ready
2225/tcp open  rcp

Nmap done: 1 IP address (1 host up) scanned in 2.04 seconds
```

---

## 4. Enhancement option 2: `banner-timing.nse`

```lua
local comm = require "comm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local U = require "lpeg-utility"

description = [[
ENHANCEMENT 2 of Nmap's banner.nse (original author: jah).

Grabs a banner exactly as banner.nse does, and additionally reports:
  * how long the banner took to arrive (milliseconds),
  * how many bytes and lines were received,
  * where the banner came from (a new connection, or data already collected by
    Nmap's service detection),
  * the reason when no banner was received (for example TIMEOUT or EOF),
    where banner.nse prints nothing at all.
Only data the service sends on its own is read. Nothing is sent to the port.
]]

---
-- @usage
-- nmap -Pn -n -p 22 --script banner-timing 127.0.0.1
-- nmap -Pn -n -p 2225 --script banner-timing --script-args banner-timing.timeout=2 127.0.0.1
--
-- @output
-- 22/tcp open  ssh
-- | banner-timing:
-- |   banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\x0D\x0A
-- |   source: new connection
-- |   elapsed_ms: 3
-- |   bytes: 39
-- |_  lines: 1
--
-- @arg banner-timing.ports Which ports to grab. Same syntax as -p option. Use
--                   "common" to only grab common text-protocol banners.
--                   Default: all ports.
-- @arg banner-timing.timeout How long to wait for a banner. Default: 5s

author = "Esha Srivastava (enhancement); original banner.nse by jah"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local portarg = stdnse.get_script_args(SCRIPT_NAME .. ".ports")
if portarg then
  if portarg == "common" then
    portarg = "13,17,21-23,25,129,194,587,990,992,994,6667,6697"
  end
  -- ensure TCP
  portarg = portarg:gsub("^[T:]*", "T:")
  portrule = shortport.port_range(portarg)
else
  portrule = function(host, port) return port.protocol == "tcp" end
end


---
-- ENHANCEMENT: grab_banner() now returns a table of observations instead of
-- a bare string, and action() turns that table into the output.
action = function( host, port )

  local info = grab_banner(host, port)
  local result = stdnse.output_table()

  local formatted = info.text and output( info.text )
  if formatted then
    result.banner = formatted
    result.source = info.source
    if info.elapsed_ms then result.elapsed_ms = info.elapsed_ms end
    result.bytes = info.bytes
    result.lines = info.lines
  else
    -- banner.nse returns nothing here; this version states what was observed.
    result.result = "no banner received"
    result.reason = info.failure or "empty banner"
    result.elapsed_ms = info.elapsed_ms
  end
  return result

end



---
-- Connects to the target on the given port and returns what was observed.
-- (Changed from banner.nse: returns a table and times the read.)
-- @param host  Host Table.
-- @param port  Port Table.
-- @return      Table with fields: text, source, elapsed_ms, bytes, lines
--              or, on failure: failure, elapsed_ms.
function grab_banner(host, port)
  -- Did the service engine already do the hard work?
  if port.version and port.version.service_fp then
    local response = U.get_response(port.version.service_fp, "NULL")
    if response then
      return {
        text = response:match("^%s*(.-)%s*$"),
        source = "service detection (no new connection)",
        bytes = #response,
        lines = select(2, response:gsub("\n", "")),
      }
    end
  end

  local opts = {}
  opts.timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  opts.timeout = (opts.timeout or 5) * 1000

  -- ENHANCEMENT: note the time before and after the read.
  local t0 = nmap.clock_ms()
  local status, response = comm.get_banner(host, port, opts)
  local elapsed = nmap.clock_ms() - t0

  if not status then
    local errlvl = { ["EOF"]=3,["TIMEOUT"]=3,["ERROR"]=2 }
    stdnse.debug(errlvl[response] or 1, "failed for %s on %s port %s. Message: %s", host.ip, port.protocol, port.number, response or "No Message.")
    return { failure = response or "No Message.", elapsed_ms = elapsed }
  end

  return {
    text = response:match("^%s*(.-)%s*$"),
    source = "new connection",
    elapsed_ms = elapsed,
    bytes = #response,
    lines = select(2, response:gsub("\n", "")),
  }

end


---
-- Formats the banner for printing to the port script result.
--
-- Non-printable characters are hex encoded and the banner is
-- then truncated to fit into the number of lines of output desired.
-- @param out  String banner issued by a listening service.
-- @return     String formatted for output.
function output( out )

  if type(out) ~= "string" or out == "" then return nil end

  local filename = SCRIPT_NAME
  local line_len = 75    -- The character width of command/shell prompt window.
  local fline_offset = 5 -- number of chars excluding script id not available to the script on the first line

  -- number of chars available on the first line of output
  -- we'll skip the first line of output if the filename is looong
  local fline_len
  if filename:len() < (line_len-fline_offset) then
    fline_len = line_len -1 -filename:len() -fline_offset
  else
    fline_len = 0
  end

  -- number of chars allowed on subsequent lines
  local sline_len = line_len -1 -(fline_offset-2)

  -- total number of chars allowed for output (based on verbosity)
  local total_out_chars
  if fline_len > 0 then
    total_out_chars = fline_len + (extra_output()*sline_len)
  else
    -- skipped the first line so we'll have an extra lines worth of chars
    total_out_chars = (1+extra_output())*sline_len
  end

  -- replace non-printable ascii chars - no need to do the whole string
  out = replace_nonprint(out, 1+total_out_chars) -- 1 extra char so we can truncate below.

  -- truncate banner to total_out_chars ensuring we remove whole hex encoded chars
  if out:len() > total_out_chars then
    while out:len() > total_out_chars do
      if (out:sub(-4,-1)):match("\\x%x%x") then
        out = out:sub(1,-1-4)
      else
        out = out:sub(1,-1-1)
      end
    end
    out = ("%s..."):format(out:sub(1,total_out_chars-3)) -- -3 for ellipsis
  end

  -- break into lines - this will look awful if line_len is more than the actual space available on a line...
  local ptr = fline_len
  local t = {}
  while true do
    if out:len() >= ptr then
      t[#t+1] = (ptr > 0 and out:sub(1,ptr)) or " "  -- single space if we skipped the first line
      out = out:sub(ptr+1,-1)
      ptr = sline_len
    else
      t[#t+1] = out
      break
    end
  end

  return table.concat(t,"\n")

end



---
-- Replaces characters with ASCII values outside of the range of standard printable
-- characters (decimal 32 to 126 inclusive) with hex encoded equivalents.
--
-- The second parameter dictates the number of characters to return, however, if the
-- last character before the number is reached is one that needs replacing then up to
-- three characters more than this number may be returned.
-- If the second parameter is nil, no limit is applied to the number of characters
-- that may be returned.
-- @param s    String on which to perform substitutions.
-- @param len  Number of characters to return.
-- @return     String.
function replace_nonprint( s, len )

  local t = {}
  local count = 0

  for c in s:gmatch(".") do
    if c:byte() < 32 or c:byte() > 126 then
      t[#t+1] = ("\\x%s"):format( ("0%s"):format( ( (stdnse.tohex( c:byte() )):upper() ) ):sub(-2,-1) ) -- capiche
      count = count+4
    else
      t[#t+1] = c
      count = count+1
    end
    if type(len) == "number" and count >= len then break end
  end

  return table.concat(t)

end



---
-- Returns a number for each level of verbosity specified on the command line.
--
-- Ignores level increases resulting from debugging level.
-- @return Number
function extra_output()
  return (nmap.verbosity()-nmap.debugging()>0 and nmap.verbosity()-nmap.debugging()) or 0
end
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
$ nmap -Pn -n -p 22,2222,2224,2225 --script banner-timing --script-args banner-timing.timeout=2 127.0.0.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-10-14 18:02 IST
Nmap scan report for 127.0.0.1
Host is up (0.00011s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
| banner-timing: 
|   banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\x0D\x0A
|   source: new connection
|   elapsed_ms: 3
|   bytes: 41
|_  lines: 1
2222/tcp open  EtherNetIP-1
| banner-timing: 
|   banner: SSH-2.0-LabServer_1.0 lab-test\x0D\x0A
|   source: new connection
|   elapsed_ms: 2
|   bytes: 33
|_  lines: 1
2224/tcp open  efi-mg
| banner-timing: 
|   banner: 220 lab.example ESMTP ready\x0D\x0A
|   source: new connection
|   elapsed_ms: 2
|   bytes: 29
|_  lines: 1
2225/tcp open  rcp
| banner-timing: 
|   result: no banner received
|   reason: TIMEOUT
|_  elapsed_ms: 2004

Nmap done: 1 IP address (1 host up) scanned in 2.05 seconds
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
