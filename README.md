# nmap-banner-enhancements

Two enhanced versions of Nmap's own `banner.nse` (original author: jah; `reference/banner.nse`
is the unmodified upstream file, shown for comparison).

| Script | What it adds |
|---|---|
| `banner-parsed.nse` | Splits SSH identification strings and numeric reply lines (e.g. `220 ...`) into named fields |
| `banner-timing.nse` | Adds elapsed time, byte and line counts, banner source, and the reason a banner was missing |

Both only listen for what the service sends; neither sends data. Use only on localhost or
systems you are authorised to test. Nmap is not an invisibility tool, and even one connection
may be logged or noticed.

## Install
```bash
nmap --version
sudo cp banner-parsed.nse banner-timing.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
nmap --script-help banner-parsed
nmap --script-help banner-timing
```

## Run
```bash
sudo systemctl start ssh
nmap -Pn -n -p 22 --script banner-parsed 127.0.0.1
nmap -Pn -n -p 22 --script banner-timing 127.0.0.1
nmap -Pn -n -p 22 --script banner-timing -oN scan-output.txt 127.0.0.1
```
Never use `-sC` or `-A`; they start other scripts.

## Generate the real outputs and the blog
```bash
bash tests/run_blog_tests.sh      # writes outputs/*.txt
python3 tests/build_blog.py       # writes BLOG.md from BLOG.template.md
```

## Licence
Same as Nmap (see https://nmap.org/book/man-legal.html). Modified from `banner.nse` by jah.
