# tldhunter (domain availability checker)

A WIP Go rewrite and extension of [TLDHunt](https://github.com/yuyudhn/TLDHunt). A CLI to check domain name availability.

![](static/2026-08-23-tldhunter.png)

# How It Works?

To detect whether a domain is registered or not, we search for the words
"**Name Server**", "**nserver**", "**nameservers**", or "**status: active**" in
the output of the WHOIS command, as this is a signature of a registered domain
(thanks to [Alex Matveenko](https://github.com/Alex-Matveenko) for the
suggestion).

If you have a better signature or detection method, please feel free to submit a pull request.

# Domain Extension List

For the default Top Level Domain list (`tlds.txt`), we use data from
https://data.iana.org. You can update this list directly using the
`--update-tld` flag, which fetches the latest TLDs from IANA and saves them to
`tlds.txt`.

You can also use a custom TLD list, but ensure it is formatted like this:
```
.aero
.asia
.biz
.cat
.com
.coop
.info
.int
.jobs
.mobi
```

