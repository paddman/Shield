# Optional YARA engine

The agent has a YARA adapter, but does not silently download or trust an
executable during installation. To enable the YARA stage, place an approved
64-bit Windows YARA binary at:

```text
tools/yara64.exe
```

The installer copies that file when it is present. Obtain and verify the
binary through the organization's software supply-chain process; the upstream
VirusTotal YARA releases are documented at:

https://github.com/VirusTotal/yara/releases

Pin the expected release and SHA-256 in deployment records. Microsoft Defender
remains the primary local scan engine when YARA is not installed.
