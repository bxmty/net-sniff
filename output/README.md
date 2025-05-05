# Network Scan Output Directory

This directory contains CSV output files from network scanning operations.

By default, all network scan results will be saved to this directory unless a different output location is specified using the `--output` option.

## File Naming

Files are named using the format:

```
network_scan_YYYYMMDD_HHMMSS.csv
```

Where `YYYYMMDD_HHMMSS` is the timestamp of when the scan was conducted.

You can also specify a custom filename using the `--filename` option.