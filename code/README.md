# XoXo XSS Scanner – Reconstructed Source

This directory contains the reconstructed Go source code corresponding to the
`xoxo-linux-amd64` binary.

## Master License Key

Extracted from `.rodata` at address `0x74f69c` (17 bytes):

```text
Kassem@Xoxo@123%N
```

## Build

```bash
cd code
go build -o xoxo-rebuilt ./cmd/xoxo
```

## Usage

```bash
echo "http://test.com" > urls.txt
./xoxo-rebuilt -l urls.txt -key "Kassem@Xoxo@123%N"
```
