# fw-clean — Firmware Persistence Cleaner

Wipes unused slack space in eMMC firmware partitions to eliminate persistence mechanisms hiding in partition tail padding.

## The Problem

Firmware implants love hiding in the unused tail end of partitions. Manufacturers pack real firmware data from offset 0, leaving the rest as `0xFF` padding. An implant can nestle into this space and survive reflashing (since most updaters only write the image, not the full partition).

## Strategy

1. Enumerate all eMMC partitions via GPT / by-name symlinks
2. Scan each partition backward from the end to find where real data stops
3. Overwrite the unused tail with `0xFF` (or `0x00` / random) to nuke anything hiding there
4. Profit

## Building

### For Fire TV (ARM)

```bash
# Most Fire TVs are ARM64 (newer) or ARM32 (older)
GOOS=linux GOARCH=arm64 go build -o fw-clean-arm64 .
GOOS=linux GOARCH=arm   go build -o fw-clean-arm   .
```

### For local testing

```bash
go build -o fw-clean .
```

## Deploying to Fire TV

```bash
# Enable ADB debugging on Fire TV:
#   Settings > My Fire TV > Developer Options > ADB Debugging

# Push the binary
adb push fw-clean-arm64 /data/local/tmp/fw-clean
adb shell chmod +x /data/local/tmp/fw-clean

# Get root (requires unlocked bootloader or magisk)
adb shell
su

# Run
/data/local/tmp/fw-clean --scan --verbose
```

## Usage

```
fw-clean --scan                              # Survey all partitions
fw-clean --scan --partition boot --verbose   # Deep scan boot partition
fw-clean --backup /sdcard/fw-backup --scan   # Backup + scan
fw-clean --clean --backup /sdcard/fw-backup  # Backup then clean all
fw-clean --clean --partition recovery        # Clean specific partition
fw-clean --clean --fill 0 --dry-run          # Zero-fill, dry run
fw-clean --clean --fill -1                   # Random fill (most thorough)
```

### Flags

| Flag | Description |
|------|-------------|
| `--scan` | Scan and report unused space |
| `--clean` | Wipe unused tail space |
| `--partition NAME` | Target specific partition |
| `--backup DIR` | Backup partitions before cleaning |
| `--force` | Skip confirmation prompts |
| `--fill N` | Fill byte: `255` (0xFF, default), `0` (zero), `-1` (random) |
| `--chunk N` | Read/write chunk size in bytes (default 4096) |
| `--dry-run` | Show what would happen without writing |
| `--verbose` | Detailed output |

## Partition Priority

The tool categorizes partitions:

- **HIGH**: Known persistence targets (`boot`, `recovery`, `misc`, `aboot`, `tee`, etc.)
- **SKIP**: Protected partitions that should never be touched (`system`, `userdata`, `vbmeta`, etc.)
- **normal**: Other partitions with slack space

## Safety

- **ALWAYS backup before cleaning** (`--backup`)
- Use `--dry-run` first to see what would happen
- Protected partitions are never touched even if explicitly targeted
- The tool requires root and will refuse to run without it
- If something goes wrong, restore from backup:
  ```bash
  dd if=/sdcard/fw-backup/boot.img of=/dev/block/by-name/boot
  ```

## Extending to Other Devices

The partition discovery is generic enough to work on most Android/eMMC devices. You may need to add device-specific partition names to the `highValuePartitions` or `protectedPartitions` maps.

For router firmware (OpenWrt, etc.) or UEFI/SPI flash, the concept is the same but the access method differs — those would need MTD/SPI flash tooling instead of block device access.
