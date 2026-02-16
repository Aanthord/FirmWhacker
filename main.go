// fw-clean: Firmware Persistence Cleaner for Fire TV / Android eMMC Devices
//
// This utility identifies unused space in firmware partitions and overwrites it
// to eliminate any persistence mechanisms hiding in padding/slack space.
//
// Strategy: Manufacturers pack real firmware data from the start of each partition.
// Unused tail space (typically 0xFF on NAND/eMMC) is prime real estate for implants.
// We find where real data ends and blast the rest.
//
// REQUIRES: root access on the target device (adb root or su)
// TARGETS: Fire TV (Amlogic/MediaTek), adaptable to other Android devices
//
// Usage:
//   fw-clean --scan                    # Scan and report unused space
//   fw-clean --clean                   # Wipe unused space (DANGEROUS)
//   fw-clean --clean --partition boot  # Wipe only a specific partition
//   fw-clean --backup /sdcard/backup   # Backup partitions before cleaning
//
// ALWAYS backup before cleaning. This tool can brick your device.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// GPT / Partition Table Structures
// ---------------------------------------------------------------------------

const (
	sectorSize    = 512
	gptHeaderSig  = "EFI PART"
	gptEntrySize  = 128
	maxPartitions = 128

	// Block device path patterns for eMMC on Android/Fire TV
	mmcBlockDev  = "/dev/block/mmcblk0"
	byNamePrefix = "/dev/block/by-name/"
	platformPath = "/dev/block/platform/"
)

type GPTHeader struct {
	Signature       [8]byte
	Revision        uint32
	HeaderSize      uint32
	HeaderCRC32     uint32
	Reserved        uint32
	MyLBA           uint64
	AlternateLBA    uint64
	FirstUsableLBA  uint64
	LastUsableLBA   uint64
	DiskGUID        [16]byte
	PartEntryStart  uint64
	NumPartEntries  uint32
	PartEntrySize   uint32
	PartEntryCRC32  uint32
}

type GPTEntry struct {
	TypeGUID   [16]byte
	UniqueGUID [16]byte
	FirstLBA   uint64
	LastLBA    uint64
	Attributes uint64
	Name       [72]byte // UTF-16LE encoded
}

// Partition represents a discovered partition with analysis results
type Partition struct {
	Name         string
	DevicePath   string
	StartLBA     uint64
	EndLBA       uint64
	SizeBytes    uint64
	DataEndOff   int64  // Offset where real data ends (tail starts)
	SlackBytes   int64  // Bytes of unused tail space
	SlackPercent float64
	FillByte     byte   // What the slack is filled with (0xFF, 0x00, etc.)
	IsHighValue  bool   // Known persistence target
	Backed       bool
	Cleaned      bool
}

// High-value partitions that are common persistence targets
var highValuePartitions = map[string]bool{
	"boot":     true,
	"recovery": true,
	"misc":     true,
	"aboot":    true,
	"abootimg": true,
	"dtbo":     true,
	"logo":     true,
	"tee":      true, // TrustZone
	"scp":      true, // System Control Processor
	"lk":       true, // Little Kernel bootloader
	"factory":  true,
	"proinfo":  true,
	"para":     true,
	"custom":   true,
	"oem":      true,
	"persist":  true,
}

// Partitions we should NEVER touch
var protectedPartitions = map[string]bool{
	"userdata":   true,
	"system":     true,
	"vendor":     true,
	"data":       true,
	"cache":      true,
	"metadata":   true,
	"super":      true,
	"vbmeta":     true,
	"vbmeta_a":   true,
	"vbmeta_b":   true,
	"gpt":        true,
	"pgpt":       true,
	"sgpt":       true,
	"preloader":  true,
	"preloader2": true,
}

// ---------------------------------------------------------------------------
// CLI Flags
// ---------------------------------------------------------------------------

var (
	flagScan      = flag.Bool("scan", false, "Scan partitions and report unused space")
	flagClean     = flag.Bool("clean", false, "Wipe unused tail space in partitions")
	flagPartition = flag.String("partition", "", "Target a specific partition by name")
	flagBackup    = flag.String("backup", "", "Backup directory (backs up before cleaning)")
	flagForce     = flag.Bool("force", false, "Skip confirmation prompts")
	flagFillByte  = flag.Int("fill", 0xFF, "Byte to fill slack space with (0xFF=erase, 0x00=zero, -1=random)")
	flagChunkSize = flag.Int("chunk", 4096, "Read/write chunk size in bytes")
	flagDryRun    = flag.Bool("dry-run", false, "Show what would be done without writing")
	flagVerbose   = flag.Bool("verbose", false, "Verbose output")
	flagHelp      = flag.Bool("help", false, "Show help")

	// FaceDancer mode
	flagFaceDancer = flag.Bool("facedancer", false, "Use FaceDancer USB transport (no root needed on target)")
	flagFDAddr     = flag.String("fd-addr", "127.0.0.1:7342", "FaceDancer proxy address")
	flagFDMITM     = flag.Bool("fd-mitm", false, "Start FaceDancer in MITM passthrough mode")
	flagFDLog      = flag.String("fd-log", "", "MITM log file path")

	// For development/testing on non-Android hosts
	flagDeviceOverride = flag.String("device", "", "Override block device path (for testing)")
)

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()

	if *flagHelp || (!*flagScan && !*flagClean) {
		printBanner()
		flag.Usage()
		fmt.Println("\nExamples:")
		fmt.Println("  fw-clean --scan                          # Survey all partitions (on-device)")
		fmt.Println("  fw-clean --scan --partition boot          # Survey boot partition only")
		fmt.Println("  fw-clean --backup /sdcard/fw-backup --scan")
		fmt.Println("  fw-clean --clean --backup /sdcard/fw-backup")
		fmt.Println("  fw-clean --clean --partition recovery --force")
		fmt.Println("  fw-clean --clean --fill 0 --dry-run      # Zero-fill, dry run")
		fmt.Println("")
		fmt.Println("  FaceDancer mode (no root on target needed):")
		fmt.Println("  fw-clean --facedancer --scan              # Scan via USB")
		fmt.Println("  fw-clean --facedancer --clean --dry-run   # Preview clean over USB")
		fmt.Println("  fw-clean --facedancer --clean --force     # Clean over USB")
		fmt.Println("  fw-clean --facedancer --fd-addr host:7342 # Custom proxy address")
		os.Exit(0)
	}

	printBanner()

	// FaceDancer MITM mode (standalone)
	if *flagFDMITM {
		fmt.Println("[*] FaceDancer MITM mode — use facedancer-proxy.py with --mitm")
		fmt.Println("    This mode captures USB traffic between host and device.")
		fmt.Println("    Run: python3 facedancer-proxy.py --mitm")
		return
	}

	var partitions []Partition

	// FaceDancer mode — no root needed on target
	var fdTransport *FDTransport
	if *flagFaceDancer {
		fmt.Println("[*] FaceDancer mode — connecting via USB...")
		fmt.Printf("[*] Proxy address: %s\n", *flagFDAddr)
		fmt.Println("[*] Make sure facedancer-proxy.py is running and target is in download mode")

		var err error
		partitions, fdTransport, err = DiscoverPartitionsViaFD(*flagFDAddr, *flagVerbose)
		if err != nil {
			fatal("FaceDancer discovery failed: %v", err)
		}
		defer fdTransport.Close()

		fmt.Printf("[+] Found %d partitions via FaceDancer (%s)\n", len(partitions), fdTransport.mode)
	} else {
		// Local mode — requires root
		if os.Getuid() != 0 {
			fatal("This tool requires root. Run with 'su' or 'adb root'.\n" +
				"    Or use --facedancer for USB-based access without root.")
		}
		var err error
		partitions, err = discoverPartitions()
		if err != nil {
			fatal("Failed to discover partitions: %v", err)
		}
	}

	if len(partitions) == 0 {
		fatal("No partitions found. Is this an Android/eMMC device?")
	}

	// Filter if specific partition requested
	if *flagPartition != "" {
		filtered := make([]Partition, 0)
		for _, p := range partitions {
			if strings.EqualFold(p.Name, *flagPartition) {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) == 0 {
			fatal("Partition '%s' not found. Available: %s", *flagPartition, partitionNames(partitions))
		}
		partitions = filtered
	}

	// Analyze each partition
	fmt.Printf("\n[*] Analyzing %d partition(s)...\n\n", len(partitions))
	for i := range partitions {
		if fdTransport != nil {
			AnalyzePartitionFD(fdTransport, &partitions[i])
		} else {
			analyzePartition(&partitions[i])
		}
	}

	// Print report
	printReport(partitions)

	// If cleaning, do it
	if *flagClean {
		cleanable := filterCleanable(partitions)
		if len(cleanable) == 0 {
			fmt.Println("\n[*] No cleanable partitions with slack space found.")
			return
		}

		if !*flagForce && !*flagDryRun {
			fmt.Printf("\n[!] WARNING: About to wipe slack space in %d partition(s).\n", len(cleanable))
			fmt.Println("[!] This can BRICK your device if something goes wrong.")
			fmt.Print("[?] Type 'YES' to proceed: ")
			var confirm string
			fmt.Scanln(&confirm)
			if confirm != "YES" {
				fmt.Println("[*] Aborted.")
				return
			}
		}

		// Backup first if requested
		if *flagBackup != "" {
			fmt.Printf("\n[*] Backing up to %s...\n", *flagBackup)
			if err := backupPartitions(cleanable, *flagBackup); err != nil {
				fatal("Backup failed: %v", err)
			}
			fmt.Println("[+] Backup complete.")
		}

		// Clean
		fmt.Println("\n[*] Cleaning slack space...")
		for i := range cleanable {
			if fdTransport != nil {
				fillVal := byte(*flagFillByte)
				if *flagFillByte == -1 {
					fillVal = 0 // random handled inside
				}
				if err := CleanPartitionFD(fdTransport, &cleanable[i], fillVal, *flagDryRun); err != nil {
					fmt.Printf("  [!] ERROR cleaning %s: %v\n", cleanable[i].Name, err)
				}
			} else {
				cleanPartition(&cleanable[i])
			}
		}

		// Final report
		fmt.Println("\n[+] Cleaning complete. Summary:")
		for _, p := range cleanable {
			status := "CLEANED"
			if *flagDryRun {
				status = "DRY-RUN"
			}
			fmt.Printf("    %-15s %s (%s wiped)\n", p.Name, status, humanBytes(p.SlackBytes))
		}
	}
}

// ---------------------------------------------------------------------------
// Partition Discovery
// ---------------------------------------------------------------------------

func discoverPartitions() ([]Partition, error) {
	// Strategy 1: Try /dev/block/by-name/ symlinks (most reliable on Android)
	partitions, err := discoverByName()
	if err == nil && len(partitions) > 0 {
		logVerbose("Discovered %d partitions via by-name symlinks", len(partitions))
		return partitions, nil
	}

	// Strategy 2: Try platform-specific paths (Fire TV)
	partitions, err = discoverPlatformLinks()
	if err == nil && len(partitions) > 0 {
		logVerbose("Discovered %d partitions via platform links", len(partitions))
		return partitions, nil
	}

	// Strategy 3: Parse GPT directly from block device
	dev := mmcBlockDev
	if *flagDeviceOverride != "" {
		dev = *flagDeviceOverride
	}
	partitions, err = discoverFromGPT(dev)
	if err == nil && len(partitions) > 0 {
		logVerbose("Discovered %d partitions via GPT parse", len(partitions))
		return partitions, nil
	}

	// Strategy 4: Parse /proc/partitions as fallback
	partitions, err = discoverFromProc()
	if err == nil && len(partitions) > 0 {
		logVerbose("Discovered %d partitions via /proc/partitions", len(partitions))
		return partitions, nil
	}

	return nil, fmt.Errorf("no partition discovery method succeeded")
}

func discoverByName() ([]Partition, error) {
	// Check multiple possible by-name paths
	paths := []string{
		"/dev/block/by-name",
		"/dev/block/bootdevice/by-name",
	}

	// Also search /dev/block/platform/*/by-name
	matches, _ := filepath.Glob("/dev/block/platform/*/by-name")
	paths = append(paths, matches...)
	matches, _ = filepath.Glob("/dev/block/platform/*/*/by-name")
	paths = append(paths, matches...)

	for _, dir := range paths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		var partitions []Partition
		for _, e := range entries {
			name := e.Name()
			linkPath := filepath.Join(dir, name)

			// Resolve symlink to actual device
			target, err := filepath.EvalSymlinks(linkPath)
			if err != nil {
				target = linkPath
			}

			// Get size
			size := getBlockDeviceSize(target)
			if size == 0 {
				continue
			}

			partitions = append(partitions, Partition{
				Name:        name,
				DevicePath:  target,
				SizeBytes:   uint64(size),
				IsHighValue: highValuePartitions[strings.ToLower(name)],
			})
		}

		if len(partitions) > 0 {
			sort.Slice(partitions, func(i, j int) bool {
				return partitions[i].Name < partitions[j].Name
			})
			return partitions, nil
		}
	}

	return nil, fmt.Errorf("no by-name directory found")
}

func discoverPlatformLinks() ([]Partition, error) {
	// Fire TV specific paths
	patterns := []string{
		"/dev/block/platform/*/by-num/*",
		"/dev/block/platform/*/*/by-num/*",
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}

		var partitions []Partition
		for _, path := range matches {
			name := filepath.Base(path)
			target, err := filepath.EvalSymlinks(path)
			if err != nil {
				target = path
			}
			size := getBlockDeviceSize(target)
			if size == 0 {
				continue
			}
			partitions = append(partitions, Partition{
				Name:        name,
				DevicePath:  target,
				SizeBytes:   uint64(size),
				IsHighValue: highValuePartitions[strings.ToLower(name)],
			})
		}
		if len(partitions) > 0 {
			return partitions, nil
		}
	}

	return nil, fmt.Errorf("no platform links found")
}

func discoverFromGPT(device string) ([]Partition, error) {
	f, err := os.Open(device)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %v", device, err)
	}
	defer f.Close()

	// Read GPT header at LBA 1
	headerBuf := make([]byte, sectorSize)
	if _, err := f.ReadAt(headerBuf, int64(sectorSize)); err != nil {
		return nil, fmt.Errorf("cannot read GPT header: %v", err)
	}

	var header GPTHeader
	if err := binary.Read(bytes.NewReader(headerBuf), binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("cannot parse GPT header: %v", err)
	}

	if string(header.Signature[:]) != gptHeaderSig {
		return nil, fmt.Errorf("invalid GPT signature")
	}

	logVerbose("GPT: %d entries starting at LBA %d", header.NumPartEntries, header.PartEntryStart)

	// Read partition entries
	entryTableSize := int64(header.NumPartEntries) * int64(header.PartEntrySize)
	entryBuf := make([]byte, entryTableSize)
	if _, err := f.ReadAt(entryBuf, int64(header.PartEntryStart)*int64(sectorSize)); err != nil {
		return nil, fmt.Errorf("cannot read partition entries: %v", err)
	}

	var partitions []Partition
	reader := bytes.NewReader(entryBuf)

	for i := uint32(0); i < header.NumPartEntries; i++ {
		var entry GPTEntry
		entryData := make([]byte, header.PartEntrySize)
		if _, err := reader.Read(entryData); err != nil {
			break
		}
		if err := binary.Read(bytes.NewReader(entryData), binary.LittleEndian, &entry); err != nil {
			continue
		}

		// Skip empty entries
		emptyGUID := [16]byte{}
		if entry.TypeGUID == emptyGUID {
			continue
		}

		name := decodeUTF16LE(entry.Name[:])
		if name == "" {
			name = fmt.Sprintf("part%d", i)
		}

		sizeBytes := (entry.LastLBA - entry.FirstLBA + 1) * uint64(sectorSize)
		devPath := fmt.Sprintf("%sp%d", device, i+1)

		// Try to find the actual device node
		possiblePaths := []string{
			devPath,
			fmt.Sprintf("/dev/block/mmcblk0p%d", i+1),
			filepath.Join("/dev/block/by-name", name),
		}
		actualPath := devPath
		for _, pp := range possiblePaths {
			if _, err := os.Stat(pp); err == nil {
				actualPath = pp
				break
			}
		}

		partitions = append(partitions, Partition{
			Name:        name,
			DevicePath:  actualPath,
			StartLBA:    entry.FirstLBA,
			EndLBA:      entry.LastLBA,
			SizeBytes:   sizeBytes,
			IsHighValue: highValuePartitions[strings.ToLower(name)],
		})
	}

	return partitions, nil
}

func discoverFromProc() ([]Partition, error) {
	data, err := os.ReadFile("/proc/partitions")
	if err != nil {
		return nil, err
	}

	var partitions []Partition
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 4 {
			continue
		}
		name := fields[3]
		if !strings.HasPrefix(name, "mmcblk0p") {
			continue
		}

		devPath := "/dev/block/" + name
		size := getBlockDeviceSize(devPath)
		if size == 0 {
			continue
		}

		// Try to determine partition name from by-name links
		displayName := name
		byNameDir := "/dev/block/by-name"
		if entries, err := os.ReadDir(byNameDir); err == nil {
			for _, e := range entries {
				link := filepath.Join(byNameDir, e.Name())
				target, _ := filepath.EvalSymlinks(link)
				if target == devPath {
					displayName = e.Name()
					break
				}
			}
		}

		partitions = append(partitions, Partition{
			Name:        displayName,
			DevicePath:  devPath,
			SizeBytes:   uint64(size),
			IsHighValue: highValuePartitions[strings.ToLower(displayName)],
		})
	}

	return partitions, nil
}

// ---------------------------------------------------------------------------
// Partition Analysis
// ---------------------------------------------------------------------------

func analyzePartition(p *Partition) {
	logVerbose("Analyzing: %s (%s, %s)", p.Name, p.DevicePath, humanBytes(int64(p.SizeBytes)))

	f, err := os.Open(p.DevicePath)
	if err != nil {
		logVerbose("  Cannot open: %v", err)
		return
	}
	defer f.Close()

	size := int64(p.SizeBytes)
	if size == 0 {
		size = getBlockDeviceSize(p.DevicePath)
		p.SizeBytes = uint64(size)
	}
	if size == 0 {
		logVerbose("  Cannot determine size")
		return
	}

	// Scan from the END backwards to find where padding stops and real data begins.
	// This is the key insight: we scan backwards because implants hide in the tail.
	chunkSize := int64(*flagChunkSize)
	dataEnd := size // Assume full if we can't find padding

	// Determine the fill byte by reading the very last chunk
	lastChunk := make([]byte, chunkSize)
	readPos := size - chunkSize
	if readPos < 0 {
		readPos = 0
	}
	n, err := f.ReadAt(lastChunk, readPos)
	if err != nil && err != io.EOF {
		logVerbose("  Cannot read tail: %v", err)
		return
	}
	lastChunk = lastChunk[:n]

	// Determine what "empty" looks like - usually 0xFF for NAND, sometimes 0x00
	fillByte := detectFillByte(lastChunk)
	p.FillByte = fillByte

	// If the tail isn't filled with the expected byte, there might be something there
	if !isFilledWith(lastChunk, fillByte) {
		// The very end has data - could be legit or an implant
		// Report it either way
		p.DataEndOff = size
		p.SlackBytes = 0
		p.SlackPercent = 0
		logVerbose("  Tail contains non-padding data (possible persistence)")
		return
	}

	// Binary search backward to find where real data ends
	// We scan in chunks from the end
	for offset := size - chunkSize; offset >= 0; offset -= chunkSize {
		readSize := chunkSize
		if offset < 0 {
			readSize += offset
			offset = 0
		}

		chunk := make([]byte, readSize)
		n, err := f.ReadAt(chunk, offset)
		if err != nil && err != io.EOF {
			break
		}
		chunk = chunk[:n]

		if !isFilledWith(chunk, fillByte) {
			// This chunk has real data - find exact boundary within chunk
			for i := len(chunk) - 1; i >= 0; i-- {
				if chunk[i] != fillByte {
					dataEnd = offset + int64(i) + 1
					goto found
				}
			}
		}
	}
	// If we get here, entire partition is fill bytes
	dataEnd = 0

found:
	p.DataEndOff = dataEnd
	p.SlackBytes = size - dataEnd
	if size > 0 {
		p.SlackPercent = float64(p.SlackBytes) / float64(size) * 100
	}

	logVerbose("  Data ends at offset 0x%X, slack: %s (%.1f%%)",
		dataEnd, humanBytes(p.SlackBytes), p.SlackPercent)
}

func detectFillByte(data []byte) byte {
	if len(data) == 0 {
		return 0xFF
	}

	// Count occurrences of 0xFF and 0x00
	ffCount := 0
	zeroCount := 0
	for _, b := range data {
		switch b {
		case 0xFF:
			ffCount++
		case 0x00:
			zeroCount++
		}
	}

	// NAND erased state is typically 0xFF
	if ffCount > len(data)*80/100 {
		return 0xFF
	}
	if zeroCount > len(data)*80/100 {
		return 0x00
	}

	// Default to 0xFF (NAND standard)
	return 0xFF
}

func isFilledWith(data []byte, b byte) bool {
	for _, v := range data {
		if v != b {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Cleaning
// ---------------------------------------------------------------------------

func filterCleanable(partitions []Partition) []Partition {
	var result []Partition
	for _, p := range partitions {
		if protectedPartitions[strings.ToLower(p.Name)] {
			continue
		}
		if p.SlackBytes <= 0 {
			continue
		}
		result = append(result, p)
	}
	return result
}

func cleanPartition(p *Partition) {
	fmt.Printf("  [*] Cleaning %-15s slack: %s starting at 0x%X\n",
		p.Name, humanBytes(p.SlackBytes), p.DataEndOff)

	if *flagDryRun {
		fmt.Printf("  [~] DRY RUN - would write %s of 0x%02X to %s\n",
			humanBytes(p.SlackBytes), getFillValue(), p.DevicePath)
		p.Cleaned = true
		return
	}

	f, err := os.OpenFile(p.DevicePath, os.O_WRONLY, 0)
	if err != nil {
		fmt.Printf("  [!] ERROR: Cannot open for writing: %v\n", err)
		return
	}
	defer f.Close()

	chunkSize := int64(*flagChunkSize)
	fillChunk := makeFillChunk(int(chunkSize))
	remaining := p.SlackBytes
	offset := p.DataEndOff
	written := int64(0)

	for remaining > 0 {
		writeSize := chunkSize
		if int64(writeSize) > remaining {
			writeSize = remaining
		}

		// For random fill, regenerate each chunk
		if *flagFillByte == -1 {
			rand.Read(fillChunk[:writeSize])
		}

		n, err := f.WriteAt(fillChunk[:writeSize], offset)
		if err != nil {
			fmt.Printf("  [!] ERROR at offset 0x%X: %v (wrote %s)\n",
				offset, err, humanBytes(written))
			return
		}

		offset += int64(n)
		remaining -= int64(n)
		written += int64(n)
	}

	// Sync to ensure writes hit the flash
	f.Sync()

	p.Cleaned = true
	fmt.Printf("  [+] %-15s CLEANED: %s written\n", p.Name, humanBytes(written))
}

func getFillValue() byte {
	if *flagFillByte == -1 {
		return 0 // placeholder for "random"
	}
	return byte(*flagFillByte)
}

func makeFillChunk(size int) []byte {
	chunk := make([]byte, size)
	if *flagFillByte == -1 {
		rand.Read(chunk)
	} else {
		b := byte(*flagFillByte)
		for i := range chunk {
			chunk[i] = b
		}
	}
	return chunk
}

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

func backupPartitions(partitions []Partition, backupDir string) error {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("cannot create backup dir: %v", err)
	}

	// Write a manifest
	manifest := fmt.Sprintf("# fw-clean backup manifest\n# Date: %s\n# Device: %s\n\n",
		time.Now().Format(time.RFC3339), mmcBlockDev)

	for _, p := range partitions {
		outPath := filepath.Join(backupDir, fmt.Sprintf("%s.img", p.Name))
		fmt.Printf("  [*] Backing up %-15s -> %s\n", p.Name, outPath)

		if err := copyPartition(p.DevicePath, outPath, int64(p.SizeBytes)); err != nil {
			return fmt.Errorf("backup of %s failed: %v", p.Name, err)
		}

		manifest += fmt.Sprintf("%s\t%s\t%d\t0x%X\n", p.Name, p.DevicePath, p.SizeBytes, p.DataEndOff)
		p.Backed = true
	}

	manifestPath := filepath.Join(backupDir, "manifest.txt")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
		return fmt.Errorf("cannot write manifest: %v", err)
	}

	return nil
}

func copyPartition(src, dst string, size int64) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if size > 0 {
		_, err = io.CopyN(out, in, size)
	} else {
		_, err = io.Copy(out, in)
	}

	return err
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

func printReport(partitions []Partition) {
	fmt.Println("┌─────────────────┬──────────────┬──────────────┬──────────┬──────┬──────────┐")
	fmt.Println("│ Partition       │ Size         │ Slack        │ Slack %  │ Fill │ Priority │")
	fmt.Println("├─────────────────┼──────────────┼──────────────┼──────────┼──────┼──────────┤")

	totalSlack := int64(0)
	for _, p := range partitions {
		prot := ""
		if protectedPartitions[strings.ToLower(p.Name)] {
			prot = "SKIP"
		} else if p.IsHighValue {
			prot = "HIGH ⚠"
		} else if p.SlackBytes > 0 {
			prot = "normal"
		}

		name := p.Name
		if len(name) > 15 {
			name = name[:15]
		}

		fmt.Printf("│ %-15s │ %12s │ %12s │ %6.1f%% │ 0x%02X │ %-8s │\n",
			name,
			humanBytes(int64(p.SizeBytes)),
			humanBytes(p.SlackBytes),
			p.SlackPercent,
			p.FillByte,
			prot,
		)
		if !protectedPartitions[strings.ToLower(p.Name)] {
			totalSlack += p.SlackBytes
		}
	}

	fmt.Println("└─────────────────┴──────────────┴──────────────┴──────────┴──────┴──────────┘")
	fmt.Printf("\n  Total cleanable slack: %s\n", humanBytes(totalSlack))
}

func printBanner() {
	fmt.Println(`
  ╔═══════════════════════════════════════════╗
  ║  fw-clean v1.0                            ║
  ║  Firmware Persistence Cleaner             ║
  ║  Target: Fire TV / Android eMMC           ║
  ║                                           ║
  ║  ⚠  BACKUP BEFORE CLEANING               ║
  ║  ⚠  CAN BRICK DEVICE IF MISUSED          ║
  ╚═══════════════════════════════════════════╝`)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func getBlockDeviceSize(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	// Try seeking to end
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return 0
	}

	return size
}

func decodeUTF16LE(b []byte) string {
	var runes []rune
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(binary.LittleEndian.Uint16(b[i:]))
		if r == 0 {
			break
		}
		if utf8.ValidRune(r) {
			runes = append(runes, r)
		}
	}
	return string(runes)
}

func humanBytes(b int64) string {
	if b < 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func partitionNames(parts []Partition) string {
	names := make([]string, len(parts))
	for i, p := range parts {
		names[i] = p.Name
	}
	return strings.Join(names, ", ")
}

func logVerbose(format string, args ...interface{}) {
	if *flagVerbose {
		fmt.Printf("[v] "+format+"\n", args...)
	}
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[!] FATAL: "+format+"\n", args...)
	os.Exit(1)
}
