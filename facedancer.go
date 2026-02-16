// facedancer.go — FaceDancer USB transport for fw-clean
//
// Enables reading/writing eMMC partitions over USB using a FaceDancer board,
// without requiring root on the target device.
//
// Supported modes:
//   1. Amlogic USB Burn Mode — Fire TV Stick (1st/2nd/3rd gen), Fire TV Cube (Amlogic)
//   2. MediaTek BROM/Download Agent — Fire TV (MediaTek-based models)
//   3. Raw USB Mass Storage — When device exposes eMMC as USB MSC (fastboot, etc.)
//   4. FaceDancer MITM — Passthrough sniffing between host and device
//
// Hardware: Requires a FaceDancer (GreatFET-based) or compatible board.
// The FaceDancer runs a companion Python service that we talk to over a
// local TCP socket (facedancer-proxy). This keeps the Go side clean and
// leverages the existing FaceDancer Python ecosystem.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// FaceDancer Transport Configuration
// ---------------------------------------------------------------------------

const (
	fdProxyDefaultAddr = "127.0.0.1:7342" // facedancer-proxy default
	fdProxyTimeout     = 10 * time.Second
	fdMaxPacketSize    = 16384 // USB HS bulk max we'll use

	// Amlogic USB Burn Mode identifiers
	amlogicVID       = 0x1B8E
	amlogicBurnPID   = 0xC003 // Burn mode PID (varies by SoC)
	amlogicBurnPID2  = 0xC002
	amlogicWorldCup  = 0xC004 // S905X2 and later

	// MediaTek BROM identifiers
	mtkVID          = 0x0E8D
	mtkBromPID      = 0x0003
	mtkPreloaderPID = 0x2000

	// USB Mass Storage class
	usbMSCClass    = 0x08
	usbMSCSubclass = 0x06 // SCSI transparent
	usbMSCProtocol = 0x50 // Bulk-only
)

// FaceDancerMode determines how we interact with the target
type FaceDancerMode int

const (
	FDModeNone      FaceDancerMode = iota
	FDModeAmlogic                  // Amlogic USB Burn protocol
	FDModeMTK                      // MediaTek BROM/DA protocol
	FDModeMSC                      // USB Mass Storage (generic)
	FDModeMITM                     // Passthrough MITM sniffing
)

func (m FaceDancerMode) String() string {
	switch m {
	case FDModeAmlogic:
		return "Amlogic USB Burn"
	case FDModeMTK:
		return "MediaTek BROM"
	case FDModeMSC:
		return "USB Mass Storage"
	case FDModeMITM:
		return "MITM Passthrough"
	default:
		return "None"
	}
}

// ---------------------------------------------------------------------------
// FaceDancer Proxy Protocol
// ---------------------------------------------------------------------------
// We communicate with the Python facedancer-proxy over TCP using a simple
// JSON-line protocol. This avoids CGo/libusb dependencies and leverages
// the FaceDancer Python ecosystem directly.

// FDCommand is a command sent to the facedancer-proxy
type FDCommand struct {
	Cmd    string            `json:"cmd"`
	Params map[string]interface{} `json:"params,omitempty"`
}

// FDResponse is a response from the facedancer-proxy
type FDResponse struct {
	Status string          `json:"status"` // "ok", "error"
	Data   json.RawMessage `json:"data,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// FDDeviceInfo returned by device enumeration
type FDDeviceInfo struct {
	VID          uint16 `json:"vid"`
	PID          uint16 `json:"pid"`
	Manufacturer string `json:"manufacturer"`
	Product      string `json:"product"`
	Serial       string `json:"serial"`
	DeviceClass  uint8  `json:"device_class"`
}

// FDTransport handles communication with the FaceDancer proxy
type FDTransport struct {
	conn    net.Conn
	addr    string
	mode    FaceDancerMode
	device  *FDDeviceInfo
	verbose bool
}

// NewFDTransport creates a new FaceDancer transport
func NewFDTransport(addr string, verbose bool) *FDTransport {
	if addr == "" {
		addr = fdProxyDefaultAddr
	}
	return &FDTransport{
		addr:    addr,
		verbose: verbose,
	}
}

// Connect establishes connection to facedancer-proxy
func (fd *FDTransport) Connect() error {
	conn, err := net.DialTimeout("tcp", fd.addr, fdProxyTimeout)
	if err != nil {
		return fmt.Errorf("cannot connect to facedancer-proxy at %s: %v\n"+
			"Make sure facedancer-proxy is running:\n"+
			"  python3 facedancer-proxy.py", fd.addr, err)
	}
	fd.conn = conn

	// Handshake
	resp, err := fd.sendCommand("hello", nil)
	if err != nil {
		fd.conn.Close()
		return fmt.Errorf("proxy handshake failed: %v", err)
	}

	fd.logVerbose("Connected to facedancer-proxy: %s", string(resp.Data))
	return nil
}

// Close disconnects from the proxy
func (fd *FDTransport) Close() {
	if fd.conn != nil {
		fd.sendCommand("disconnect", nil)
		fd.conn.Close()
		fd.conn = nil
	}
}

// DetectDevice scans USB bus via FaceDancer and identifies the target
func (fd *FDTransport) DetectDevice() (*FDDeviceInfo, FaceDancerMode, error) {
	resp, err := fd.sendCommand("enumerate", nil)
	if err != nil {
		return nil, FDModeNone, fmt.Errorf("USB enumeration failed: %v", err)
	}

	var devices []FDDeviceInfo
	if err := json.Unmarshal(resp.Data, &devices); err != nil {
		return nil, FDModeNone, fmt.Errorf("cannot parse device list: %v", err)
	}

	if len(devices) == 0 {
		return nil, FDModeNone, fmt.Errorf("no USB devices found — is the Fire TV connected and in download mode?")
	}

	// Try to identify the device
	for i := range devices {
		dev := &devices[i]
		mode := identifyDevice(dev)
		if mode != FDModeNone {
			fd.device = dev
			fd.mode = mode
			fd.logVerbose("Identified: %s (VID=%04X PID=%04X) as %s",
				dev.Product, dev.VID, dev.PID, mode)
			return dev, mode, nil
		}
	}

	// Show what we found
	fmt.Println("[!] No recognized device found. Devices on bus:")
	for _, dev := range devices {
		fmt.Printf("    VID=%04X PID=%04X %s %s\n", dev.VID, dev.PID, dev.Manufacturer, dev.Product)
	}

	return nil, FDModeNone, fmt.Errorf("no supported device found")
}

func identifyDevice(dev *FDDeviceInfo) FaceDancerMode {
	// Amlogic USB Burn mode
	if dev.VID == amlogicVID {
		switch dev.PID {
		case amlogicBurnPID, amlogicBurnPID2, amlogicWorldCup:
			return FDModeAmlogic
		}
	}

	// MediaTek BROM
	if dev.VID == mtkVID {
		switch dev.PID {
		case mtkBromPID, mtkPreloaderPID:
			return FDModeMTK
		}
	}

	// Generic USB Mass Storage
	if dev.DeviceClass == usbMSCClass {
		return FDModeMSC
	}

	return FDModeNone
}

// ---------------------------------------------------------------------------
// Amlogic USB Burn Protocol
// ---------------------------------------------------------------------------
// Amlogic SoCs (S905X, S905X2, S922X used in Fire TVs) have a USB burn mode
// that allows raw eMMC access. The protocol uses bulk transfers with a
// custom command structure.

const (
	amlCmdIdentify   = 0x00
	amlCmdReadMedia  = 0x22
	amlCmdWriteMedia = 0x23
	amlCmdReadMem    = 0x52
	amlCmdWriteMem   = 0x53
	amlCmdRunInAddr  = 0x05
	amlCmdTPL        = 0x30 // Transfer Partition Layout
)

// AmlogicHeader is the USB command header for Amlogic burn protocol
type AmlogicHeader struct {
	Magic     uint32 // 0x414D4C43 "AMLC"
	Reserved  uint32
	Sequence  uint32
	CmdID     uint32
	DataLen   uint32
	Offset    uint64
	Padding   [8]byte
}

const amlMagic = 0x414D4C43

// AmlogicReadPartitionTable reads the partition table via Amlogic burn protocol
func (fd *FDTransport) AmlogicReadPartitionTable() ([]Partition, error) {
	// Step 1: Identify/handshake with the SoC
	fd.logVerbose("Amlogic: Sending identify command")
	identResp, err := fd.amlCommand(amlCmdIdentify, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("amlogic identify failed: %v", err)
	}
	fd.logVerbose("Amlogic: Device identified: %s", string(identResp))

	// Step 2: Request partition table via TPL command
	fd.logVerbose("Amlogic: Reading partition layout")
	tplData, err := fd.amlCommand(amlCmdTPL, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("amlogic TPL read failed: %v", err)
	}

	return fd.parseAmlogicPartitionTable(tplData)
}

// AmlogicReadPartition reads raw data from a partition
func (fd *FDTransport) AmlogicReadPartition(partName string, offset, length int64) ([]byte, error) {
	params := map[string]interface{}{
		"partition": partName,
		"offset":    offset,
		"length":    length,
	}

	resp, err := fd.sendCommand("aml_read_partition", params)
	if err != nil {
		return nil, err
	}

	var data []byte
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return nil, fmt.Errorf("cannot decode partition data: %v", err)
	}

	return data, nil
}

// AmlogicWritePartition writes raw data to a partition at given offset
func (fd *FDTransport) AmlogicWritePartition(partName string, offset int64, data []byte) error {
	params := map[string]interface{}{
		"partition": partName,
		"offset":    offset,
		"length":    len(data),
		"data":      data,
	}

	_, err := fd.sendCommand("aml_write_partition", params)
	return err
}

func (fd *FDTransport) amlCommand(cmdID uint32, offset uint64, payload []byte) ([]byte, error) {
	hdr := AmlogicHeader{
		Magic:   amlMagic,
		CmdID:   cmdID,
		DataLen: uint32(len(payload)),
		Offset:  offset,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, &hdr)
	if payload != nil {
		buf.Write(payload)
	}

	params := map[string]interface{}{
		"endpoint": "bulk_out",
		"data":     buf.Bytes(),
	}

	resp, err := fd.sendCommand("usb_transfer", params)
	if err != nil {
		return nil, err
	}

	var respData []byte
	if err := json.Unmarshal(resp.Data, &respData); err != nil {
		return nil, err
	}

	return respData, nil
}

func (fd *FDTransport) parseAmlogicPartitionTable(data []byte) ([]Partition, error) {
	// Amlogic partition table format varies by SoC generation.
	// Common format: lines of "name:offset:size" or structured binary.
	// We handle both.

	partitions := make([]Partition, 0)

	// Try text format first (common in older burn tools)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		var offset, size uint64
		fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &offset)
		fmt.Sscanf(strings.TrimSpace(parts[2]), "%d", &size)

		if name != "" && size > 0 {
			partitions = append(partitions, Partition{
				Name:        name,
				DevicePath:  fmt.Sprintf("facedancer://amlogic/%s", name),
				StartLBA:    offset / uint64(sectorSize),
				EndLBA:      (offset + size) / uint64(sectorSize),
				SizeBytes:   size,
				IsHighValue: highValuePartitions[strings.ToLower(name)],
			})
		}
	}

	if len(partitions) > 0 {
		return partitions, nil
	}

	// Try binary format — Amlogic uses a packed struct table
	return fd.parseAmlogicBinaryPartTable(data)
}

func (fd *FDTransport) parseAmlogicBinaryPartTable(data []byte) ([]Partition, error) {
	// Binary partition table header:
	// 4 bytes: magic "MPT\x00"
	// 4 bytes: version
	// 4 bytes: num_entries
	// Followed by entries of:
	//   64 bytes: name (null-terminated)
	//   8 bytes: offset
	//   8 bytes: size
	//   4 bytes: flags
	//   4 bytes: padding

	if len(data) < 12 {
		return nil, fmt.Errorf("partition table too small")
	}

	magic := string(data[:3])
	if magic != "MPT" {
		return nil, fmt.Errorf("unrecognized partition table format (magic: %q)", magic)
	}

	numEntries := binary.LittleEndian.Uint32(data[8:12])
	entryStart := 12
	entrySize := 88 // 64 + 8 + 8 + 4 + 4

	var partitions []Partition
	for i := uint32(0); i < numEntries; i++ {
		off := entryStart + int(i)*entrySize
		if off+entrySize > len(data) {
			break
		}

		entry := data[off : off+entrySize]
		name := strings.TrimRight(string(entry[:64]), "\x00")
		offset := binary.LittleEndian.Uint64(entry[64:72])
		size := binary.LittleEndian.Uint64(entry[72:80])

		if name != "" && size > 0 {
			partitions = append(partitions, Partition{
				Name:        name,
				DevicePath:  fmt.Sprintf("facedancer://amlogic/%s", name),
				StartLBA:    offset / uint64(sectorSize),
				EndLBA:      (offset + size) / uint64(sectorSize),
				SizeBytes:   size,
				IsHighValue: highValuePartitions[strings.ToLower(name)],
			})
		}
	}

	return partitions, nil
}

// ---------------------------------------------------------------------------
// MediaTek BROM/DA Protocol
// ---------------------------------------------------------------------------
// MediaTek-based Fire TVs use a boot ROM (BROM) protocol for USB download.
// The protocol requires loading a Download Agent (DA) first, then the DA
// provides read/write access to eMMC.

const (
	mtkCmdStartCmd     = 0xA0
	mtkCmdGetHWCode    = 0xFD
	mtkCmdGetHWSWVer   = 0xFC
	mtkCmdSendDA       = 0xD7
	mtkCmdJumpDA       = 0xD5
	mtkCmdReadPartInfo = 0xE0
	mtkCmdRead16       = 0xD1
	mtkCmdWrite16      = 0xD4
	mtkCmdFormatEMMC   = 0xE8
	mtkACK             = 0x5A
	mtkNACK            = 0xA5
)

// MTKReadPartitionTable reads the partition layout via MediaTek DA protocol
func (fd *FDTransport) MTKReadPartitionTable() ([]Partition, error) {
	// Step 1: Handshake with BROM
	fd.logVerbose("MTK: BROM handshake")
	if err := fd.mtkHandshake(); err != nil {
		return nil, fmt.Errorf("MTK handshake failed: %v", err)
	}

	// Step 2: Get hardware code to identify exact SoC
	hwCode, err := fd.mtkGetHWCode()
	if err != nil {
		return nil, fmt.Errorf("MTK get HW code failed: %v", err)
	}
	fd.logVerbose("MTK: HW Code = 0x%04X", hwCode)

	// Step 3: Read partition info
	// This requires either a pre-loaded DA or direct BROM partition read
	partData, err := fd.mtkReadPartInfo()
	if err != nil {
		return nil, fmt.Errorf("MTK partition read failed: %v", err)
	}

	return fd.parseMTKPartitionTable(partData)
}

func (fd *FDTransport) mtkHandshake() error {
	// MTK BROM handshake: send 0xA0, expect 0x5A back
	params := map[string]interface{}{
		"endpoint": "bulk_out",
		"data":     []byte{mtkCmdStartCmd},
	}

	resp, err := fd.sendCommand("usb_transfer", params)
	if err != nil {
		return err
	}

	var respData []byte
	json.Unmarshal(resp.Data, &respData)

	if len(respData) < 1 || respData[0] != mtkACK {
		return fmt.Errorf("BROM did not ACK (got 0x%X)", respData)
	}

	return nil
}

func (fd *FDTransport) mtkGetHWCode() (uint16, error) {
	params := map[string]interface{}{
		"endpoint": "bulk_out",
		"data":     []byte{mtkCmdGetHWCode},
	}

	resp, err := fd.sendCommand("usb_transfer", params)
	if err != nil {
		return 0, err
	}

	var respData []byte
	json.Unmarshal(resp.Data, &respData)

	if len(respData) < 4 {
		return 0, fmt.Errorf("short HW code response")
	}

	// Response: ACK(1) + Status(2) + HWCode(2)
	hwCode := binary.BigEndian.Uint16(respData[len(respData)-2:])
	return hwCode, nil
}

func (fd *FDTransport) mtkReadPartInfo() ([]byte, error) {
	params := map[string]interface{}{
		"endpoint": "bulk_out",
		"data":     []byte{mtkCmdReadPartInfo},
	}

	resp, err := fd.sendCommand("usb_transfer", params)
	if err != nil {
		return nil, err
	}

	var data []byte
	json.Unmarshal(resp.Data, &data)
	return data, nil
}

func (fd *FDTransport) parseMTKPartitionTable(data []byte) ([]Partition, error) {
	// MTK partition info format:
	// 4 bytes: count
	// For each partition:
	//   64 bytes: name
	//   8 bytes: start sector
	//   8 bytes: num sectors

	if len(data) < 4 {
		return nil, fmt.Errorf("partition info too small")
	}

	count := binary.LittleEndian.Uint32(data[:4])
	entrySize := 80 // 64 + 8 + 8

	var partitions []Partition
	for i := uint32(0); i < count; i++ {
		off := 4 + int(i)*entrySize
		if off+entrySize > len(data) {
			break
		}

		entry := data[off : off+entrySize]
		name := strings.TrimRight(string(entry[:64]), "\x00")
		startSector := binary.LittleEndian.Uint64(entry[64:72])
		numSectors := binary.LittleEndian.Uint64(entry[72:80])
		sizeBytes := numSectors * uint64(sectorSize)

		if name != "" && numSectors > 0 {
			partitions = append(partitions, Partition{
				Name:        name,
				DevicePath:  fmt.Sprintf("facedancer://mtk/%s", name),
				StartLBA:    startSector,
				EndLBA:      startSector + numSectors - 1,
				SizeBytes:   sizeBytes,
				IsHighValue: highValuePartitions[strings.ToLower(name)],
			})
		}
	}

	return partitions, nil
}

// ---------------------------------------------------------------------------
// USB Mass Storage (SCSI over Bulk) — Generic mode
// ---------------------------------------------------------------------------

// MSCReadCapacity gets the total size of the exposed storage
func (fd *FDTransport) MSCReadCapacity() (uint64, uint32, error) {
	// SCSI READ CAPACITY(10)
	cbd := make([]byte, 10)
	cbd[0] = 0x25 // READ CAPACITY(10)

	resp, err := fd.scsiCommand(cbd, 8)
	if err != nil {
		return 0, 0, err
	}

	if len(resp) < 8 {
		return 0, 0, fmt.Errorf("short READ CAPACITY response")
	}

	lastLBA := binary.BigEndian.Uint32(resp[0:4])
	blockSize := binary.BigEndian.Uint32(resp[4:8])

	totalSize := uint64(lastLBA+1) * uint64(blockSize)
	return totalSize, blockSize, nil
}

// MSCRead reads blocks from the storage device
func (fd *FDTransport) MSCRead(lba uint64, blocks uint32) ([]byte, error) {
	// SCSI READ(10)
	cbd := make([]byte, 10)
	cbd[0] = 0x28 // READ(10)
	binary.BigEndian.PutUint32(cbd[2:6], uint32(lba))
	binary.BigEndian.PutUint16(cbd[7:9], uint16(blocks))

	return fd.scsiCommand(cbd, int(blocks)*512)
}

// MSCWrite writes blocks to the storage device
func (fd *FDTransport) MSCWrite(lba uint64, data []byte) error {
	blocks := (len(data) + 511) / 512

	// SCSI WRITE(10)
	cbd := make([]byte, 10)
	cbd[0] = 0x2A // WRITE(10)
	binary.BigEndian.PutUint32(cbd[2:6], uint32(lba))
	binary.BigEndian.PutUint16(cbd[7:9], uint16(blocks))

	params := map[string]interface{}{
		"endpoint": "bulk_out",
		"cbw":      makeCBW(cbd, len(data), false),
		"data":     data,
	}

	_, err := fd.sendCommand("msc_command", params)
	return err
}

func (fd *FDTransport) scsiCommand(cdb []byte, expectLen int) ([]byte, error) {
	params := map[string]interface{}{
		"endpoint":    "bulk_out",
		"cbw":         makeCBW(cdb, expectLen, true),
		"expect_len":  expectLen,
	}

	resp, err := fd.sendCommand("msc_command", params)
	if err != nil {
		return nil, err
	}

	var data []byte
	json.Unmarshal(resp.Data, &data)
	return data, nil
}

// CBW - Command Block Wrapper for USB Mass Storage Bulk-Only Transport
func makeCBW(cdb []byte, dataLen int, dataIn bool) []byte {
	cbw := make([]byte, 31)
	// Signature: "USBC"
	binary.LittleEndian.PutUint32(cbw[0:4], 0x43425355)
	// Tag
	binary.LittleEndian.PutUint32(cbw[4:8], 0x00000001)
	// Transfer length
	binary.LittleEndian.PutUint32(cbw[8:12], uint32(dataLen))
	// Flags: bit 7 = direction (1=in, 0=out)
	if dataIn {
		cbw[12] = 0x80
	}
	// LUN
	cbw[13] = 0
	// CDB length
	cbw[14] = byte(len(cdb))
	// CDB
	copy(cbw[15:], cdb)

	return cbw
}

// ---------------------------------------------------------------------------
// MITM / Passthrough Mode
// ---------------------------------------------------------------------------

// FDMITMConfig configures the MITM passthrough
type FDMITMConfig struct {
	LogFile      string
	FilterVID    uint16
	FilterPID    uint16
	InterceptFn  func(endpoint string, data []byte) []byte // nil = passthrough
	LogTransfers bool
}

// StartMITM begins USB passthrough with logging/interception
func (fd *FDTransport) StartMITM(cfg FDMITMConfig) error {
	params := map[string]interface{}{
		"mode":       "mitm",
		"log":        cfg.LogTransfers,
		"filter_vid": cfg.FilterVID,
		"filter_pid": cfg.FilterPID,
	}

	if cfg.LogFile != "" {
		params["log_file"] = cfg.LogFile
	}

	_, err := fd.sendCommand("start_mitm", params)
	return err
}

// StopMITM stops the passthrough
func (fd *FDTransport) StopMITM() error {
	_, err := fd.sendCommand("stop_mitm", nil)
	return err
}

// ---------------------------------------------------------------------------
// Unified Read/Write Interface (used by fw-clean core)
// ---------------------------------------------------------------------------

// FDPartitionReader implements io.ReaderAt for a FaceDancer-accessed partition
type FDPartitionReader struct {
	fd        *FDTransport
	partition string
	size      int64
}

func (r *FDPartitionReader) ReadAt(p []byte, off int64) (int, error) {
	switch r.fd.mode {
	case FDModeAmlogic:
		data, err := r.fd.AmlogicReadPartition(r.partition, off, int64(len(p)))
		if err != nil {
			return 0, err
		}
		n := copy(p, data)
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil

	case FDModeMTK:
		// Similar pattern via MTK DA read commands
		params := map[string]interface{}{
			"partition": r.partition,
			"offset":    off,
			"length":    len(p),
		}
		resp, err := r.fd.sendCommand("mtk_read_partition", params)
		if err != nil {
			return 0, err
		}
		var data []byte
		json.Unmarshal(resp.Data, &data)
		n := copy(p, data)
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil

	case FDModeMSC:
		// Calculate LBA from byte offset
		lba := uint64(off) / 512
		blocks := uint32((len(p) + 511) / 512)
		data, err := r.fd.MSCRead(lba, blocks)
		if err != nil {
			return 0, err
		}
		// Trim to actual requested range
		start := int(off % 512)
		n := copy(p, data[start:])
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil

	default:
		return 0, fmt.Errorf("unsupported mode for read: %s", r.fd.mode)
	}
}

// FDPartitionWriter implements writing to a FaceDancer-accessed partition
type FDPartitionWriter struct {
	fd        *FDTransport
	partition string
	size      int64
}

func (w *FDPartitionWriter) WriteAt(p []byte, off int64) (int, error) {
	switch w.fd.mode {
	case FDModeAmlogic:
		err := w.fd.AmlogicWritePartition(w.partition, off, p)
		if err != nil {
			return 0, err
		}
		return len(p), nil

	case FDModeMTK:
		params := map[string]interface{}{
			"partition": w.partition,
			"offset":    off,
			"data":      p,
		}
		_, err := w.fd.sendCommand("mtk_write_partition", params)
		if err != nil {
			return 0, err
		}
		return len(p), nil

	case FDModeMSC:
		// Align to sector boundaries
		startLBA := uint64(off) / 512
		if off%512 != 0 {
			// Need read-modify-write for unaligned access
			alignedOff := int64(startLBA) * 512
			existing, err := w.fd.MSCRead(startLBA, 1)
			if err != nil {
				return 0, fmt.Errorf("RMW read failed: %v", err)
			}
			copy(existing[off-alignedOff:], p)
			if err := w.fd.MSCWrite(startLBA, existing); err != nil {
				return 0, err
			}
		} else {
			if err := w.fd.MSCWrite(startLBA, p); err != nil {
				return 0, err
			}
		}
		return len(p), nil

	default:
		return 0, fmt.Errorf("unsupported mode for write: %s", w.fd.mode)
	}
}

// ---------------------------------------------------------------------------
// Proxy Communication
// ---------------------------------------------------------------------------

func (fd *FDTransport) sendCommand(cmd string, params map[string]interface{}) (*FDResponse, error) {
	if fd.conn == nil {
		return nil, fmt.Errorf("not connected to facedancer-proxy")
	}

	command := FDCommand{
		Cmd:    cmd,
		Params: params,
	}

	// Send JSON line
	data, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')

	fd.conn.SetWriteDeadline(time.Now().Add(fdProxyTimeout))
	if _, err := fd.conn.Write(data); err != nil {
		return nil, fmt.Errorf("write to proxy failed: %v", err)
	}

	// Read response
	fd.conn.SetReadDeadline(time.Now().Add(fdProxyTimeout * 3)) // reads can be slow
	buf := make([]byte, 0, 65536)
	tmp := make([]byte, 4096)
	for {
		n, err := fd.conn.Read(tmp)
		if err != nil {
			return nil, fmt.Errorf("read from proxy failed: %v", err)
		}
		buf = append(buf, tmp[:n]...)
		if bytes.Contains(buf, []byte("\n")) {
			break
		}
	}

	var resp FDResponse
	if err := json.Unmarshal(bytes.TrimSpace(buf), &resp); err != nil {
		return nil, fmt.Errorf("cannot parse proxy response: %v", err)
	}

	if resp.Status == "error" {
		return nil, fmt.Errorf("proxy error: %s", resp.Error)
	}

	return &resp, nil
}

func (fd *FDTransport) logVerbose(format string, args ...interface{}) {
	if fd.verbose {
		fmt.Printf("[fd] "+format+"\n", args...)
	}
}

// ---------------------------------------------------------------------------
// Helper: Discover partitions via FaceDancer
// ---------------------------------------------------------------------------

// DiscoverPartitionsViaFD discovers partitions through FaceDancer USB connection
func DiscoverPartitionsViaFD(addr string, verbose bool) ([]Partition, *FDTransport, error) {
	fd := NewFDTransport(addr, verbose)

	if err := fd.Connect(); err != nil {
		return nil, nil, err
	}

	_, mode, err := fd.DetectDevice()
	if err != nil {
		fd.Close()
		return nil, nil, err
	}

	var partitions []Partition

	switch mode {
	case FDModeAmlogic:
		partitions, err = fd.AmlogicReadPartitionTable()
	case FDModeMTK:
		partitions, err = fd.MTKReadPartitionTable()
	case FDModeMSC:
		// For MSC, we read GPT from the exposed storage
		partitions, err = discoverFromMSC(fd)
	default:
		err = fmt.Errorf("mode %s does not support partition discovery", mode)
	}

	if err != nil {
		fd.Close()
		return nil, nil, err
	}

	return partitions, fd, nil
}

// discoverFromMSC reads GPT from USB Mass Storage device
func discoverFromMSC(fd *FDTransport) ([]Partition, error) {
	// Read GPT header at LBA 1
	headerData, err := fd.MSCRead(1, 1)
	if err != nil {
		return nil, fmt.Errorf("cannot read GPT header: %v", err)
	}

	var header GPTHeader
	if err := binary.Read(bytes.NewReader(headerData), binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("cannot parse GPT header: %v", err)
	}

	if string(header.Signature[:]) != gptHeaderSig {
		return nil, fmt.Errorf("no valid GPT found on MSC device")
	}

	// Read partition entries
	numSectors := (uint32(header.NumPartEntries)*header.PartEntrySize + 511) / 512
	entryData, err := fd.MSCRead(header.PartEntryStart, numSectors)
	if err != nil {
		return nil, fmt.Errorf("cannot read GPT entries: %v", err)
	}

	var partitions []Partition
	reader := bytes.NewReader(entryData)

	for i := uint32(0); i < header.NumPartEntries; i++ {
		entryBuf := make([]byte, header.PartEntrySize)
		if _, err := reader.Read(entryBuf); err != nil {
			break
		}

		var entry GPTEntry
		if err := binary.Read(bytes.NewReader(entryBuf), binary.LittleEndian, &entry); err != nil {
			continue
		}

		emptyGUID := [16]byte{}
		if entry.TypeGUID == emptyGUID {
			continue
		}

		name := decodeUTF16LE(entry.Name[:])
		if name == "" {
			name = fmt.Sprintf("part%d", i)
		}

		sizeBytes := (entry.LastLBA - entry.FirstLBA + 1) * uint64(sectorSize)

		partitions = append(partitions, Partition{
			Name:        name,
			DevicePath:  fmt.Sprintf("facedancer://msc/%s", name),
			StartLBA:    entry.FirstLBA,
			EndLBA:      entry.LastLBA,
			SizeBytes:   sizeBytes,
			IsHighValue: highValuePartitions[strings.ToLower(name)],
		})
	}

	return partitions, nil
}

// ---------------------------------------------------------------------------
// FaceDancer-aware analysis and cleaning
// ---------------------------------------------------------------------------

// AnalyzePartitionFD analyzes a partition's slack space via FaceDancer
func AnalyzePartitionFD(fd *FDTransport, p *Partition) {
	reader := &FDPartitionReader{
		fd:        fd,
		partition: p.Name,
		size:      int64(p.SizeBytes),
	}

	size := int64(p.SizeBytes)
	chunkSize := int64(4096)

	// Read last chunk to determine fill byte
	lastChunk := make([]byte, chunkSize)
	readPos := size - chunkSize
	if readPos < 0 {
		readPos = 0
	}
	n, err := reader.ReadAt(lastChunk, readPos)
	if err != nil && err != io.EOF {
		logVerbose("  FD: Cannot read tail of %s: %v", p.Name, err)
		return
	}
	lastChunk = lastChunk[:n]

	fillByte := detectFillByte(lastChunk)
	p.FillByte = fillByte

	if !isFilledWith(lastChunk, fillByte) {
		p.DataEndOff = size
		p.SlackBytes = 0
		return
	}

	// Scan backward
	dataEnd := size
	for offset := size - chunkSize; offset >= 0; offset -= chunkSize {
		readSize := chunkSize
		if offset < 0 {
			readSize += offset
			offset = 0
		}

		chunk := make([]byte, readSize)
		n, err := reader.ReadAt(chunk, offset)
		if err != nil && err != io.EOF {
			break
		}
		chunk = chunk[:n]

		if !isFilledWith(chunk, fillByte) {
			for i := len(chunk) - 1; i >= 0; i-- {
				if chunk[i] != fillByte {
					dataEnd = offset + int64(i) + 1
					goto found
				}
			}
		}
	}
	dataEnd = 0

found:
	p.DataEndOff = dataEnd
	p.SlackBytes = size - dataEnd
	if size > 0 {
		p.SlackPercent = float64(p.SlackBytes) / float64(size) * 100
	}
}

// CleanPartitionFD wipes slack space via FaceDancer
func CleanPartitionFD(fd *FDTransport, p *Partition, fillByte byte, dryRun bool) error {
	if dryRun {
		fmt.Printf("  [~] DRY RUN: would write %s of 0x%02X to %s via FaceDancer\n",
			humanBytes(p.SlackBytes), fillByte, p.Name)
		return nil
	}

	writer := &FDPartitionWriter{
		fd:        fd,
		partition: p.Name,
		size:      int64(p.SizeBytes),
	}

	chunkSize := 4096
	fillChunk := make([]byte, chunkSize)
	for i := range fillChunk {
		fillChunk[i] = fillByte
	}

	remaining := p.SlackBytes
	offset := p.DataEndOff
	written := int64(0)

	for remaining > 0 {
		writeSize := int64(chunkSize)
		if writeSize > remaining {
			writeSize = remaining
		}

		if _, err := writer.WriteAt(fillChunk[:writeSize], offset); err != nil {
			return fmt.Errorf("write error at 0x%X: %v (wrote %s)", offset, err, humanBytes(written))
		}

		offset += writeSize
		remaining -= writeSize
		written += writeSize
	}

	p.Cleaned = true
	return nil
}
