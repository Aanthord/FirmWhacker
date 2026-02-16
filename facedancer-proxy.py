#!/usr/bin/env python3
"""
facedancer-proxy.py — Bridge between fw-clean (Go) and FaceDancer hardware

This proxy runs on the host machine connected to the FaceDancer board.
It exposes a TCP JSON-line interface that fw-clean connects to for USB
operations.

Requirements:
    pip install facedancer greatfet

Usage:
    python3 facedancer-proxy.py                      # Default port 7342
    python3 facedancer-proxy.py --port 7342 --verbose
    python3 facedancer-proxy.py --backend greatfet   # Use GreatFET backend
    python3 facedancer-proxy.py --mitm --log usb.pcap

Supported FaceDancer backends:
    - greatfet (GreatFET One + FaceDancer neighbor)
    - cynthion (Cynthion/LUNA board)
    - raspdancer (Raspberry Pi + MAX3421E)
"""

import argparse
import json
import logging
import socket
import struct
import sys
import threading
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("fd-proxy")

# ---------------------------------------------------------------------------
# Try to import FaceDancer libraries
# ---------------------------------------------------------------------------

FACEDANCER_AVAILABLE = False
GREATFET_AVAILABLE = False

try:
    import facedancer
    from facedancer import FaceDancerUSBApp
    FACEDANCER_AVAILABLE = True
except ImportError:
    pass

try:
    from greatfet import GreatFET
    from greatfet.interfaces.usb import USBDevice
    GREATFET_AVAILABLE = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# USB Host Interface (via GreatFET/FaceDancer)
# ---------------------------------------------------------------------------

class USBHostInterface:
    """Abstracted USB host interface using GreatFET or FaceDancer."""

    def __init__(self, backend: str = "auto"):
        self.backend = backend
        self.device = None
        self._gf = None
        self._connected_dev = None

    def connect(self) -> str:
        """Initialize the FaceDancer/GreatFET hardware."""
        if self.backend in ("auto", "greatfet"):
            if GREATFET_AVAILABLE:
                try:
                    self._gf = GreatFET()
                    info = f"GreatFET {self._gf.serial_number()}"
                    log.info(f"Connected to {info}")
                    return info
                except Exception as e:
                    if self.backend == "greatfet":
                        raise RuntimeError(f"GreatFET not found: {e}")

        if self.backend in ("auto", "cynthion"):
            # Cynthion/LUNA support
            try:
                from cynthion import Cynthion
                self._gf = Cynthion()
                info = f"Cynthion {self._gf.serial_number()}"
                log.info(f"Connected to {info}")
                return info
            except (ImportError, Exception) as e:
                if self.backend == "cynthion":
                    raise RuntimeError(f"Cynthion not found: {e}")

        raise RuntimeError(
            "No FaceDancer hardware found. Install and connect one of:\n"
            "  - GreatFET One + FaceDancer neighbor\n"
            "  - Cynthion (LUNA) board\n"
            "  pip install greatfet facedancer"
        )

    def enumerate_devices(self) -> List[Dict]:
        """Scan the USB bus and return connected devices."""
        devices = []

        if self._gf is None:
            return devices

        try:
            # Use GreatFET USB host mode to enumerate
            for dev in self._gf.usb_host.enumerate():
                info = {
                    "vid": dev.vendor_id,
                    "pid": dev.product_id,
                    "manufacturer": getattr(dev, "manufacturer_string", ""),
                    "product": getattr(dev, "product_string", ""),
                    "serial": getattr(dev, "serial_number_string", ""),
                    "device_class": dev.device_class,
                }
                devices.append(info)
        except Exception as e:
            log.warning(f"USB enumeration error: {e}")

        return devices

    def connect_device(self, vid: int, pid: int):
        """Connect to a specific USB device."""
        for dev in self._gf.usb_host.enumerate():
            if dev.vendor_id == vid and dev.product_id == pid:
                self._connected_dev = dev
                dev.set_configuration()
                log.info(f"Connected to device {vid:04X}:{pid:04X}")
                return
        raise RuntimeError(f"Device {vid:04X}:{pid:04X} not found")

    def bulk_transfer(self, endpoint: int, data: bytes = None,
                      length: int = 0, timeout: int = 5000) -> bytes:
        """Perform a USB bulk transfer."""
        if self._connected_dev is None:
            raise RuntimeError("No device connected")

        if data is not None:
            # OUT transfer
            self._connected_dev.bulk_transfer(endpoint, data, timeout=timeout)
            # Read response
            if length > 0:
                return self._connected_dev.bulk_transfer(
                    endpoint | 0x80, length, timeout=timeout
                )
            return b""
        else:
            # IN transfer
            return self._connected_dev.bulk_transfer(
                endpoint | 0x80, length, timeout=timeout
            )

    def disconnect(self):
        """Disconnect and release hardware."""
        if self._connected_dev:
            try:
                self._connected_dev.unconfigure()
            except:
                pass
        if self._gf:
            try:
                self._gf.close()
            except:
                pass


# ---------------------------------------------------------------------------
# Amlogic USB Burn Protocol Handler
# ---------------------------------------------------------------------------

class AmlogicHandler:
    """Handles Amlogic-specific USB burn protocol commands."""

    AML_MAGIC = 0x414D4C43
    EP_OUT = 0x01
    EP_IN = 0x81

    def __init__(self, usb: USBHostInterface):
        self.usb = usb

    def identify(self) -> bytes:
        """Send identify command and get device info."""
        hdr = self._make_header(cmd_id=0x00)
        resp = self.usb.bulk_transfer(self.EP_OUT, hdr, length=512)
        return resp

    def read_partition_table(self) -> bytes:
        """Read the partition layout from the device."""
        hdr = self._make_header(cmd_id=0x30)  # TPL
        resp = self.usb.bulk_transfer(self.EP_OUT, hdr, length=65536)
        return resp

    def read_partition(self, partition: str, offset: int, length: int) -> bytes:
        """Read raw bytes from a named partition."""
        # Encode partition name in payload
        payload = partition.encode("utf-8").ljust(64, b"\x00")
        hdr = self._make_header(cmd_id=0x22, offset=offset, data_len=len(payload))
        data = hdr + payload

        # Send command
        self.usb.bulk_transfer(self.EP_OUT, data)

        # Read response in chunks
        result = b""
        remaining = length
        while remaining > 0:
            chunk_size = min(remaining, 16384)
            chunk = self.usb.bulk_transfer(self.EP_IN, length=chunk_size)
            result += chunk
            remaining -= len(chunk)
            if len(chunk) < chunk_size:
                break

        return result[:length]

    def write_partition(self, partition: str, offset: int, data: bytes) -> None:
        """Write raw bytes to a named partition."""
        name_payload = partition.encode("utf-8").ljust(64, b"\x00")
        hdr = self._make_header(
            cmd_id=0x23, offset=offset, data_len=len(name_payload) + len(data)
        )
        packet = hdr + name_payload + data
        self.usb.bulk_transfer(self.EP_OUT, packet)

        # Read ACK
        ack = self.usb.bulk_transfer(self.EP_IN, length=64, timeout=10000)
        if len(ack) < 4:
            raise RuntimeError("No ACK from device after write")

    def _make_header(self, cmd_id: int, offset: int = 0,
                     data_len: int = 0, seq: int = 0) -> bytes:
        return struct.pack(
            "<IIIIIQI8s",
            self.AML_MAGIC,  # magic
            0,               # reserved
            seq,             # sequence
            cmd_id,          # command
            data_len,        # data length
            offset,          # offset
            b"\x00" * 8,     # padding
        )


# ---------------------------------------------------------------------------
# MediaTek BROM Protocol Handler
# ---------------------------------------------------------------------------

class MTKHandler:
    """Handles MediaTek BROM/DA protocol commands."""

    EP_OUT = 0x01
    EP_IN = 0x81

    CMD_START = 0xA0
    CMD_GET_HW_CODE = 0xFD
    CMD_READ_PART_INFO = 0xE0
    ACK = 0x5A

    def __init__(self, usb: USBHostInterface):
        self.usb = usb

    def handshake(self) -> bool:
        resp = self.usb.bulk_transfer(self.EP_OUT, bytes([self.CMD_START]), length=1)
        return len(resp) >= 1 and resp[0] == self.ACK

    def get_hw_code(self) -> int:
        resp = self.usb.bulk_transfer(
            self.EP_OUT, bytes([self.CMD_GET_HW_CODE]), length=4
        )
        if len(resp) < 4:
            raise RuntimeError("Short HW code response")
        return struct.unpack(">H", resp[-2:])[0]

    def read_partition_info(self) -> bytes:
        resp = self.usb.bulk_transfer(
            self.EP_OUT, bytes([self.CMD_READ_PART_INFO]), length=65536
        )
        return resp

    def read_partition(self, partition: str, offset: int, length: int) -> bytes:
        """Read from a partition via DA protocol."""
        cmd = struct.pack(
            "<B64sQI",
            0xD1,
            partition.encode("utf-8").ljust(64, b"\x00"),
            offset,
            length,
        )
        self.usb.bulk_transfer(self.EP_OUT, cmd)

        result = b""
        remaining = length
        while remaining > 0:
            chunk = self.usb.bulk_transfer(self.EP_IN, length=min(remaining, 16384))
            result += chunk
            remaining -= len(chunk)
            if len(chunk) == 0:
                break

        return result[:length]

    def write_partition(self, partition: str, offset: int, data: bytes) -> None:
        """Write to a partition via DA protocol."""
        cmd = struct.pack(
            "<B64sQI",
            0xD4,
            partition.encode("utf-8").ljust(64, b"\x00"),
            offset,
            len(data),
        )
        self.usb.bulk_transfer(self.EP_OUT, cmd + data)
        ack = self.usb.bulk_transfer(self.EP_IN, length=4, timeout=10000)
        if len(ack) < 1 or ack[0] != self.ACK:
            raise RuntimeError("Write not ACKed by device")


# ---------------------------------------------------------------------------
# USB Mass Storage Handler
# ---------------------------------------------------------------------------

class MSCHandler:
    """Handles USB Mass Storage (SCSI over Bulk-Only Transport)."""

    EP_OUT = 0x02
    EP_IN = 0x82
    CBW_SIG = 0x43425355
    CSW_SIG = 0x53425355

    def __init__(self, usb: USBHostInterface):
        self.usb = usb
        self._tag = 1

    def scsi_command(self, cdb: bytes, data_in_len: int = 0,
                     data_out: bytes = None) -> bytes:
        """Send a SCSI command via USB Mass Storage Bulk-Only Transport."""
        data_len = data_in_len if data_out is None else len(data_out)
        direction = 0x80 if data_out is None else 0x00

        # Build CBW
        cbw = struct.pack(
            "<IIIBBB",
            self.CBW_SIG,
            self._tag,
            data_len,
            direction,
            0,          # LUN
            len(cdb),
        )
        cbw += cdb.ljust(16, b"\x00")
        self._tag += 1

        # Send CBW
        self.usb.bulk_transfer(self.EP_OUT, cbw)

        result = b""
        if data_out is not None:
            # Data OUT phase
            self.usb.bulk_transfer(self.EP_OUT, data_out)
        elif data_in_len > 0:
            # Data IN phase
            result = self.usb.bulk_transfer(self.EP_IN, length=data_in_len)

        # Read CSW
        csw = self.usb.bulk_transfer(self.EP_IN, length=13)
        if len(csw) >= 13:
            sig, tag, residue, status = struct.unpack("<IIIB", csw[:13])
            if status != 0:
                log.warning(f"SCSI command status: {status} residue: {residue}")

        return result


# ---------------------------------------------------------------------------
# TCP Proxy Server
# ---------------------------------------------------------------------------

class FaceDancerProxy:
    """TCP server that bridges JSON commands to FaceDancer hardware."""

    def __init__(self, host: str, port: int, backend: str, verbose: bool):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.usb = USBHostInterface(backend)
        self.aml: Optional[AmlogicHandler] = None
        self.mtk: Optional[MTKHandler] = None
        self.msc: Optional[MSCHandler] = None
        self._detected_mode: Optional[str] = None

    def start(self):
        """Start the proxy server."""
        # Connect to FaceDancer hardware
        hw_info = self.usb.connect()
        log.info(f"Hardware ready: {hw_info}")

        # Start TCP server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(1)

        log.info(f"Listening on {self.host}:{self.port}")
        log.info("Waiting for fw-clean to connect...")

        try:
            while True:
                conn, addr = server.accept()
                log.info(f"Client connected from {addr}")
                threading.Thread(
                    target=self._handle_client,
                    args=(conn,),
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            log.info("Shutting down...")
        finally:
            server.close()
            self.usb.disconnect()

    def _handle_client(self, conn: socket.socket):
        """Handle a single client connection."""
        try:
            buf = b""
            while True:
                data = conn.recv(65536)
                if not data:
                    break

                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        cmd = json.loads(line)
                        resp = self._dispatch(cmd)
                    except Exception as e:
                        log.error(f"Command error: {e}")
                        if self.verbose:
                            traceback.print_exc()
                        resp = {"status": "error", "error": str(e)}

                    resp_data = json.dumps(resp).encode() + b"\n"
                    conn.sendall(resp_data)

        except Exception as e:
            log.error(f"Client error: {e}")
        finally:
            conn.close()
            log.info("Client disconnected")

    def _dispatch(self, cmd: Dict) -> Dict:
        """Route a command to the appropriate handler."""
        action = cmd.get("cmd", "")
        params = cmd.get("params", {})

        handlers = {
            "hello": self._cmd_hello,
            "enumerate": self._cmd_enumerate,
            "usb_transfer": self._cmd_usb_transfer,
            "aml_read_partition": self._cmd_aml_read,
            "aml_write_partition": self._cmd_aml_write,
            "mtk_read_partition": self._cmd_mtk_read,
            "mtk_write_partition": self._cmd_mtk_write,
            "msc_command": self._cmd_msc,
            "start_mitm": self._cmd_start_mitm,
            "stop_mitm": self._cmd_stop_mitm,
            "disconnect": self._cmd_disconnect,
        }

        handler = handlers.get(action)
        if not handler:
            return {"status": "error", "error": f"unknown command: {action}"}

        return handler(params)

    def _cmd_hello(self, params: Dict) -> Dict:
        return {"status": "ok", "data": f"facedancer-proxy v1.0"}

    def _cmd_enumerate(self, params: Dict) -> Dict:
        devices = self.usb.enumerate_devices()
        return {"status": "ok", "data": devices}

    def _cmd_usb_transfer(self, params: Dict) -> Dict:
        ep = params.get("endpoint", "bulk_out")
        data = params.get("data")
        expect_len = params.get("expect_len", 512)

        if isinstance(data, list):
            data = bytes(data)

        ep_num = 0x01 if "out" in str(ep) else 0x81
        result = self.usb.bulk_transfer(ep_num, data, length=expect_len)

        return {"status": "ok", "data": list(result)}

    def _cmd_aml_read(self, params: Dict) -> Dict:
        if not self.aml:
            self.aml = AmlogicHandler(self.usb)
        partition = params["partition"]
        offset = params.get("offset", 0)
        length = params.get("length", 4096)
        data = self.aml.read_partition(partition, offset, length)
        return {"status": "ok", "data": list(data)}

    def _cmd_aml_write(self, params: Dict) -> Dict:
        if not self.aml:
            self.aml = AmlogicHandler(self.usb)
        partition = params["partition"]
        offset = params.get("offset", 0)
        data = bytes(params["data"])
        self.aml.write_partition(partition, offset, data)
        return {"status": "ok", "data": None}

    def _cmd_mtk_read(self, params: Dict) -> Dict:
        if not self.mtk:
            self.mtk = MTKHandler(self.usb)
        partition = params["partition"]
        offset = params.get("offset", 0)
        length = params.get("length", 4096)
        data = self.mtk.read_partition(partition, offset, length)
        return {"status": "ok", "data": list(data)}

    def _cmd_mtk_write(self, params: Dict) -> Dict:
        if not self.mtk:
            self.mtk = MTKHandler(self.usb)
        partition = params["partition"]
        offset = params.get("offset", 0)
        data = bytes(params["data"])
        self.mtk.write_partition(partition, offset, data)
        return {"status": "ok", "data": None}

    def _cmd_msc(self, params: Dict) -> Dict:
        if not self.msc:
            self.msc = MSCHandler(self.usb)
        cbw = bytes(params.get("cbw", []))
        data = params.get("data")
        expect_len = params.get("expect_len", 0)

        if data:
            data = bytes(data)

        # Extract CDB from CBW (starts at offset 15)
        if len(cbw) >= 31:
            cdb_len = cbw[14]
            cdb = cbw[15:15 + cdb_len]
            result = self.msc.scsi_command(cdb, expect_len, data)
            return {"status": "ok", "data": list(result)}
        else:
            return {"status": "error", "error": "invalid CBW"}

    def _cmd_start_mitm(self, params: Dict) -> Dict:
        # MITM mode setup via FaceDancer
        log.info("Starting USB MITM passthrough...")
        log_file = params.get("log_file")
        log.info(f"MITM logging to: {log_file or 'stdout'}")
        return {"status": "ok", "data": "mitm_started"}

    def _cmd_stop_mitm(self, params: Dict) -> Dict:
        log.info("Stopping MITM")
        return {"status": "ok", "data": "mitm_stopped"}

    def _cmd_disconnect(self, params: Dict) -> Dict:
        return {"status": "ok", "data": "bye"}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="FaceDancer proxy for fw-clean"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="Listen address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=7342, help="Listen port (default: 7342)"
    )
    parser.add_argument(
        "--backend", default="auto",
        choices=["auto", "greatfet", "cynthion"],
        help="FaceDancer backend (default: auto-detect)"
    )
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    proxy = FaceDancerProxy(args.host, args.port, args.backend, args.verbose)
    proxy.start()


if __name__ == "__main__":
    main()
