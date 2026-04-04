/**
 * ledger.ts — Raw WebHID transport for Ledger Nano S+
 *
 * Implements the Ledger HID framing protocol directly (no npm dependency).
 * Channel 0x0101, tag 0x05, 64-byte reports.
 */

const LEDGER_VENDOR_ID = 0x2c97;
const CHANNEL = 0x0101;
const TAG = 0x05;
const PACKET_SIZE = 64;

export type LedgerDevice = {
  device: HIDDevice;
  close: () => Promise<void>;
};

export async function connectLedger(): Promise<LedgerDevice> {
  const devices = await navigator.hid.requestDevice({
    filters: [{ vendorId: LEDGER_VENDOR_ID }],
  });
  if (devices.length === 0) throw new Error("No Ledger device selected");
  const device = devices[0];
  if (!device.opened) await device.open();
  return {
    device,
    close: () => device.close(),
  };
}

export async function sendAPDU(
  ledger: LedgerDevice,
  apduHex: string
): Promise<{ data: Uint8Array; sw: number }> {
  const apdu = hexToBytes(apduHex);
  await sendFrames(ledger.device, apdu);
  const response = await recvFrames(ledger.device);
  const sw = (response[response.length - 2] << 8) | response[response.length - 1];
  const data = response.slice(0, response.length - 2);
  return { data, sw };
}

export async function sendChunkedAPDUs(
  ledger: LedgerDevice,
  apdus: string[],
  onProgress?: (i: number, total: number) => void
): Promise<{ data: Uint8Array; sw: number }> {
  for (let i = 0; i < apdus.length; i++) {
    onProgress?.(i, apdus.length);
    const { data, sw } = await sendAPDU(ledger, apdus[i]);
    if (i < apdus.length - 1) {
      if (sw !== 0x9000) throw new Error(`Chunk ${i} rejected: SW=0x${sw.toString(16)}`);
    } else {
      return { data, sw };
    }
  }
  throw new Error("No chunks to send");
}

/** Build chunked APDUs for PLONK/Groth16 payloads */
export function buildChunkedAPDUs(
  ins: number,
  payloadHex: string,
  chunkSize = 250
): string[] {
  const CLA = 0xe0;
  const data = hexToBytes(payloadHex);
  const apdus: string[] = [];
  let offset = 0, idx = 0;
  while (offset < data.length) {
    const remaining = data.length - offset;
    const isLast = remaining <= chunkSize;
    const len = isLast ? remaining : chunkSize;
    const chunk = data.slice(offset, offset + len);
    const p2 = isLast ? 0x00 : 0x80;
    const header = new Uint8Array([CLA, ins, idx, p2, len]);
    const full = new Uint8Array(header.length + chunk.length);
    full.set(header);
    full.set(chunk, header.length);
    apdus.push(bytesToHex(full));
    offset += len;
    idx++;
  }
  return apdus;
}

// ── HID framing ──────────────────────────────────────────────────

async function sendFrames(device: HIDDevice, apdu: Uint8Array) {
  let offset = 0;
  let seq = 0;
  while (offset < apdu.length) {
    const buf = new Uint8Array(PACKET_SIZE);
    buf[0] = CHANNEL >> 8;
    buf[1] = CHANNEL & 0xff;
    buf[2] = TAG;
    buf[3] = seq >> 8;
    buf[4] = seq & 0xff;
    let headerLen = 5;
    if (seq === 0) {
      buf[5] = apdu.length >> 8;
      buf[6] = apdu.length & 0xff;
      headerLen = 7;
    }
    const chunk = apdu.slice(offset, offset + PACKET_SIZE - headerLen);
    buf.set(chunk, headerLen);
    await device.sendReport(0, buf);
    offset += chunk.length;
    seq++;
  }
}

async function recvFrames(device: HIDDevice): Promise<Uint8Array> {
  let seq = 0;
  let totalLen = 0;
  const chunks: Uint8Array[] = [];
  let received = 0;

  while (true) {
    const report = await waitForReport(device);
    const view = new Uint8Array(report.buffer);
    let offset = 0;

    // Skip channel + tag
    offset += 3; // channel(2) + tag(1)
    const rseq = (view[offset] << 8) | view[offset + 1];
    offset += 2;

    if (rseq !== seq) throw new Error(`Sequence mismatch: expected ${seq}, got ${rseq}`);

    if (seq === 0) {
      totalLen = (view[offset] << 8) | view[offset + 1];
      offset += 2;
    }

    const dataLen = Math.min(view.length - offset, totalLen - received);
    chunks.push(view.slice(offset, offset + dataLen));
    received += dataLen;
    seq++;

    if (received >= totalLen) break;
  }

  const result = new Uint8Array(totalLen);
  let pos = 0;
  for (const chunk of chunks) {
    result.set(chunk, pos);
    pos += chunk.length;
  }
  return result;
}

function waitForReport(device: HIDDevice): Promise<DataView> {
  return new Promise((resolve) => {
    const handler = (e: HIDInputReportEvent) => {
      device.removeEventListener("inputreport", handler);
      resolve(e.data);
    };
    device.addEventListener("inputreport", handler);
  });
}

// ── Hex utils ────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const h = hex.replace(/\s/g, "");
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.substr(i * 2, 2), 16);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
