// WebHID API type declarations
interface HIDDevice {
  opened: boolean;
  vendorId: number;
  productId: number;
  productName: string;
  open(): Promise<void>;
  close(): Promise<void>;
  sendReport(reportId: number, data: BufferSource): Promise<void>;
  addEventListener(type: "inputreport", listener: (e: HIDInputReportEvent) => void): void;
  removeEventListener(type: "inputreport", listener: (e: HIDInputReportEvent) => void): void;
}

interface HIDInputReportEvent extends Event {
  device: HIDDevice;
  reportId: number;
  data: DataView;
}

interface HID {
  requestDevice(options: { filters: Array<{ vendorId?: number; productId?: number }> }): Promise<HIDDevice[]>;
  getDevices(): Promise<HIDDevice[]>;
}

interface Navigator {
  hid: HID;
}
