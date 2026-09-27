/// <reference types="vite/client" />

declare module 'qrcode-generator' {
  interface QrCode {
    addData(data: string): void;
    make(): void;
    createSvgTag(options?: { scalable?: boolean; margin?: number }): string;
  }
  export default function qrcode(typeNumber: number, errorCorrectionLevel: 'L' | 'M' | 'Q' | 'H'): QrCode;
}

interface BarcodeDetectorResult {
  rawValue: string;
}

interface BarcodeDetector {
  detect(image: ImageBitmapSource): Promise<BarcodeDetectorResult[]>;
}

interface BarcodeDetectorConstructor {
  new (options?: { formats?: string[] }): BarcodeDetector;
}

interface Window {
  BarcodeDetector?: BarcodeDetectorConstructor;
}

// The SDK ships no typings for its wasm-bindgen glue; the loader only links it to the WASM instance.
declare module '@bitwarden/sdk-internal/bitwarden_wasm_internal_bg.js' {
  export function __wbg_set_wasm(exports: WebAssembly.Exports): void;
}
