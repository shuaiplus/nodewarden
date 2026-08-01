import jsQR from 'jsqr';

export const QR_IMAGE_MAX_BYTES = 8 * 1024 * 1024;

export type QrDecodeResult =
  | { ok: true; value: string }
  | { ok: false; reason: 'empty' | 'multiple' | 'unsupported' | 'unreadable' };

export function createQrCodeDetector(): BarcodeDetector | null {
  if (typeof window === 'undefined' || !window.BarcodeDetector) return null;
  return new window.BarcodeDetector({ formats: ['qr_code'] });
}

export function decodeQrFromCanvas(source: ImageBitmap | HTMLVideoElement): string {
  const width = 'videoWidth' in source ? source.videoWidth : source.width;
  const height = 'videoHeight' in source ? source.videoHeight : source.height;
  if (!width || !height) return '';
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const context = canvas.getContext('2d');
  if (!context) return '';
  // jsQR ignores alpha and reads RGB directly, so transparent pixels would be
  // treated as black. Composite over white first so transparent-background QR
  // exports do not become black-on-black and fail to decode.
  context.fillStyle = '#ffffff';
  context.fillRect(0, 0, width, height);
  context.drawImage(source, 0, 0, width, height);
  const imageData = context.getImageData(0, 0, width, height);
  return String(jsQR(imageData.data, width, height)?.data || '').trim();
}

async function detectQrValues(source: ImageBitmap | HTMLVideoElement): Promise<string[]> {
  const detector = createQrCodeDetector();
  if (!detector) return [];
  try {
    const results = await detector.detect(source);
    return results
      .map((result) => String(result.rawValue || '').trim())
      .filter(Boolean);
  } catch {
    // Fall back to jsQR when the native detector is present but not usable.
    return [];
  }
}

export async function decodeSingleQrCode(
  source: ImageBitmap | HTMLVideoElement,
  options?: { allowMultipleNativeHits?: boolean }
): Promise<QrDecodeResult> {
  const detected = await detectQrValues(source);
  if (detected.length > 1 && !options?.allowMultipleNativeHits) {
    return { ok: false, reason: 'multiple' };
  }
  if (detected.length === 1) return { ok: true, value: detected[0] };
  if (detected.length > 1) return { ok: true, value: detected[0] };

  const fallback = decodeQrFromCanvas(source);
  if (!fallback) return { ok: false, reason: 'unreadable' };
  return { ok: true, value: fallback };
}

export function assertQrImageFile(file: File): 'ok' | 'invalid-type' | 'too-large' {
  if (file.type && !file.type.startsWith('image/')) return 'invalid-type';
  if (file.size > QR_IMAGE_MAX_BYTES) return 'too-large';
  return 'ok';
}
