// 生成 1024x1024 主图标:与 GUI 托盘图标同款(青绿圆盘+白色圆点),8x 超采样抗锯齿
const zlib = require("zlib");
const fs = require("fs");
const S = 1024, SS = 8; // 画布与超采样倍数
const px = Buffer.alloc(S * S * 4);
const inside = (x, y, cx, cy, r) => (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
for (let y = 0; y < S; y++) {
  for (let x = 0; x < S; x++) {
    let r = 0, g = 0, b = 0, a = 0;
    for (let sy = 0; sy < SS; sy++) {
      for (let sx = 0; sx < SS; sx++) {
        const X = x + (sx + 0.5) / SS, Y = y + (sy + 0.5) / SS;
        const cx = S / 2, cy = S / 2;
        let cr, cg, cb, ca = 255;
        if (inside(X, Y, cx, cy, 128)) { cr = 255; cg = 255; cb = 255; }        // 中心圆点
        else if (inside(X, Y, cx, cy, 448)) { cr = 30; cg = 116; cb = 105; }    // 青绿圆盘
        else { cr = cg = cb = 0; ca = 0; }
        r += cr * ca; g += cg * ca; b += cb * ca; a += ca;
      }
    }
    const i = (y * S + x) * 4;
    px[i] = Math.round(r / a); px[i + 1] = Math.round(g / a); px[i + 2] = Math.round(b / a);
    px[i + 3] = Math.round(a / (SS * SS));
  }
}
// 最小 PNG 编码器(无依赖)
const crc32 = (() => { const t = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return b => { let c = 0xFFFFFFFF; for (const v of b) c = t[(c ^ v) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }; })();
const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type), data]); const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td)); return Buffer.concat([len, td, crc]); };
const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(S, 0); ihdr.writeUInt32BE(S, 4); ihdr[8] = 8; ihdr[9] = 6;
const raw = Buffer.alloc(S * (S * 4 + 1)); for (let y = 0; y < S; y++) { raw[y * (S * 4 + 1)] = 0; px.copy(raw, y * (S * 4 + 1) + 1, y * S * 4, (y + 1) * S * 4); }
const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), chunk("IHDR", ihdr), chunk("IDAT", zlib.deflateSync(raw, { level: 9 })), chunk("IEND", Buffer.alloc(0))]);
fs.writeFileSync(process.argv[2], png);
console.log("written", process.argv[2], png.length, "bytes");
