import sharp from 'sharp';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { resolve } from 'path';

const avatarPath = resolve('C:/Users/EJ/Desktop/avatar.jpg.png');

async function makeIcon(size) {
  const fontSize = Math.round(size * 0.19);
  const badgeW = Math.round(size * 0.44);
  const badgeH = Math.round(size * 0.24);
  const badgeX = size - badgeW - Math.round(size * 0.04);
  const badgeY = size - badgeH - Math.round(size * 0.04);
  const textX = Math.round(badgeX + badgeW / 2);
  const textY = Math.round(badgeY + badgeH * 0.72);

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}">
    <rect x="${badgeX}" y="${badgeY}" width="${badgeW}" height="${badgeH}" rx="${Math.round(size*0.055)}" fill="#42d392"/>
    <text x="${textX}" y="${textY}" font-family="Arial Black, Arial, sans-serif" font-weight="900"
      font-size="${fontSize}" fill="white" text-anchor="middle">GE</text>
  </svg>`;

  const outPath = resolve(`C:/Users/EJ/Desktop/ge-runtime/ge-icon-${size}.png`);
  await sharp(avatarPath)
    .resize(size, size, { fit: 'cover' })
    .composite([{ input: Buffer.from(svg), blend: 'over' }])
    .png()
    .toFile(outPath);

  console.log(`✓ ge-icon-${size}.png`);
}

await makeIcon(192);
await makeIcon(512);
