# Brand assets

Visual identity for ownerwatch. The two `.svg` files are the masters; the `.png`
files are rendered from them (cairosvg). Regenerate the PNGs with:

```
cairosvg logo.svg          -o logo-400.png -W 400  -H 400
cairosvg logo.svg          -o logo-512.png -W 512  -H 512
cairosvg logo.svg          -o logo-128.png -W 128  -H 128
cairosvg social-preview.svg -o social-preview.png -W 1280 -H 640
```

## Files
| File | Size | Use |
|---|---|---|
| `logo.svg` | square | Master icon (shield = audit; keyhole = who holds the owner/admin keys). |
| `logo-400.png` | 400×400 | Marketplace/directory icons that want a 400px PNG (e.g. Cline MCP submission). |
| `logo-512.png` | 512×512 | General high-res icon (Glama, app stores, docs). |
| `logo-128.png` | 128×128 | Small icon / favicon source. |
| `social-preview.svg` | 1280×640 | Master for the repo social-preview banner. |
| `social-preview.png` | 1280×640 | GitHub repo **Settings → Social preview** image; link-unfurl card. |

## Palette
- Background: `#121D30` → `#0C1422` (vertical gradient)
- Accent (teal): `#34E3C8` → `#1FB5A6`
- Keyhole / text on dark: `#F4FBFA`
- Muted text: `#8CA0B8`
- Border hairline: `#2A3B55`

Tagline: **Who controls this contract?** — owners · admins · Safe signers · timelocks · roles.
