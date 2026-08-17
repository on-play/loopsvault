# Design: LoopsVault

Locked project-wide brand system. Future agents must read this file before creating any LoopsVault
interface or artifact. Amend it intentionally. Do not create page-specific palettes or font stacks.

## Agent contract

1. Use the semantic roles in `tokens.css`. Never introduce a raw color inside an interface file.
2. Use system UI and system monospace fonts. Do not download or bundle a brand font.
3. Keep accent blue below 5 percent of a view. It marks trust, focus, and the protected value.
4. Keep security claims exact. LoopsVault prevents credentials from entering agent context. It does
   not stop an attacker with root access.
5. Use the supplied SVG marks. Do not redraw, stretch, rotate, add shadows, or add gradients.
6. Prefer native controls on macOS, Windows, and Linux. Brand the system around the control, not
   over it.

## System

- Genre: modern-minimal
- Marketing macrostructure: Split Studio
- Theme: custom, "protected, local, exact, native"
- Axes: light / system-native / cool
- Primary action: understand the boundary, then read the CLI quick start
- Surface rule: off-white paper, pure black ink, blue only as a trust signal

## Logo

The mark is two opposing rounded loops protecting one blue square. The loops are the operating
boundary. The square is the credential while it is in use.

- Primary mark: `brand/logo-mark.svg`
- Inverse mark: `brand/logo-mark-inverse.svg`
- Horizontal lockup: `brand/logo-lockup.svg`
- Minimum mark size: 16 px digital, 5 mm print
- Clear space: at least the width of the center square on every side
- Default mark: black loops, Vault Blue center, off-white or transparent ground
- Monochrome use: allowed only where the operating system supplies one-color iconography

The lockup uses live system monospace text by design. Native platforms should typeset the wordmark
with their system mono rather than converting it to a platform-specific outline.

## Color

| Role | Hex reference | Canonical token | Use |
| --- | --- | --- | --- |
| Ink | `#000000` | `--color-ink` | Primary text, vault boundary, high-emphasis controls |
| Paper | `#FBFBFB` | `--color-paper` | Default background and inverse logo stroke |
| Vault Blue | `#124EC5` | `--color-accent` | Protected value, links, selected state, trust signal |
| Focus Blue | `#2870E5` | `--color-focus` | Focus rings only |
| Blue Wash | `#EAF0FF` reference | `--color-accent-soft` | Small current-state surface |

Vault Blue has a 6.95:1 contrast ratio against Paper. Paper has a 20.29:1 ratio against Ink.
Focus Blue clears 4.4:1 against both Paper and Ink. Do not lighten the primary blue for decoration.

## Typography

- Display and body: native system UI at the platform's regular and bold weights
- Technical metadata: native system monospace
- Web UI: `ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`
- Web mono: `ui-monospace, "SFMono-Regular", "Cascadia Code", "Roboto Mono", monospace`
- macOS: San Francisco and SF Mono through `Font.system`
- Windows: Segoe UI and Cascadia Mono through system resources
- Linux: the desktop environment's default sans and monospace faces

Headlines use system UI, heavy weight, tight tracking, and roman style. Commands, credential names,
status, small labels, and the wordmark use system mono. Never italicize headings.

## Layout and components

- Base spacing: 4 px, through the named `--space-*` scale
- Page axis: left-biased with an unbalanced 7/5 split where two columns are needed
- Corners: 12 px for diagrams and large surfaces, 8 px for controls
- Borders: one visible 1 px rule, never card inside card
- Primary CTA: off-white surface, black border, compact rectangle, monospace label
- Focus: 2 px Focus Blue outline, 4 px offset, visible immediately
- Information architecture: paired claim-and-proof sections, spec rows, and ordered roadmap entries before feature cards

## Voice

- Declarative, technical, and specific
- Use short verbs: Use, Describe, Rotate, Revoke, Inspect
- Name the mechanism before the benefit
- Prefer "exact host matching" to "advanced security"
- Prefer "the value never enters agent context" to "your secrets are safe"
- Always state the root-access limit when describing the security boundary in depth
- Never say: military-grade, impenetrable, seamless, magical, unleash, or zero-risk

## Motion stance

- One paired entrance may establish the opening claim and protected path
- Buttons may move by 1 px on hover and active press
- No parallax, looping decoration, ambient glow, or section-by-section reveal
- Reduced motion: all spatial motion is removed or reduced to at most 120 ms

## Platform mapping

| Surface | Token delivery | Native guidance |
| --- | --- | --- |
| Web | `tokens.css` | CSS custom properties and semantic HTML |
| macOS | Asset Catalog generated from `brand/tokens.json` | SwiftUI colors, `Font.system`, SF Symbols where icons are needed |
| Windows | XAML resources generated from `brand/tokens.json` | WinUI controls, Segoe UI, Cascadia Mono |
| Linux | CSS or resource output generated from `brand/tokens.json` | libadwaita or toolkit-native controls, environment fonts |
| Agent harnesses | This file plus `brand/tokens.json` | Read before emitting UI, docs, screenshots, or install flows |

Windows and Linux desktop applications are brand-ready, not roadmap commitments. Product status
must remain separate from brand portability.

## Exports

`tokens.css` is the source of truth. `brand/tokens.json` is the checked-in DTCG export.

### CSS custom properties

```css
:root {
  --color-paper: oklch(98.809% 0 0);
  --color-paper-2: oklch(96% 0.012 262);
  --color-paper-3: oklch(92% 0.02 262);
  --color-ink: oklch(0% 0 0);
  --color-ink-2: oklch(26% 0.025 262);
  --color-rule: oklch(88% 0.02 262);
  --color-rule-2: oklch(74% 0.03 262);
  --color-muted: oklch(44% 0.03 262);
  --color-neutral: oklch(56% 0.03 262);
  --color-accent: oklch(46.845% 0.19501 262.119);
  --color-accent-ink: oklch(98.809% 0 0);
  --color-focus: oklch(56.82% 0.1917 259.947);

  --font-display: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-body: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-mono: ui-monospace, "SFMono-Regular", "Cascadia Code", "Roboto Mono", monospace;

  --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
  --ease-in: cubic-bezier(0.7, 0, 0.84, 0);
  --ease-in-out: cubic-bezier(0.65, 0, 0.35, 1);
  --dur-micro: 120ms;
  --dur-short: 220ms;
  --dur-long: 420ms;
  --radius-card: 0.75rem;
  --radius-input: 0.5rem;
}
```

### Tailwind v4

```css
@theme {
  --color-paper: oklch(98.809% 0 0);
  --color-paper-2: oklch(96% 0.012 262);
  --color-paper-3: oklch(92% 0.02 262);
  --color-ink: oklch(0% 0 0);
  --color-ink-2: oklch(26% 0.025 262);
  --color-rule: oklch(88% 0.02 262);
  --color-muted: oklch(44% 0.03 262);
  --color-accent: oklch(46.845% 0.19501 262.119);
  --color-focus: oklch(56.82% 0.1917 259.947);

  --font-display: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-body: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-mono: ui-monospace, "SFMono-Regular", "Cascadia Code", "Roboto Mono", monospace;

  --spacing-3xs: 0.125rem;
  --spacing-2xs: 0.25rem;
  --spacing-xs: 0.5rem;
  --spacing-sm: 0.75rem;
  --spacing-md: 1rem;
  --spacing-lg: 1.5rem;
  --spacing-xl: 2.5rem;
  --spacing-2xl: 4rem;
  --spacing-3xl: 6rem;
  --spacing-4xl: 9rem;

  --radius-card: 0.75rem;
  --radius-input: 0.5rem;
  --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
  --ease-in: cubic-bezier(0.7, 0, 0.84, 0);
  --ease-in-out: cubic-bezier(0.65, 0, 0.35, 1);
}
```

### DTCG

The complete export is `brand/tokens.json`. Its core shape is:

```json
{
  "$schema": "https://design-tokens.github.io/community-group/format/",
  "color": {
    "paper": { "$value": "oklch(98.809% 0 0)", "$type": "color" },
    "ink": { "$value": "oklch(0% 0 0)", "$type": "color" },
    "accent": { "$value": "oklch(46.845% 0.19501 262.119)", "$type": "color" },
    "focus": { "$value": "oklch(56.82% 0.1917 259.947)", "$type": "color" }
  },
  "font": {
    "display": { "$value": ["ui-sans-serif", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "sans-serif"], "$type": "fontFamily" },
    "mono": { "$value": ["ui-monospace", "SFMono-Regular", "Cascadia Code", "Roboto Mono", "monospace"], "$type": "fontFamily" }
  }
}
```

### shadcn/ui

```css
:root {
  --background: 98.809% 0 0;
  --foreground: 0% 0 0;
  --card: 96% 0.012 262;
  --card-foreground: 0% 0 0;
  --popover: 98.809% 0 0;
  --popover-foreground: 0% 0 0;
  --primary: 46.845% 0.19501 262.119;
  --primary-foreground: 98.809% 0 0;
  --secondary: 92% 0.02 262;
  --secondary-foreground: 26% 0.025 262;
  --muted: 88% 0.02 262;
  --muted-foreground: 44% 0.03 262;
  --accent: 46.845% 0.19501 262.119;
  --accent-foreground: 98.809% 0 0;
  --border: 88% 0.02 262;
  --input: 88% 0.02 262;
  --ring: 56.82% 0.1917 259.947;
  --radius: 0.75rem;
}
```
