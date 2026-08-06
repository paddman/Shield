# NT Shield visual system

NT Shield uses a bright, trustworthy enterprise-security language rather than a dark cyberpunk theme.

## Core palette

| Token | Hex | Use |
|---|---:|---|
| NT Yellow | `#FFC400` | Primary action, active state, shield accent |
| Deep Charcoal | `#171C26` | Primary text, app-icon field |
| Slate | `#667085` | Secondary text |
| Cloud | `#F5F7FA` | App background |
| White | `#FFFFFF` | Surfaces and cards |
| Success | `#16A36A` | Healthy/online state |
| Critical | `#E23B3B` | Critical incidents only |

## Assets

- `assets/branding/ntshield-wordmark.svg` is the editable horizontal wordmark.
- `assets/branding/ntshield-app-icon.svg` is the editable square application mark.
- `assets/branding/ntshield-platform-hero.png` is the generated hero/background plate used by the web login.
- `docs/design-reference/` contains the supplied mobile login, desktop login, and dashboard references.

Keep product copy in HTML/XAML instead of baking it into bitmap artwork. This preserves accessibility, localization, and responsive layouts.

## Typography

The web control center ships Noto Sans Thai locally in regular and bold weights. It is loaded before the system sans-serif stack so Thai and English copy render consistently without depending on a third-party font CDN. The bundled font files are distributed under the SIL Open Font License in `src/NTShield.Server/wwwroot/assets/fonts/OFL.txt`.

> Before an external commercial release, confirm the wordmark against NT's current corporate-identity requirements.
