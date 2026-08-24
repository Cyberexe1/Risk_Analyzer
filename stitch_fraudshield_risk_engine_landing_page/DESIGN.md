---
name: FraudShield Editorial Ledger
colors:
  surface: '#fbf9f6'
  surface-dim: '#dbdad7'
  surface-bright: '#fbf9f6'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f5f3f0'
  surface-container: '#efeeeb'
  surface-container-high: '#eae8e5'
  surface-container-highest: '#e4e2df'
  on-surface: '#1b1c1a'
  on-surface-variant: '#56423a'
  inverse-surface: '#30312f'
  inverse-on-surface: '#f2f0ed'
  outline: '#897268'
  outline-variant: '#ddc1b5'
  surface-tint: '#9e420d'
  primary: '#9b400a'
  on-primary: '#ffffff'
  primary-container: '#bb5823'
  on-primary-container: '#fffbff'
  inverse-primary: '#ffb695'
  secondary: '#635e56'
  on-secondary: '#ffffff'
  secondary-container: '#eae1d7'
  on-secondary-container: '#69635c'
  tertiary: '#635b4e'
  on-tertiary: '#ffffff'
  tertiary-container: '#7c7366'
  on-tertiary-container: '#fffbff'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#ffdbcc'
  primary-fixed-dim: '#ffb695'
  on-primary-fixed: '#351000'
  on-primary-fixed-variant: '#7b2f00'
  secondary-fixed: '#eae1d7'
  secondary-fixed-dim: '#cdc5bc'
  on-secondary-fixed: '#1f1b15'
  on-secondary-fixed-variant: '#4b463f'
  tertiary-fixed: '#ede1d1'
  tertiary-fixed-dim: '#d0c5b5'
  on-tertiary-fixed: '#201b11'
  on-tertiary-fixed-variant: '#4d463a'
  background: '#fbf9f6'
  on-background: '#1b1c1a'
  surface-variant: '#e4e2df'
typography:
  display-lg:
    fontFamily: Playfair Display
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Playfair Display
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
  headline-lg-mobile:
    fontFamily: Playfair Display
    fontSize: 28px
    fontWeight: '700'
    lineHeight: 36px
  headline-md:
    fontFamily: Playfair Display
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  body-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  data-mono:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: -0.01em
  label-caps:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '700'
    lineHeight: 16px
    letterSpacing: 0.05em
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  base: 8px
  container-margin: 32px
  gutter: 24px
  section-gap: 48px
---

## Brand & Style

This design system shifts the fraud prevention narrative from "emergency response" to "scholarly oversight." It rejects the cold, blue-light aesthetic of traditional fintech in favor of an editorial, warm-neutral palette that evokes the reliability of a high-end financial journal or a physical ledger.

The visual style is **Modern Editorial with Tonal Layering**. It utilizes high-contrast typography and a restrained color palette to provide clarity in data-dense environments. The aesthetic response should feel authoritative, calm, and intellectually rigorous—positioning the fraud analyst as an expert investigator rather than a reactive operator.

The system relies on:
- **Spatial clarity:** Generous whitespace and hairline borders to separate complex data.
- **Materiality:** A bone-colored base that reduces eye strain compared to pure white.
- **Expert Precision:** A mix of classic serifs and technical monospaced fonts to balance heritage with modern data analysis.

## Colors

The palette is anchored in organic, ink-like tones that feel grounded and permanent.

- **Backgrounds:** The primary surface is #F7F5F2 (Bone). In dark mode, surfaces transition to a deep warm charcoal (#1A1816).
- **Primary Accent:** Burnt Amber (#C9622D) is reserved exclusively for primary calls to action, focus states, and critical paths.
- **Semantic Logic:** Instead of neon "traffic lights," use muted, desaturated tones. 
    - **Allow (Green):** A deep forest/ink green (#3D5A45).
    - **Review (Amber):** A weathered gold (#B38B3F).
    - **Block (Red):** A rusted, iron-oxide red (#963E2D).
- **Text:** Use a soft black (#1F1D1B) for primary readability to maintain high contrast without the harshness of pure hex black.

## Typography

Typography is the primary driver of the "Editorial" feel. 

1.  **Headlines:** Use **Playfair Display**. It provides a literary, authoritative character. Use it for page titles, section headers, and large metric callouts.
2.  **Body & UI:** Use **Inter**. It provides maximum legibility for long-form fraud reports and complex dashboard controls.
3.  **Data & IDs:** Use **JetBrains Mono** for all Transaction IDs, IP addresses, Device Fingerprints, and Indian Rupee (₹) amounts. This ensures character alignment and a technical "ledger" feel.
4.  **Formatting:** Always use the Indian Numbering System for currency (e.g., ₹1,00,000). Ensure the Rupee symbol (₹) uses the monospaced weight for alignment in tables.

## Layout & Spacing

The layout philosophy follows a **Fixed-Fluid Hybrid Grid**. Content is housed in a centered container on ultra-wide screens to maintain readability, but internal components utilize fluid percentage widths.

- **The 8px Rhythm:** All spacing (padding, margins, gaps) must be multiples of 8px.
- **Density:** FraudShield requires high information density. Use 8px or 12px gaps for data tables, but allow 48px+ of vertical breathing room between major semantic sections.
- **Breakpoints:**
    - **Mobile:** Single column, 16px margins.
    - **Tablet:** 8-column grid, 24px margins.
    - **Desktop (1440px+):** 12-column grid, 32px margins, maximum container width of 1280px.

## Elevation & Depth

This system avoids heavy shadows and floating effects to maintain its "printed" aesthetic.

- **Tonal Layering:** Depth is communicated through color shifts. The main background is #F7F5F2; secondary containers or "cards" use a slightly lighter off-white (#FFFFFF) or a very subtle tint of the primary color at 2% opacity.
- **Hairline Borders:** Use 1px borders in a muted taupe/grey (#D9D4CC) to define elements. This replaces the need for shadows.
- **Focused Elevation:** Only use shadows for ephemeral elements like dropdown menus or modals. Use a "Paper Shadow": `0px 4px 20px rgba(31, 29, 27, 0.08)`, which is highly diffused and light.

## Shapes

The shape language is "Soft-Mechanical." It avoids the extreme "pill" shapes of consumer apps to remain professional, but uses enough rounding to feel modern and accessible.

- **Standard Elements:** Buttons, Inputs, and Cards use a **10px radius** (the midpoint of the "Rounded" scale).
- **Small Elements:** Checkboxes and Chips use a **4px radius**.
- **Interactive States:** On hover, borders should remain 1px but transition to a darker neutral or the primary terracotta color.

## Components

- **Buttons:** 
    - *Primary:* Solid Burnt Amber (#C9622D) with White text. No gradients.
    - *Secondary:* 1px hairline border in #4A453E with matching text color.
- **Data Tables:** Use a 1px horizontal-only border style. Rows should have a subtle #F2EFEA hover state. All currency values (₹) right-aligned and monospaced.
- **Status Chips:** Use a subtle background (10% opacity of the semantic color) with high-contrast text. For example, a "Block" chip has #963E2D text on a #F9EBED background.
- **Input Fields:** 1px hairline border. Focus state uses a 1px Burnt Amber border and a 2px outer "halo" of the same color at 10% opacity. Label text uses the `label-caps` typography style.
- **Summary Cards:** Use the `headline-md` for the primary metric and `data-mono` for the secondary "percentage change" or "ID" indicator.
- **Fraud Score Indicator:** Use a horizontal bar (gauge) rather than a circle, utilizing the muted semantic scale (Green -> Amber -> Red).