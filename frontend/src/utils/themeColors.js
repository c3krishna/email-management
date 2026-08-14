/**
 * Theme-aware color tokens for Security pages.
 * Uses CSS variables so Light / Dark / Worktual themes apply everywhere.
 */
export function useThemeColors() {
  return {
    bg: 'var(--bg-primary)',
    bgCard: 'var(--bg-card)',
    bgSecondary: 'var(--bg-secondary)',
    bgPanel: 'var(--bg-secondary)',
    bgHover: 'var(--bg-hover)',
    navy: 'var(--bg-primary)',
    navyMid: 'var(--bg-secondary)',
    card: 'var(--bg-card)',
    white: 'var(--text-primary)',
    muted: 'var(--text-muted)',
    border: 'var(--border)',
    teal: 'var(--accent-cyan)',
    tealDim: 'rgba(8,145,178,0.12)',
    blue: 'var(--accent-blue)',
    blueDim: 'rgba(37,99,235,0.12)',
    purple: 'var(--accent-purple)',
    purpleDim: 'rgba(124,58,237,0.12)',
    green: 'var(--accent-green)',
    greenDim: 'rgba(22,163,74,0.12)',
    red: 'var(--accent-red)',
    redDim: 'rgba(220,38,38,0.12)',
    orange: 'var(--accent-orange)',
    orangeDim: 'rgba(234,88,12,0.12)',
    amber: 'var(--accent-yellow)',
    yellow: 'var(--accent-yellow)',
  };
}

/** Static export for modules that can't use hooks */
export const themeColors = {
  bg: 'var(--bg-primary)',
  bgCard: 'var(--bg-card)',
  bgSecondary: 'var(--bg-secondary)',
  bgPanel: 'var(--bg-secondary)',
  navy: 'var(--bg-primary)',
  navyMid: 'var(--bg-secondary)',
  card: 'var(--bg-card)',
  white: 'var(--text-primary)',
  muted: 'var(--text-muted)',
  border: 'var(--border)',
  teal: 'var(--accent-cyan)',
  tealDim: 'rgba(8,145,178,0.12)',
  blue: 'var(--accent-blue)',
  blueDim: 'rgba(37,99,235,0.12)',
  purple: 'var(--accent-purple)',
  purpleDim: 'rgba(124,58,237,0.12)',
  green: 'var(--accent-green)',
  greenDim: 'rgba(22,163,74,0.12)',
  red: 'var(--accent-red)',
  redDim: 'rgba(220,38,38,0.12)',
  orange: 'var(--accent-orange)',
  orangeDim: 'rgba(234,88,12,0.12)',
  amber: 'var(--accent-yellow)',
  yellow: 'var(--accent-yellow)',
};
