interface Props {
  size?: number;
  className?: string;
}

/**
 * GhostTrace brand mark — minimal terminal cursor with a ghost wisp.
 * Echoes the cyberpunk-clean aesthetic of professional offensive tooling.
 */
export function GhostTraceMark({ size = 24, className }: Props) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 28 28"
      className={className}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <rect x="2" y="2" width="24" height="24" rx="5" fill="currentColor" opacity="0.08" />
      <rect x="2" y="2" width="24" height="24" rx="5" stroke="currentColor" strokeOpacity="0.4" />
      <path
        d="M8 18.5V10.5c0-1.66 1.34-3 3-3h6c1.66 0 3 1.34 3 3v8L17.5 17l-1.75 1.5L14 17l-1.75 1.5L10.5 17 8 18.5z"
        fill="currentColor"
      />
      <circle cx="12" cy="12.5" r="1" fill="hsl(var(--bg))" />
      <circle cx="16" cy="12.5" r="1" fill="hsl(var(--bg))" />
    </svg>
  );
}
