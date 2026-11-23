/** Product mark: a file split into three chunks, each sitting on a different provider lane. */
export function Mark({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden focusable="false">
      <rect x="2" y="3" width="9" height="5" rx="1" fill="var(--p-aws)" />
      <rect x="8" y="9.5" width="9" height="5" rx="1" fill="var(--p-azure)" />
      <rect x="13" y="16" width="9" height="5" rx="1" fill="var(--p-gcs)" />
      <path d="M6.5 8v4.5H8M12.5 14.5V18.5H13" stroke="var(--ink-2)" strokeWidth="1.2" fill="none" />
    </svg>
  );
}
