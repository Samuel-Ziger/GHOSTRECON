'use client';

/** Hub MITRE ao vivo (HTML legado embutido). */
export default function GhostreconMitrePage() {
  const src =
    (process.env.NEXT_PUBLIC_BASE_PATH || '') + '/mitre-live.html';
  return (
    <iframe
      title="GHOSTRECON MITRE Map"
      src={src}
      className="w-full h-full border-0 bg-[#080c10]"
    />
  );
}
