export default function ProjectLayout({ children }: { children: React.ReactNode }) {
  // Per-project layout shell would go here (project context provider, etc.)
  // For the prototype, each page reads the projectId from the URL and the store directly.
  return <>{children}</>;
}
