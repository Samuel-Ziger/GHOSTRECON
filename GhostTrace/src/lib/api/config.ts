export function getApiBaseUrl(): string | null {
  const url = process.env.NEXT_PUBLIC_API_URL?.trim();
  if (!url) return null;
  return url.replace(/\/$/, '');
}

export function isApiEnabled(): boolean {
  return !!getApiBaseUrl();
}
