'use client';

import { useEffect, useState } from 'react';
import { MITRE_LIVE_SESSION_STORAGE_KEY } from './constants';

export function useMitreSessionId(): string {
  const [id, setId] = useState('');

  useEffect(() => {
    const fromHash = (window.location.hash || '').replace(/^#/, '').trim();
    let fromStorage = '';
    try {
      fromStorage = localStorage.getItem(MITRE_LIVE_SESSION_STORAGE_KEY) || '';
    } catch {
      /* ignore */
    }
    const sid = fromStorage || fromHash;
    setId(sid);
    if (sid && sid !== fromHash) {
      try {
        const u = new URL(window.location.href);
        u.hash = sid;
        window.history.replaceState(null, '', u.toString());
      } catch {
        /* ignore */
      }
    }
  }, []);

  return id;
}
