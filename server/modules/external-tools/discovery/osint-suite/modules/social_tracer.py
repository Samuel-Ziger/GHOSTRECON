"""
modules/social_tracer.py — Rastreia username em 100+ plataformas
"""

import asyncio
import aiohttp
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from core.base import BaseModule

PLATFORMS = {
    "GitHub":       "https://github.com/{u}",
    "GitLab":       "https://gitlab.com/{u}",
    "Twitter/X":    "https://twitter.com/{u}",
    "Instagram":    "https://www.instagram.com/{u}/",
    "TikTok":       "https://www.tiktok.com/@{u}",
    "YouTube":      "https://www.youtube.com/@{u}",
    "Reddit":       "https://www.reddit.com/user/{u}",
    "LinkedIn":     "https://www.linkedin.com/in/{u}",
    "Pinterest":    "https://www.pinterest.com/{u}/",
    "Twitch":       "https://www.twitch.tv/{u}",
    "Steam":        "https://steamcommunity.com/id/{u}",
    "Spotify":      "https://open.spotify.com/user/{u}",
    "SoundCloud":   "https://soundcloud.com/{u}",
    "Medium":       "https://medium.com/@{u}",
    "Dev.to":       "https://dev.to/{u}",
    "HackerNews":   "https://news.ycombinator.com/user?id={u}",
    "Keybase":      "https://keybase.io/{u}",
    "Telegram":     "https://t.me/{u}",
    "Linktree":     "https://linktr.ee/{u}",
    "Patreon":      "https://www.patreon.com/{u}",
    "OnlyFans":     "https://onlyfans.com/{u}",
    "Behance":      "https://www.behance.net/{u}",
    "Dribbble":     "https://dribbble.com/{u}",
    "ProductHunt":  "https://www.producthunt.com/@{u}",
    "DockerHub":    "https://hub.docker.com/u/{u}",
    "PyPI":         "https://pypi.org/user/{u}/",
    "NPM":          "https://www.npmjs.com/~{u}",
    "Gravatar":     "https://en.gravatar.com/{u}",
    "AboutMe":      "https://about.me/{u}",
    "Flipboard":    "https://flipboard.com/@{u}",
    "Goodreads":    "https://www.goodreads.com/{u}",
    "Last.fm":      "https://www.last.fm/user/{u}",
    "Lichess":      "https://lichess.org/@/{u}",
    "Chess.com":    "https://www.chess.com/member/{u}",
    "Codepen":      "https://codepen.io/{u}",
    "Replit":       "https://replit.com/@{u}",
    "HackerEarth":  "https://www.hackerearth.com/@{u}",
    "LeetCode":     "https://leetcode.com/{u}/",
    "Codeforces":   "https://codeforces.com/profile/{u}",
    "Kaggle":       "https://www.kaggle.com/{u}",
    "Vimeo":        "https://vimeo.com/{u}",
    "Flickr":       "https://www.flickr.com/people/{u}",
    "500px":        "https://500px.com/p/{u}",
    "Unsplash":     "https://unsplash.com/@{u}",
    "Imgur":        "https://imgur.com/user/{u}",
    "VK":           "https://vk.com/{u}",
    "OK.ru":        "https://ok.ru/{u}",
    "Mastodon":     "https://mastodon.social/@{u}",
    "Bluesky":      "https://bsky.app/profile/{u}.bsky.social",
    "Substack":     "https://{u}.substack.com",
    "Hashnode":     "https://hashnode.com/@{u}",
}

NOT_FOUND_INDICATORS = [
    "404", "not found", "user not found", "page not found",
    "doesn't exist", "no longer available", "this account",
    "usuário não encontrado",
]


class SocialTracer(BaseModule):
    name        = "SocialTracer"
    description = "Rastreia username em múltiplas plataformas"

    def run(self, target: str) -> dict:
        self.info(f"Buscando username: [bold]{target}[/bold]")
        results = asyncio.run(self._scan_all(target))

        found    = [r for r in results if r["status"] == "found"]
        notfound = [r for r in results if r["status"] == "not_found"]

        self.success(f"Encontrado em {len(found)}/{len(PLATFORMS)} plataformas")

        return {
            "target":    target,
            "found":     found,
            "not_found": notfound,
            "total":     len(PLATFORMS),
        }

    async def _scan_all(self, username: str) -> list:
        connector = aiohttp.TCPConnector(limit=20, ssl=False)
        timeout   = aiohttp.ClientTimeout(total=10)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [
                self._check(session, platform, url.format(u=username), username)
                for platform, url in PLATFORMS.items()
            ]
            return await asyncio.gather(*tasks)

    async def _check(self, session, platform: str, url: str, username: str) -> dict:
        base = {
            "platform": platform,
            "url":      url,
            "username": username,
        }
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            async with session.get(url, headers=headers, allow_redirects=True) as resp:
                if resp.status == 200:
                    text = (await resp.text(errors="ignore")).lower()
                    if any(ind in text for ind in NOT_FOUND_INDICATORS):
                        return {**base, "status": "not_found", "http": resp.status}
                    return {**base, "status": "found", "http": resp.status}
                elif resp.status == 404:
                    return {**base, "status": "not_found", "http": 404}
                else:
                    return {**base, "status": "unknown", "http": resp.status}
        except Exception as e:
            return {**base, "status": "error", "error": str(e)}
