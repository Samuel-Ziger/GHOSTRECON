"""
Cliente Neo4j async (driver oficial).
Encapsula sessions + transactions + retries.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from neo4j import AsyncGraphDatabase, AsyncSession

from app.config import get_settings


class Neo4jClient:
    def __init__(self) -> None:
        s = get_settings()
        self._driver = AsyncGraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password))

    async def close(self) -> None:
        await self._driver.close()

    @asynccontextmanager
    async def session(self, database: str = "neo4j") -> AsyncIterator[AsyncSession]:
        s = self._driver.session(database=database)
        try:
            yield s
        finally:
            await s.close()

    async def run(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        async with self.session() as s:
            res = await s.run(cypher, params or {})
            return [dict(r) async for r in res]

    async def write(self, cypher: str, params: dict[str, Any] | None = None) -> None:
        async with self.session() as s:
            async def _tx(tx):
                await tx.run(cypher, params or {})
            await s.execute_write(_tx)


_singleton: Neo4jClient | None = None


def get_neo4j() -> Neo4jClient:
    global _singleton
    if _singleton is None:
        _singleton = Neo4jClient()
    return _singleton
