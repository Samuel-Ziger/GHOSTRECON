from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NotFoundError
from app.db.postgres import get_session
from app.models import HttpRequest
from app.schemas import HttpRequestOut, RequestList
# usamos o HAR exporter do capture/
from capture.proxy.har_exporter import to_har  # type: ignore

router = APIRouter(prefix="/projects/{project_id}/requests")


@router.get("", response_model=RequestList)
async def list_requests(
    project_id: UUID,
    q: str | None = None,
    host: str | None = None,
    method: str | None = None,
    only_xhr: bool = False,
    only_graphql: bool = False,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: AsyncSession = Depends(get_session),
) -> RequestList:
    stmt = select(HttpRequest).where(HttpRequest.project_id == project_id)
    if q:
        stmt = stmt.where(HttpRequest.url.ilike(f"%{q}%"))
    if host:
        stmt = stmt.where(HttpRequest.host == host)
    if method:
        stmt = stmt.where(HttpRequest.method == method.upper())
    if only_xhr:
        stmt = stmt.where(HttpRequest.is_xhr.is_(True))
    if only_graphql:
        stmt = stmt.where(HttpRequest.is_graphql.is_(True))
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = int((await db.execute(count_stmt)).scalar_one())
    rows = list((await db.execute(
        stmt.order_by(HttpRequest.occurred_at.desc()).limit(limit).offset(offset)
    )).scalars())
    return RequestList(items=[HttpRequestOut.model_validate(r) for r in rows], total=total)


@router.get("/{request_id}", response_model=HttpRequestOut)
async def get_request(project_id: UUID, request_id: UUID, db: AsyncSession = Depends(get_session)) -> HttpRequest:
    r = (await db.execute(
        select(HttpRequest).where(
            HttpRequest.project_id == project_id, HttpRequest.id == request_id,
        )
    )).scalar_one_or_none()
    if r is None:
        raise NotFoundError("request not found")
    return r


@router.get("/export/har")
async def export_har(
    project_id: UUID,
    session_id: UUID | None = None,
    db: AsyncSession = Depends(get_session),
) -> Response:
    stmt = select(HttpRequest).where(HttpRequest.project_id == project_id)
    if session_id:
        stmt = stmt.where(HttpRequest.session_id == session_id)
    stmt = stmt.order_by(HttpRequest.occurred_at)
    rows = list((await db.execute(stmt)).scalars())
    raw_list = [{
        "method": r.method, "url": r.url, "host": r.host, "path": r.path,
        "query": r.query or {}, "req_headers": r.req_headers, "req_body": r.req_body,
        "req_body_text": r.req_body_text, "status": r.status, "resp_headers": r.resp_headers,
        "resp_body": r.resp_body, "resp_body_text": r.resp_body_text,
        "duration_ms": r.duration_ms, "occurred_at": r.occurred_at,
    } for r in rows]
    har = to_har(raw_list)
    import orjson
    return Response(
        content=orjson.dumps(har), media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="ghostmap_{project_id}.har"'},
    )
