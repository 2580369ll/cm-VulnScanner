"""WebSocket — 扫描进度实时推送"""

import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["websocket"])

# 连接池: {task_id: [ws1, ws2, ...]}
_connections: dict[str, list[WebSocket]] = {}


@router.websocket("/tasks/{task_id}")
async def scan_progress(websocket: WebSocket, task_id: str):
    """WebSocket 连接：实时推送扫描进度"""
    await websocket.accept()

    if task_id not in _connections:
        _connections[task_id] = []
    _connections[task_id].append(websocket)

    try:
        while True:
            # 保持连接，等待客户端消息（心跳检测）
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    finally:
        _connections[task_id].remove(websocket)
        if not _connections[task_id]:
            del _connections[task_id]


async def broadcast_progress(task_id: str, message: dict):
    """向某任务的所有 WebSocket 连接广播消息"""
    if task_id in _connections:
        dead = []
        for ws in _connections[task_id]:
            try:
                await ws.send_text(json.dumps(message, ensure_ascii=False))
            except Exception:
                dead.append(ws)
        for ws in dead:
            _connections[task_id].remove(ws)
