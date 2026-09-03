# -*- coding: utf-8 -*-
"""
캐치테이블 줄서기예약 웹 UI (FastAPI, 포트 9091)

기존 reservation-catchtable.py 의 CatchTableClient 를 그대로 재사용해서
매장명/날짜/인원을 넣으면 시간대를 조회하고, 원하는 시간대에 바로 줄서기예약을
등록할 수 있는 최소한의 웹 화면을 제공한다. 원하는 날짜에 예약 가능한 시간대가
없으면 '자동예약'을 켜두면 백그라운드에서 주기적으로 재조회하다가 시간대가
열리는 순간 자동으로 등록을 시도한다.
"""

import importlib.util
import os
import sys
import threading
import uuid
from datetime import datetime

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(WEB_DIR)
sys.path.insert(0, ROOT_DIR)

# .env 파일 로드 (reservation-catchtable.py 와 동일하게 CATCHTABLE_ID/PASSWORD 등을 읽어옴)
env_path = os.path.join(ROOT_DIR, ".env")
if os.path.exists(env_path):
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())

# reservation-catchtable.py 는 파일명에 하이픈이 있어 일반 import 문으로는 불러올 수
# 없으므로 importlib 로 경로 지정해서 로드한다.
_spec = importlib.util.spec_from_file_location(
    "reservation_catchtable", os.path.join(ROOT_DIR, "reservation-catchtable.py")
)
reservation_catchtable = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reservation_catchtable)

CatchTableClient = reservation_catchtable.CatchTableClient
CatchTableApiError = reservation_catchtable.CatchTableApiError
to_yymmdd = reservation_catchtable.to_yymmdd
to_hhmm = reservation_catchtable.to_hhmm

app = FastAPI(title="캐치테이블 줄서기예약")

CATCHTABLE_ID = os.environ.get("CATCHTABLE_ID") or os.environ.get("ID", "")
CATCHTABLE_PASSWORD = os.environ.get("CATCHTABLE_PASSWORD") or os.environ.get("PASSWORD", "")

_client = None
_client_lock = threading.Lock()
# 캐치테이블 API 는 세션 쿠키(x-ct-a)를 직접 갱신하므로 여러 스레드(수동 조회/등록 +
# 자동예약 워커들)가 동시에 호출하지 않도록 직렬화한다.
_call_lock = threading.Lock()

AUTO_RESERVE_INTERVAL_SEC = 20


def get_client():
    """로그인 세션(쿠키) 확보에 네트워크 호출이 필요하므로 앱 전체에서 하나만 만들어 재사용한다."""
    global _client
    with _client_lock:
        if _client is None:
            if not CATCHTABLE_ID or not CATCHTABLE_PASSWORD:
                raise CatchTableApiError(
                    "CATCHTABLE_ID/CATCHTABLE_PASSWORD가 설정되어 있지 않습니다 (.env 확인)"
                )
            client = CatchTableClient()
            client.login(CATCHTABLE_ID, CATCHTABLE_PASSWORD)
            _client = client
        return _client


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def err_response(e: Exception):
    return JSONResponse({"ok": False, "error": str(e)}, status_code=200)


class SearchRequest(BaseModel):
    shop: str
    date: str
    person: int = 1


class RegisterRequest(BaseModel):
    shop_ref: str
    shop_name: str = ""
    date: str
    time: str
    table_id: str
    person: int = 1
    purpose: str = "EAT_ALONE"


class CancelRequest(BaseModel):
    reservation_ref: str


class AutoReserveStartRequest(BaseModel):
    shop_ref: str
    shop_name: str = ""
    date: str
    time: str = ""  # 특정 시간 지정 시 그 시간만 감시, 비어있으면 첫 가능 시간대
    person: int = 1
    purpose: str = "EAT_ALONE"


class AutoReserveStopRequest(BaseModel):
    job_id: str


@app.post("/api/search")
def search(req: SearchRequest):
    try:
        client = get_client()
        with _call_lock:
            shop = client.search_shop(req.shop)
            shop_ref = shop["primaryCode"]
            data = client.time_slots(shop_ref, req.date, req.person)
    except CatchTableApiError as e:
        return err_response(e)

    return {
        "ok": True,
        "shop": shop,
        "shop_ref": shop_ref,
        "slots": data.get("timeSlots") or [],
        "not_available_reason": data.get("notAvailableReason"),
        "remaining_count": data.get("remainingCount"),
    }


@app.post("/api/register")
def register(req: RegisterRequest):
    try:
        client = get_client()
        date_yymmdd = to_yymmdd(req.date)
        time_hhmm = to_hhmm(req.time)
        with _call_lock:
            client.validate_time_slot(req.shop_ref, date_yymmdd, time_hhmm)
            holding_id = client.create_holding(req.shop_ref, req.table_id, req.date, req.time)
            reservation = client.register(
                req.shop_ref, holding_id, req.table_id, req.date, req.time, req.person
            )
            if req.purpose and req.purpose != "none":
                try:
                    client.set_visit_purpose(reservation["reservationRef"], [req.purpose])
                except Exception:
                    pass
    except CatchTableApiError as e:
        return err_response(e)

    return {"ok": True, "reservation": reservation}


@app.get("/api/reservations")
def reservations(status: str = "PLANNED"):
    try:
        client = get_client()
        with _call_lock:
            items = client.list_reservations(status_group=status)
    except CatchTableApiError as e:
        return err_response(e)

    return {"ok": True, "items": items}


@app.post("/api/cancel")
def cancel(req: CancelRequest):
    try:
        client = get_client()
        with _call_lock:
            current = client.get_reservation(req.reservation_ref)
            if current.get("status") == "CANCEL":
                return {"ok": True, "already_cancelled": True, "reservation": current}
            result = client.cancel_reservation(req.reservation_ref)
    except CatchTableApiError as e:
        return err_response(e)

    return {"ok": True, "reservation": result}


# ---------------------------------------------------------------------------
# 자동예약 (원하는 날짜에 시간대가 없을 때 백그라운드에서 주기적으로 재조회하다가
# 시간대가 열리는 순간 즉시 줄서기예약을 등록)
# ---------------------------------------------------------------------------

_jobs: dict = {}
_jobs_lock = threading.Lock()


def _job_public(job: dict) -> dict:
    return {k: v for k, v in job.items() if not k.startswith("_")}


def _pick_slot(slots: list, wanted_time: str):
    if not slots:
        return None
    if wanted_time:
        return next((s for s in slots if s.get("operationTime") == wanted_time), None)
    return slots[0]


def _auto_reserve_worker(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None:
        return
    stop_event = job["_stop_event"]
    client = get_client()

    while not stop_event.is_set():
        job["attempts"] += 1
        job["updated_at"] = now_iso()
        try:
            with _call_lock:
                data = client.time_slots(job["shop_ref"], job["date"], job["person"])
            slots = data.get("timeSlots") or []
            target = _pick_slot(slots, job["time"])

            if target is None:
                job["last_status_text"] = data.get("notAvailableReason") or "가능한 시간대 없음"
            else:
                visit_time = target["operationTime"]
                table_id = target["tableIds"][0]
                job["last_status_text"] = f"시간대 발견: {visit_time} (잔여 {data.get('remainingCount')}팀), 등록 시도 중"
                date_yymmdd = to_yymmdd(job["date"])
                time_hhmm = to_hhmm(visit_time)
                with _call_lock:
                    client.validate_time_slot(job["shop_ref"], date_yymmdd, time_hhmm)
                    holding_id = client.create_holding(job["shop_ref"], table_id, job["date"], visit_time)
                    reservation = client.register(
                        job["shop_ref"], holding_id, table_id, job["date"], visit_time, job["person"]
                    )
                    if job["purpose"] and job["purpose"] != "none":
                        try:
                            client.set_visit_purpose(reservation["reservationRef"], [job["purpose"]])
                        except Exception:
                            pass
                job["status"] = "reserved"
                job["result"] = reservation
                job["updated_at"] = now_iso()
                return
        except Exception as e:
            job["last_status_text"] = f"오류 발생, 계속 감시: {e}"

        if stop_event.wait(AUTO_RESERVE_INTERVAL_SEC):
            break

    if job["status"] == "running":
        job["status"] = "stopped"
        job["updated_at"] = now_iso()


@app.post("/api/auto-reserve/start")
def auto_reserve_start(req: AutoReserveStartRequest):
    if not (req.shop_ref and req.date):
        return JSONResponse({"ok": False, "error": "매장/날짜 정보가 올바르지 않습니다."}, status_code=400)

    with _jobs_lock:
        for existing in _jobs.values():
            if (
                existing["status"] == "running"
                and existing["shop_ref"] == req.shop_ref
                and existing["date"] == req.date
                and existing["time"] == req.time
            ):
                return {"ok": True, "job": _job_public(existing)}

        job_id = uuid.uuid4().hex[:12]
        job = {
            "id": job_id,
            "shop_ref": req.shop_ref,
            "shop_name": req.shop_name,
            "date": req.date,
            "time": req.time,
            "person": req.person,
            "purpose": req.purpose,
            "status": "running",
            "attempts": 0,
            "last_status_text": "감시 시작",
            "result": None,
            "created_at": now_iso(),
            "updated_at": now_iso(),
            "_stop_event": threading.Event(),
        }
        _jobs[job_id] = job

    thread = threading.Thread(target=_auto_reserve_worker, args=(job_id,), daemon=True)
    job["_thread"] = thread
    thread.start()

    return {"ok": True, "job": _job_public(job)}


@app.post("/api/auto-reserve/stop")
def auto_reserve_stop(req: AutoReserveStopRequest):
    with _jobs_lock:
        job = _jobs.get(req.job_id)
        if job is None:
            return JSONResponse({"ok": False, "error": "해당 자동예약 작업이 없습니다."}, status_code=404)
        if job["status"] == "running":
            job["status"] = "stopped"
            job["updated_at"] = now_iso()
        job["_stop_event"].set()
        return {"ok": True, "job": _job_public(job)}


@app.get("/api/auto-reserve/list")
def auto_reserve_list():
    with _jobs_lock:
        jobs = sorted(_jobs.values(), key=lambda j: j["created_at"], reverse=True)
        return {"ok": True, "jobs": [_job_public(j) for j in jobs]}


@app.post("/api/auto-reserve/remove")
def auto_reserve_remove(req: AutoReserveStopRequest):
    with _jobs_lock:
        job = _jobs.get(req.job_id)
        if job is None:
            return JSONResponse({"ok": False, "error": "해당 자동예약 작업이 없습니다."}, status_code=404)
        if job["status"] == "running":
            return JSONResponse({"ok": False, "error": "실행 중인 작업은 먼저 중지해주세요."}, status_code=400)
        del _jobs[req.job_id]
        return {"ok": True}


app.mount("/", StaticFiles(directory=os.path.join(WEB_DIR, "static"), html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=9091, reload=False)
