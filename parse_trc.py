#!/usr/bin/env python3
"""
Oracle DB SQL Trace File (10046) Interactive HTML Visualizer.
Uses only Python 3 built-in standard library modules (Python 3.4+ compatible).
"""

import argparse
import base64
import datetime
import gzip
import html
import json
import os
import re
import sys


def parse_timestamp(t_str):
    """
    Parses Oracle trace timestamps without relying on datetime.fromisoformat()
    for compatibility across all Python 3 versions.
    """
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", t_str)
    if not m:
        return None
    year, month, day, hour, minute, second, frac = m.groups()
    us = 0
    if frac:
        frac = (frac + "000000")[:6]
        us = int(frac)
    return datetime.datetime(int(year), int(month), int(day), int(hour), int(minute), int(second), us)


def parse_trace_file(file_path):
    """
    Parses an Oracle SQL trace file into structured events, cursor definitions,
    and wall-clock calibration points.
    Associates wait events to cursor calls while keeping SQL*Net client waits at the top level.
    """
    time_re = re.compile(
        r"^\*\*\*\s+(?:SESSION ID:\([^)]+\)\s+)?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    )
    cursor_re = re.compile(
        r"^PARSING IN CURSOR #(\d+).*?\bdep=(\d+).*?\btim=(\d+).*?\bhv=(\d+)(?:.*?sqlid='([^']+)')?"
    )
    call_re = re.compile(
        r"^(PARSE|EXEC|FETCH|CLOSE) #(\d+):.*?\bc=(\d+).*?\be=(\d+).*?\br=(\d+).*?\bdep=(\d+).*?\btim=(\d+)"
    )
    wait_re = re.compile(
        r"^WAIT #(\d+): nam='([^']+)' ela=\s*(\d+).*?tim=(\d+)"
    )

    cursors = {}
    sql_texts = {}
    events = []
    wall_checkpoints = []

    pending_wall_time = None
    in_stmt = False
    cur_stmt_sql_id = None
    cur_stmt_lines = []

    active_top_call = None
    last_call_by_cursor = {}
    pending_waits_by_cursor = {}
    event_id_seq = 0

    def flush_cursor_waits(cid, target_call=None):
        if target_call is None:
            target_call = last_call_by_cursor.get(cid) or active_top_call
        waits = pending_waits_by_cursor.pop(cid, [])
        for w in waits:
            if target_call:
                w["parent_id"] = target_call["id"]
                w["top_call_id"] = target_call["top_call_id"]
                w["tree_depth"] = target_call["tree_depth"] + 1
            else:
                w["is_top_level"] = True
                w["top_call_id"] = w["id"]
                w["tree_depth"] = 0
            events.append(w)

    def flush_all_pending_waits():
        for cid in list(pending_waits_by_cursor.keys()):
            flush_cursor_waits(cid)

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.rstrip("\r\n")

            if in_stmt:
                if line_str == "END OF STMT" or line_str.startswith("END OF STMT"):
                    in_stmt = False
                    if cur_stmt_sql_id:
                        sql_texts[cur_stmt_sql_id] = "\n".join(cur_stmt_lines).strip()
                    cur_stmt_lines = []
                else:
                    cur_stmt_lines.append(line_str)
                continue

            # 1. Wall clock timestamp line
            m_time = time_re.match(line_str)
            if m_time:
                t_str = m_time.group(1).replace("T", " ")
                dt = parse_timestamp(t_str)
                if dt:
                    pending_wall_time = dt
                continue

            # 2. PARSING IN CURSOR (Cursor ID assignment / reuse)
            m_cur = cursor_re.match(line_str)
            if m_cur:
                cid_str, dep_str, tim_str, hv_str, sqlid_str = m_cur.groups()
                cid = int(cid_str)
                dep = int(dep_str)
                tim = int(tim_str)
                sql_id = sqlid_str if sqlid_str else "hv_{}".format(hv_str)

                # Cursor reuse: safely flush any waits pending on this cursor ID
                if cid in pending_waits_by_cursor:
                    flush_cursor_waits(cid)

                cursors[cid] = {"sql_id": sql_id, "dep": dep}

                if pending_wall_time is not None:
                    wall_checkpoints.append((tim, pending_wall_time))
                    pending_wall_time = None

                in_stmt = True
                cur_stmt_sql_id = sql_id
                cur_stmt_lines = []
                continue

            # 3. Database Call: PARSE, EXEC, FETCH, CLOSE
            m_call = call_re.match(line_str)
            if m_call:
                call_type, cid_str, c_str, e_str, r_str, dep_str, tim_str = m_call.groups()
                cid = int(cid_str)
                c_us = int(c_str)
                e_us = int(e_str)
                r_rows = int(r_str)
                dep = int(dep_str)
                tim = int(tim_str)

                if pending_wall_time is not None:
                    wall_checkpoints.append((tim, pending_wall_time))
                    pending_wall_time = None

                cur_info = cursors.get(cid, {"sql_id": "cursor_{}".format(cid), "dep": dep})
                sql_id = cur_info["sql_id"]

                event_id_seq += 1
                is_top = (dep == 0) or (active_top_call is None)

                call_ev = {
                    "id": event_id_seq,
                    "cat": "SQL",
                    "type": call_type,
                    "name": call_type,
                    "cid": cid,
                    "sql_id": sql_id,
                    "top_sql_id": sql_id if is_top else (active_top_call["sql_id"] if active_top_call else sql_id),
                    "dep": dep,
                    "tree_depth": 0 if is_top else (active_top_call["tree_depth"] + 1 if active_top_call else dep),
                    "start_tim": tim - e_us,
                    "end_tim": tim,
                    "ela_us": e_us,
                    "cpu_us": c_us,
                    "rows": r_rows,
                    "is_top_level": is_top,
                    "top_call_id": None,
                    "parent_id": None,
                }

                if is_top:
                    call_ev["top_call_id"] = call_ev["id"]
                    active_top_call = call_ev
                else:
                    call_ev["top_call_id"] = active_top_call["id"] if active_top_call else call_ev["id"]
                    call_ev["parent_id"] = active_top_call["id"] if active_top_call else None

                events.append(call_ev)
                last_call_by_cursor[cid] = call_ev

                # Associate all waits on this cursor ID that arrived prior to this call
                flush_cursor_waits(cid, call_ev)
                continue

            # 4. WAIT event
            m_wait = wait_re.match(line_str)
            if m_wait:
                cid_str, name, ela_str, tim_str = m_wait.groups()
                cid = int(cid_str)
                ela_us = int(ela_str)
                tim = int(tim_str)

                if pending_wall_time is not None:
                    wall_checkpoints.append((tim, pending_wall_time))
                    pending_wall_time = None

                cur_info = cursors.get(cid, {"sql_id": "N/A", "dep": 0})
                sql_id = cur_info["sql_id"]

                event_id_seq += 1
                wait_ev = {
                    "id": event_id_seq,
                    "cat": "WAIT",
                    "type": "WAIT",
                    "name": name,
                    "cid": cid,
                    "sql_id": sql_id,
                    "top_sql_id": active_top_call["sql_id"] if active_top_call else sql_id,
                    "dep": cur_info["dep"],
                    "tree_depth": 1,
                    "start_tim": tim - ela_us,
                    "end_tim": tim,
                    "ela_us": ela_us,
                    "cpu_us": 0,
                    "rows": 0,
                    "is_top_level": False,
                    "top_call_id": None,
                    "parent_id": None,
                }

                # Client idle wait: always top-level, independent non-child event
                if "message from client" in name.lower():
                    flush_all_pending_waits()
                    wait_ev["is_top_level"] = True
                    wait_ev["top_call_id"] = wait_ev["id"]
                    wait_ev["tree_depth"] = 0
                    events.append(wait_ev)
                    active_top_call = None
                elif name == "SQL*Net message to client" and cid in last_call_by_cursor:
                    target = last_call_by_cursor[cid]
                    if target:
                        wait_ev["parent_id"] = target["id"]
                        wait_ev["top_call_id"] = target["top_call_id"]
                        wait_ev["tree_depth"] = target["tree_depth"] + 1
                        events.append(wait_ev)
                    else:
                        if cid not in pending_waits_by_cursor:
                            pending_waits_by_cursor[cid] = []
                        pending_waits_by_cursor[cid].append(wait_ev)
                else:
                    if cid not in pending_waits_by_cursor:
                        pending_waits_by_cursor[cid] = []
                    pending_waits_by_cursor[cid].append(wait_ev)
                continue

    flush_all_pending_waits()

    if not events:
        return None

    # Group events: sort top-level calls chronologically; group each call's children under it
    top_level_events = []
    children_by_top = {}

    for ev in events:
        if ev["is_top_level"]:
            top_level_events.append(ev)
        else:
            top_id = ev["top_call_id"]
            if top_id not in children_by_top:
                children_by_top[top_id] = []
            children_by_top[top_id].append(ev)

    # Orphan rescue: promote any children with missing top_call_id to top level
    top_ids = set(x["id"] for x in top_level_events)
    for top_id, c_list in list(children_by_top.items()):
        if top_id not in top_ids:
            for orphan in c_list:
                orphan["is_top_level"] = True
                orphan["top_call_id"] = orphan["id"]
                orphan["tree_depth"] = 0
                top_level_events.append(orphan)
            del children_by_top[top_id]

    top_level_events.sort(key=lambda x: x["start_tim"])

    # Reconstruct final display sequence: top call followed by its ordered children
    final_ordered_events = []

    for top_ev in top_level_events:
        t_id = top_ev["id"]
        c_list = children_by_top.get(t_id, [])
        c_list.sort(key=lambda x: x["start_tim"])
        top_ev["child_count"] = len(c_list)
        final_ordered_events.append(top_ev)
        for child_ev in c_list:
            child_ev["child_count"] = 0
            final_ordered_events.append(child_ev)

    min_tim = min(x["start_tim"] for x in final_ordered_events)
    max_tim = max(x["end_tim"] for x in final_ordered_events)

    if wall_checkpoints:
        ref_tim, ref_dt = wall_checkpoints[0]
    else:
        ref_tim, ref_dt = min_tim, datetime.datetime.now()

    base_start_dt = ref_dt + datetime.timedelta(microseconds=min_tim - ref_tim)
    base_end_dt = ref_dt + datetime.timedelta(microseconds=max_tim - ref_tim)

    # Build dictionary tables for compact JSON compression
    unique_names = []
    name_to_idx = {}
    unique_sqls = []
    sql_to_idx = {}

    def get_name_idx(nm):
        if nm not in name_to_idx:
            name_to_idx[nm] = len(unique_names)
            unique_names.append(nm)
        return name_to_idx[nm]

    def get_sql_idx(sq):
        if not sq or sq == "N/A":
            return -1
        if sq not in sql_to_idx:
            sql_to_idx[sq] = len(unique_sqls)
            unique_sqls.append(sq)
        return sql_to_idx[sq]

    compact_events = []
    for ev in final_ordered_events:
        cat_code = 0 if ev["cat"] == "SQL" else 1
        name_idx = get_name_idx(ev["name"])
        sql_idx = get_sql_idx(ev["sql_id"])
        top_idx = get_sql_idx(ev["top_sql_id"])
        start_offset_us = ev["start_tim"] - min_tim

        # Compact tuple format:
        # [cat_code, name_idx, sql_idx, top_idx, tree_depth, start_offset_us, ela_us, cpu_us, rows, is_top(1/0), top_call_id, child_count]
        compact_events.append([
            cat_code,
            name_idx,
            sql_idx,
            top_idx,
            ev["tree_depth"],
            start_offset_us,
            ev["ela_us"],
            ev["cpu_us"],
            ev["rows"],
            1 if ev["is_top_level"] else 0,
            ev["top_call_id"],
            ev.get("child_count", 0),
        ])

    return {
        "summary": {
            "file_name": os.path.basename(file_path),
            "total_events": len(final_ordered_events),
            "total_duration_us": max_tim - min_tim,
            "base_epoch_ms": int(base_start_dt.timestamp() * 1000),
            "start_wall_hms": base_start_dt.strftime("%H:%M:%S"),
            "end_wall_hms": base_end_dt.strftime("%H:%M:%S"),
        },
        "names": unique_names,
        "sqls": unique_sqls,
        "sql_texts": sql_texts,
        "events": compact_events,
    }


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Oracle SQL Trace Report - __FILE_NAME__</title>
<style>
  :root {
    --bg-main: #0f172a;
    --bg-card: #1e293b;
    --bg-hover: #334155;
    --text-primary: #f8fafc;
    --text-muted: #94a3b8;
    --border-color: #334155;
    --accent: #38bdf8;
    --sql-parse: #c084fc;
    --sql-exec: #4ade80;
    --sql-fetch: #22d3ee;
    --wait-idle: #94a3b8;
    --wait-io: #60a5fa;
    --wait-lock: #f87171;
    --wait-other: #fbbf24;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background-color: var(--bg-main);
    color: var(--text-primary);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    padding: 18px 28px;
    font-size: 13.5px;
    line-height: 1.5;
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 14px;
    margin-bottom: 18px;
  }
  h1 { font-size: 19px; font-weight: 600; color: #f1f5f9; }
  .meta-tag {
    background: #0f172a;
    border: 1px solid var(--border-color);
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 12px;
    color: var(--text-muted);
  }
  .meta-tag strong { color: var(--accent); }

  .card {
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 20px;
  }
  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
  }
  .card-title { font-size: 15px; font-weight: 600; }

  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    font-size: 12px;
  }
  .legend-item { display: flex; align-items: center; gap: 6px; }
  .legend-color { width: 12px; height: 12px; border-radius: 3px; }

  #timeline-container {
    position: relative;
    width: 100%;
    margin-top: 10px;
    cursor: crosshair;
  }
  canvas#timeline-canvas {
    width: 100%;
    height: 195px;
    display: block;
    background: #0b1120;
    border-radius: 6px;
    border: 1px solid var(--border-color);
  }
  .controls-bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 14px;
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid var(--border-color);
    font-size: 13px;
  }
  .ctrl-group { display: flex; align-items: center; gap: 6px; }
  .ctrl-input {
    background: #0b1120;
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 4px 8px;
    border-radius: 4px;
    width: 100px;
    font-size: 12.5px;
    font-family: monospace;
    text-align: center;
  }
  button.btn {
    background: #0284c7;
    color: #fff;
    border: none;
    padding: 5px 12px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 500;
  }
  button.btn:hover { background: #0369a1; }
  button.btn-outline {
    background: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-muted);
  }
  button.btn-outline:hover { background: var(--bg-hover); color: #fff; }

  .tab-header {
    display: flex;
    gap: 8px;
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 16px;
  }
  .tab-btn {
    background: none;
    border: none;
    color: var(--text-muted);
    font-size: 13.5px;
    font-weight: 600;
    padding: 8px 16px;
    cursor: pointer;
    border-bottom: 2px solid transparent;
  }
  .tab-btn.active {
    color: var(--accent);
    border-bottom: 2px solid var(--accent);
  }
  .tab-pane { display: none; }
  .tab-pane.active { display: block; }

  table.data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
    text-align: left;
  }
  table.data-table th {
    background: #0b1120;
    color: var(--text-muted);
    padding: 9px 12px;
    border-bottom: 1px solid var(--border-color);
    font-weight: 600;
    cursor: pointer;
    user-select: none;
  }
  table.data-table th:hover { color: var(--text-primary); }
  table.data-table td {
    padding: 7px 12px;
    border-bottom: 1px solid #1e293b;
    vertical-align: middle;
  }
  table.data-table tr:hover td { background: var(--bg-hover); }

  .bar-container {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    min-width: 130px;
  }
  .bar-outer {
    flex: 1;
    height: 8px;
    background: #334155;
    border-radius: 4px;
    overflow: hidden;
  }
  .bar-inner { height: 100%; border-radius: 4px; }
  .bar-label {
    font-size: 11px;
    font-family: monospace;
    width: 75px;
    text-align: right;
    color: var(--text-muted);
  }

  .badge {
    display: inline-block;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 10.5px;
    font-weight: 600;
    text-transform: uppercase;
    font-family: monospace;
  }
  .badge-EXEC { background: rgba(74, 222, 128, 0.2); color: var(--sql-exec); border: 1px solid var(--sql-exec); }
  .badge-PARSE { background: rgba(192, 132, 252, 0.2); color: var(--sql-parse); border: 1px solid var(--sql-parse); }
  .badge-FETCH { background: rgba(34, 211, 238, 0.2); color: var(--sql-fetch); border: 1px solid var(--sql-fetch); }
  .badge-WAIT { background: rgba(251, 191, 36, 0.2); color: var(--wait-other); border: 1px solid var(--wait-other); }
  .badge-WAIT-IDLE { background: rgba(148, 163, 184, 0.2); color: var(--wait-idle); border: 1px solid var(--wait-idle); }
  .badge-WAIT-IO { background: rgba(96, 165, 250, 0.2); color: var(--wait-io); border: 1px solid var(--wait-io); }
  .badge-WAIT-LOCK { background: rgba(248, 113, 113, 0.2); color: var(--wait-lock); border: 1px solid var(--wait-lock); }

  .badge-dep-child { background: rgba(56, 189, 248, 0.2); color: var(--accent); border: 1px solid var(--accent); font-size: 10px; }

  .tree-cell {
    display: flex;
    align-items: center;
    gap: 6px;
    font-family: monospace;
  }
  .tree-branch { color: #64748b; user-select: none; }
  .row-child { background: rgba(15, 23, 42, 0.45); }
  .row-top { font-weight: 500; }

  .tree-toggle-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    background: #1e293b;
    border: 1px solid #475569;
    color: var(--accent);
    padding: 1px 7px;
    border-radius: 4px;
    font-size: 11px;
    cursor: pointer;
    font-family: monospace;
    user-select: none;
    transition: background 0.15s, border-color 0.15s;
  }
  .tree-toggle-btn:hover {
    background: #334155;
    border-color: var(--accent);
  }

  .sql-id-code {
    font-family: monospace;
    font-weight: 600;
    color: #e2e8f0;
    cursor: pointer;
    padding: 1px 4px;
    border-radius: 3px;
    transition: background 0.15s;
  }
  .sql-id-code:hover {
    background: #0284c7;
    color: #fff;
  }

  #tooltip, #sql-hover-tooltip {
    position: absolute;
    display: none;
    background: #020617;
    color: #f8fafc;
    border: 1px solid var(--accent);
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 12px;
    pointer-events: none;
    z-index: 99999;
    box-shadow: 0 6px 18px rgba(0,0,0,0.6);
    max-width: 550px;
  }
  #sql-hover-tooltip {
    max-height: 250px;
    overflow-y: auto;
    font-family: monospace;
    white-space: pre-wrap;
    line-height: 1.4;
    color: #38bdf8;
  }

  .modal {
    display: none;
    position: fixed;
    z-index: 100000;
    left: 0; top: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.7);
    justify-content: center;
    align-items: center;
  }
  .modal-content {
    background: #1e293b;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    width: 75%;
    max-width: 850px;
    max-height: 80vh;
    padding: 20px;
    display: flex;
    flex-direction: column;
  }
  .modal-text {
    background: #0b1120;
    border: 1px solid var(--border-color);
    padding: 12px;
    border-radius: 6px;
    overflow-y: auto;
    font-family: monospace;
    font-size: 13px;
    white-space: pre-wrap;
    color: #38bdf8;
    margin-top: 10px;
  }
  .pagination-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 14px;
    font-size: 12.5px;
    color: var(--text-muted);
  }
  #loading-cover {
    position: fixed; top:0; left:0; width:100%; height:100%;
    background: #0f172a; display: flex; flex-direction: column;
    justify-content: center; align-items: center; z-index: 200000;
    font-family: monospace; color: #38bdf8;
  }
</style>
</head>
<body>

<div id="loading-cover">
  <h2>Loading &amp; Decompressing Trace Data...</h2>
  <span style="color: #94a3b8; margin-top: 8px;">Decompressing payload in browser memory...</span>
</div>

<header>
  <div>
    <h1>Oracle SQL Trace Session Inspector</h1>
    <span style="color: var(--text-muted); font-size: 12px;">Trace File: <strong>__FILE_NAME__</strong></span>
  </div>
  <div style="display: flex; gap: 8px;">
    <div class="meta-tag">Total Events: <strong>__TOTAL_EVENTS__</strong></div>
    <div class="meta-tag">Duration: <strong>__DURATION_SEC__s</strong></div>
    <div class="meta-tag">Range (HH24:MI:SS): <strong>__START_WALL__</strong> &rarr; <strong>__END_WALL__</strong></div>
  </div>
</header>

<!-- FEATURE 1: Interactive Timeline Graphic -->
<div class="card">
  <div class="card-header">
    <div class="card-title">1. Session Activity Timeline (X-Axis: MI:SS)</div>
    <div class="legend">
      <div class="legend-item"><div class="legend-color" style="background: var(--sql-exec);"></div> EXEC</div>
      <div class="legend-item"><div class="legend-color" style="background: var(--sql-parse);"></div> PARSE</div>
      <div class="legend-item"><div class="legend-color" style="background: var(--sql-fetch);"></div> FETCH</div>
      <div class="legend-item"><div class="legend-color" style="background: var(--wait-idle);"></div> SQL*Net Client (Idle)</div>
      <div class="legend-item"><div class="legend-color" style="background: var(--wait-io);"></div> I/O Waits</div>
      <div class="legend-item"><div class="legend-color" style="background: var(--wait-lock);"></div> Lock / Concurrency</div>
      <div class="legend-item"><div class="legend-color" style="background: var(--wait-other);"></div> Other Waits</div>
    </div>
  </div>

  <div id="timeline-container">
    <canvas id="timeline-canvas"></canvas>
    <div id="tooltip"></div>
  </div>

  <div class="controls-bar">
    <div class="ctrl-group">
      <span><strong>Point 1 (T1):</strong></span>
      <input type="text" id="t1-input" class="ctrl-input" placeholder="HH24:MI:SS">
    </div>
    <div class="ctrl-group">
      <span><strong>Point 2 (T2):</strong></span>
      <input type="text" id="t2-input" class="ctrl-input" placeholder="HH24:MI:SS">
    </div>
    <div class="ctrl-group">
      <span>Window:</span>
      <span id="window-span" style="font-family: monospace; color: var(--accent); font-weight: 600;">0.000s</span>
    </div>
    <button id="btn-full" class="btn btn-outline">Full Trace</button>
    <button id="btn-apply" class="btn">Apply Points</button>
    <span style="color: var(--text-muted); font-size: 11.5px; margin-left: auto;">
      &bull; Click and drag horizontally on the timeline to pick any 2 points of time.
    </span>
  </div>
</div>

<!-- FEATURE 2: Summarized & Sequential Breakdown -->
<div class="card">
  <div class="tab-header">
    <button class="tab-btn active" onclick="switchTab('summary')">2a. Summarized SQL Activity</button>
    <button class="tab-btn" onclick="switchTab('sequential')">2b. Sequential Activity Stream &amp; Waits (Tree View)</button>
  </div>

  <!-- 2a. Summarized Form -->
  <div id="pane-summary" class="tab-pane active">
    <div style="margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
      <span id="summary-meta" style="color: var(--text-muted); font-size: 13px;">Displaying aggregated SQLs in selected range</span>
      <input type="text" id="summary-search" placeholder="Filter by SQL ID..." class="ctrl-input" style="width: 180px; text-align: left;">
    </div>
    <table class="data-table" id="summary-table">
      <thead>
        <tr>
          <th onclick="sortSummaryTable('sql_id')">SQL ID</th>
          <th onclick="sortSummaryTable('ela_us')">Total Elapsed Time</th>
          <th onclick="sortSummaryTable('parse_cnt')">Parse</th>
          <th onclick="sortSummaryTable('exec_cnt')">Exec</th>
          <th onclick="sortSummaryTable('fetch_cnt')">Fetch</th>
          <th onclick="sortSummaryTable('rows')">Rows</th>
          <th onclick="sortSummaryTable('wait_us')">Total Wait</th>
          <th>SQL Text Preview</th>
        </tr>
      </thead>
      <tbody id="summary-tbody"></tbody>
    </table>
  </div>

  <!-- 2b. Sequential Order -->
  <div id="pane-sequential" class="tab-pane">
    <div style="margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center;">
      <div style="display: flex; align-items: center; gap: 10px;">
        <span id="seq-meta" style="color: var(--text-muted); font-size: 13px;">Showing sequential activity</span>
        <button class="btn btn-outline" style="padding: 2px 8px; font-size: 11.5px;" onclick="expandAllTrees()">Expand All</button>
        <button class="btn btn-outline" style="padding: 2px 8px; font-size: 11.5px;" onclick="collapseAllTrees()">Collapse All</button>
      </div>
      <div style="display: flex; gap: 8px;">
        <select id="seq-filter-type" class="ctrl-input" style="width: 140px; text-align: left;">
          <option value="ALL">All Events</option>
          <option value="SQL">SQLs Only</option>
          <option value="WAIT">Waits Only</option>
          <option value="CLIENT">Client Waits Only</option>
        </select>
        <input type="text" id="seq-search" placeholder="Filter SQL / Event..." class="ctrl-input" style="width: 180px; text-align: left;">
      </div>
    </div>
    <table class="data-table" id="seq-table">
      <thead>
        <tr>
          <th>Time (Start)</th>
          <th>Wall Clock (HH24:MI:SS)</th>
          <th>Tree Hierarchy &amp; Operation</th>
          <th>Top-Level SQL ID</th>
          <th>Current SQL ID</th>
          <th>Duration &amp; Distribution</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody id="seq-tbody"></tbody>
    </table>
    <div class="pagination-bar">
      <span id="seq-count-label"></span>
      <div style="display: flex; gap: 6px;">
        <button id="seq-prev-btn" class="btn btn-outline">&larr; Prev</button>
        <button id="seq-next-btn" class="btn btn-outline">Next &rarr;</button>
      </div>
    </div>
  </div>
</div>

<div id="sql-hover-tooltip"></div>

<!-- Statement Modal -->
<div id="sql-modal" class="modal" onclick="closeModal(event)">
  <div class="modal-content" onclick="event.stopPropagation()">
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <h3 id="modal-sql-id" style="color: var(--accent);">SQL ID Details</h3>
      <button class="btn btn-outline" onclick="closeModal()">Close</button>
    </div>
    <div id="modal-sql-text" class="modal-text"></div>
  </div>
</div>

<script>
const COMPRESSED_B64 = "__COMPRESSED_PAYLOAD__";
let DATA = null;
let TOTAL_DUR_US = 0;
let BASE_EPOCH_MS = 0;

let selT1_us = 0;
let selT2_us = 0;
let isDragging = false;
let dragStartX = 0;

let summarySortCol = 'ela_us';
let summarySortAsc = false;

let seqPage = 1;
const SEQ_PAGE_SIZE = 100;
let filteredSeqIndices = [];

// Track unfolded top-level call IDs (Set of top_call_id numbers)
const unfoldedCallIds = new Set();

async function initData() {
  try {
    const binStr = atob(COMPRESSED_B64);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }
    const ds = new DecompressionStream('gzip');
    const writer = ds.writable.getWriter();
    writer.write(bytes);
    writer.close();

    const reader = ds.readable.getReader();
    const chunks = [];
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const totalLen = chunks.reduce((acc, c) => acc + c.length, 0);
    const decompressed = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
      decompressed.set(chunk, offset);
      offset += chunk.length;
    }
    const jsonStr = new TextDecoder().decode(decompressed);
    DATA = JSON.parse(jsonStr);

    TOTAL_DUR_US = DATA.summary.total_duration_us;
    BASE_EPOCH_MS = DATA.summary.base_epoch_ms;
    selT1_us = 0;
    selT2_us = TOTAL_DUR_US;

    document.getElementById('loading-cover').style.display = 'none';

    resizeCanvas();
    updateControls();
    refreshSummaryPane();
    refreshSequentialPane();
  } catch (err) {
    document.getElementById('loading-cover').innerHTML = `<h3 style="color:#f87171;">Decompression Error</h3><p>${err}</p>`;
  }
}

function usToWallDate(us) {
  return new Date(BASE_EPOCH_MS + Math.round(us / 1000));
}

function formatWallHMS(us) {
  const d = usToWallDate(us);
  const hh = String(d.getHours()).padStart(2, '0');
  const mi = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${hh}:${mi}:${ss}`;
}

function formatWallMS(us) {
  const d = usToWallDate(us);
  const mi = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${mi}:${ss}`;
}

function parseWallTimeToUs(str) {
  if (!str) return null;
  const parts = str.trim().split(':');
  if (parts.length < 2) return null;
  const h = parseInt(parts[0], 10);
  const m = parseInt(parts[1], 10);
  const secParts = (parts[2] || '0').split('.');
  const s = parseInt(secParts[0], 10);
  const ms = secParts[1] ? parseInt((secParts[1] + '000').slice(0, 3), 10) : 0;

  const baseDate = new Date(BASE_EPOCH_MS);
  const target = new Date(baseDate.getFullYear(), baseDate.getMonth(), baseDate.getDate(), h, m, s, ms);
  let diffMs = target.getTime() - BASE_EPOCH_MS;

  if (diffMs < 0 && TOTAL_DUR_US > 12 * 3600 * 1e6) {
    diffMs += 24 * 3600 * 1000;
  }
  return diffMs * 1000;
}

function getEventColor(catCode, name) {
  if (catCode === 0) {
    if (name === 'EXEC') return '#4ade80';
    if (name === 'PARSE') return '#c084fc';
    if (name === 'FETCH') return '#22d3ee';
    return '#94a3b8';
  }
  const n = name.toLowerCase();
  if (n.includes('sql*net message from client') || n.includes('rdbms ipc message')) return '#94a3b8';
  if (n.includes('read') || n.includes('write') || n.includes('scattered') || n.includes('sequential') || n.includes('direct path')) return '#60a5fa';
  if (n.includes('enq:') || n.includes('latch') || n.includes('buffer busy') || n.includes('row cache lock')) return '#f87171';
  return '#fbbf24';
}

function getEventBadge(catCode, name) {
  if (catCode === 0) {
    return `<span class="badge badge-${name}">${name}</span>`;
  }
  const n = name.toLowerCase();
  if (n.includes('sql*net message from client')) return `<span class="badge badge-WAIT-IDLE">CLIENT WAIT</span>`;
  if (n.includes('read') || n.includes('write') || n.includes('scattered') || n.includes('sequential')) return `<span class="badge badge-WAIT-IO">I/O WAIT</span>`;
  if (n.includes('enq:') || n.includes('latch')) return `<span class="badge badge-WAIT-LOCK">LOCK / LATCH</span>`;
  return `<span class="badge badge-WAIT">WAIT</span>`;
}

function formatDuration(us) {
  if (us < 1000) return us + ' µs';
  if (us < 1000000) return (us / 1000).toFixed(2) + ' ms';
  return (us / 1000000).toFixed(4) + ' s';
}

const canvas = document.getElementById('timeline-canvas');
const ctx = canvas.getContext('2d');
const container = document.getElementById('timeline-container');
const tooltip = document.getElementById('tooltip');

function resizeCanvas() {
  if (!DATA) return;
  const rect = container.getBoundingClientRect();
  canvas.width = rect.width * window.devicePixelRatio;
  canvas.height = 195 * window.devicePixelRatio;
  renderTimeline();
}
window.addEventListener('resize', resizeCanvas);

function renderTimeline() {
  if (!DATA) return;
  const w = canvas.width;
  const h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const topPadding = 28 * window.devicePixelRatio;
  const bottomPadding = 34 * window.devicePixelRatio;
  const trackH = (h - topPadding - bottomPadding) / 2;

  const ySql = topPadding;
  const yWait = topPadding + trackH;

  ctx.fillStyle = '#64748b';
  ctx.font = `${11 * window.devicePixelRatio}px monospace`;
  ctx.fillText("SQL CALLS (EXEC, PARSE, FETCH)", 10 * window.devicePixelRatio, ySql - 6 * window.devicePixelRatio);
  ctx.fillText("WAIT EVENTS (I/O, CLIENT, LOCKS)", 10 * window.devicePixelRatio, yWait - 6 * window.devicePixelRatio);

  ctx.strokeStyle = '#334155';
  ctx.lineWidth = 1 * window.devicePixelRatio;
  ctx.beginPath();
  ctx.moveTo(0, yWait);
  ctx.lineTo(w, yWait);
  ctx.stroke();

  const totalUs = TOTAL_DUR_US || 1;
  const evCount = DATA.events.length;

  for (let i = 0; i < evCount; i++) {
    const raw = DATA.events[i];
    const catCode = raw[0];
    const name = DATA.names[raw[1]];
    const start_us = raw[5];
    const ela_us = raw[6];

    const x1 = (start_us / totalUs) * w;
    const barW = Math.max(2 * window.devicePixelRatio, (ela_us / totalUs) * w);
    const color = getEventColor(catCode, name);

    ctx.fillStyle = color;
    if (catCode === 0) {
      ctx.fillRect(x1, ySql + 2, barW, trackH - 12);
    } else {
      ctx.fillRect(x1, yWait + 2, barW, trackH - 12);
    }
  }

  // Time Axis (MI:SS)
  const axisY = h - 22 * window.devicePixelRatio;
  ctx.strokeStyle = '#475569';
  ctx.beginPath();
  ctx.moveTo(0, axisY);
  ctx.lineTo(w, axisY);
  ctx.stroke();

  const numTicks = 8;
  ctx.fillStyle = '#94a3b8';
  ctx.textAlign = 'center';
  ctx.font = `${11 * window.devicePixelRatio}px monospace`;

  for (let i = 0; i <= numTicks; i++) {
    const tx = (i / numTicks) * w;
    const tickUs = (i / numTicks) * totalUs;
    const tickLabel = formatWallMS(tickUs);

    ctx.beginPath();
    ctx.moveTo(tx, axisY);
    ctx.lineTo(tx, axisY + 5 * window.devicePixelRatio);
    ctx.stroke();

    ctx.fillText(tickLabel, tx, axisY + 16 * window.devicePixelRatio);
  }

  // Selection Markers [T1, T2]
  const selX1 = (selT1_us / totalUs) * w;
  const selX2 = (selT2_us / totalUs) * w;

  ctx.fillStyle = 'rgba(56, 189, 248, 0.15)';
  ctx.fillRect(selX1, 0, selX2 - selX1, h);

  ctx.strokeStyle = '#38bdf8';
  ctx.lineWidth = 2 * window.devicePixelRatio;
  ctx.setLineDash([4 * window.devicePixelRatio, 3 * window.devicePixelRatio]);

  ctx.beginPath();
  ctx.moveTo(selX1, 0);
  ctx.lineTo(selX1, h);
  ctx.stroke();

  ctx.beginPath();
  ctx.moveTo(selX2, 0);
  ctx.lineTo(selX2, h);
  ctx.stroke();
  ctx.setLineDash([]);

  ctx.fillStyle = '#38bdf8';
  ctx.font = `bold ${11 * window.devicePixelRatio}px monospace`;
  ctx.textAlign = 'left';
  ctx.fillText(`T1: ${formatWallHMS(selT1_us)}`, Math.min(w - 90, selX1 + 4), 16 * window.devicePixelRatio);
  ctx.fillText(`T2: ${formatWallHMS(selT2_us)}`, Math.min(w - 90, selX2 + 4), 16 * window.devicePixelRatio);
}

// Interaction handling
container.addEventListener('mousedown', (e) => {
  const rect = canvas.getBoundingClientRect();
  isDragging = true;
  dragStartX = e.clientX - rect.left;
});

window.addEventListener('mousemove', (e) => {
  if (!DATA) return;
  const rect = canvas.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;

  if (isDragging) {
    const currentX = Math.max(0, Math.min(rect.width, mouseX));
    const xMin = Math.min(dragStartX, currentX);
    const xMax = Math.max(dragStartX, currentX);

    selT1_us = Math.round((xMin / rect.width) * TOTAL_DUR_US);
    selT2_us = Math.round((xMax / rect.width) * TOTAL_DUR_US);
    updateControls();
    renderTimeline();
    return;
  }

  if (mouseX >= 0 && mouseX <= rect.width && e.clientY >= rect.top && e.clientY <= rect.bottom) {
    const hoverUs = (mouseX / rect.width) * TOTAL_DUR_US;
    const hit = DATA.events.find(raw => hoverUs >= raw[5] && hoverUs <= (raw[5] + raw[6]));

    if (hit) {
      const catCode = hit[0];
      const name = DATA.names[hit[1]];
      const sql_id = hit[2] >= 0 ? DATA.sqls[hit[2]] : 'N/A';
      const top_sql = hit[3] >= 0 ? DATA.sqls[hit[3]] : 'N/A';
      const ela_us = hit[6];

      tooltip.style.display = 'block';
      tooltip.style.left = Math.min(window.innerWidth - 260, e.pageX + 15) + 'px';
      tooltip.style.top = (e.pageY + 15) + 'px';
      tooltip.innerHTML = `
        <strong>${name}</strong><br>
        Wall Clock: <strong>${formatWallHMS(hit[5])}</strong> (+${(hit[5]/1e6).toFixed(3)}s)<br>
        SQL ID: <code>${sql_id}</code> (Top: <code>${top_sql}</code>)<br>
        Elapsed: <strong>${formatDuration(ela_us)}</strong>
      `;
    } else {
      tooltip.style.display = 'none';
    }
  } else {
    tooltip.style.display = 'none';
  }
});

window.addEventListener('mouseup', () => {
  if (isDragging) {
    isDragging = false;
    triggerSelectionUpdate();
  }
});

function updateControls() {
  document.getElementById('t1-input').value = formatWallHMS(selT1_us);
  document.getElementById('t2-input').value = formatWallHMS(selT2_us);
  document.getElementById('window-span').textContent = ((selT2_us - selT1_us) / 1e6).toFixed(3) + 's';
}

function triggerSelectionUpdate() {
  updateControls();
  refreshSummaryPane();
  refreshSequentialPane();
}

document.getElementById('btn-apply').addEventListener('click', () => {
  const v1 = parseWallTimeToUs(document.getElementById('t1-input').value);
  const v2 = parseWallTimeToUs(document.getElementById('t2-input').value);
  if (v1 !== null && v2 !== null) {
    selT1_us = Math.max(0, Math.min(v1, v2));
    selT2_us = Math.min(TOTAL_DUR_US, Math.max(v1, v2));
    renderTimeline();
    triggerSelectionUpdate();
  }
});

document.getElementById('t1-input').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') document.getElementById('btn-apply').click();
});
document.getElementById('t2-input').addEventListener('keypress', (e) => {
  if (e.key === 'Enter') document.getElementById('btn-apply').click();
});

document.getElementById('btn-full').addEventListener('click', () => {
  selT1_us = 0;
  selT2_us = TOTAL_DUR_US;
  renderTimeline();
  triggerSelectionUpdate();
});

// Feature 2a: Summary Table
function refreshSummaryPane() {
  if (!DATA) return;
  const summaryMap = {};

  for (let i = 0; i < DATA.events.length; i++) {
    const raw = DATA.events[i];
    const catCode = raw[0];
    const name = DATA.names[raw[1]];
    const sql_id = raw[2] >= 0 ? DATA.sqls[raw[2]] : 'N/A';
    const start_us = raw[5];
    const ela_us = raw[6];
    const end_us = start_us + ela_us;

    if (end_us >= selT1_us && start_us <= selT2_us) {
      const overlapStart = Math.max(start_us, selT1_us);
      const overlapEnd = Math.min(end_us, selT2_us);
      const effectiveEla = Math.max(0, overlapEnd - overlapStart);

      if (catCode === 0) {
        if (!summaryMap[sql_id]) {
          summaryMap[sql_id] = {
            sql_id: sql_id,
            ela_us: 0,
            parse_cnt: 0,
            exec_cnt: 0,
            fetch_cnt: 0,
            rows: 0,
            wait_us: 0
          };
        }
        summaryMap[sql_id].ela_us += effectiveEla;
        if (name === 'PARSE') summaryMap[sql_id].parse_cnt++;
        if (name === 'EXEC') summaryMap[sql_id].exec_cnt++;
        if (name === 'FETCH') summaryMap[sql_id].fetch_cnt++;
        summaryMap[sql_id].rows += raw[8];
      } else if (catCode === 1 && summaryMap[sql_id]) {
        summaryMap[sql_id].wait_us += effectiveEla;
      }
    }
  }

  let summaryList = Object.values(summaryMap);
  const q = document.getElementById('summary-search').value.trim().toLowerCase();
  if (q) {
    summaryList = summaryList.filter(s => s.sql_id.toLowerCase().includes(q));
  }

  summaryList.sort((a, b) => {
    let vA = a[summarySortCol];
    let vB = b[summarySortCol];
    return summarySortAsc ? (vA > vB ? 1 : -1) : (vA < vB ? 1 : -1);
  });

  const tbody = document.getElementById('summary-tbody');
  tbody.innerHTML = '';

  document.getElementById('summary-meta').textContent =
    `Found ${summaryList.length} distinct SQL statement(s) active in window [${formatWallHMS(selT1_us)} - ${formatWallHMS(selT2_us)}]`;

  if (summaryList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">No SQL activity found in this time range.</td></tr>`;
    return;
  }

  const maxEla = Math.max(...summaryList.map(x => x.ela_us), 1);

  summaryList.forEach(item => {
    const pct = ((item.ela_us / maxEla) * 100).toFixed(1);
    const sqlText = DATA.sql_texts[item.sql_id] || '(No text captured in cursor)';

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="sql-id-code" onmouseenter="showSqlHover(event, '${item.sql_id}')" onmouseleave="hideSqlHover()" onclick="showSqlModal('${item.sql_id}')">${item.sql_id}</span></td>
      <td>
        <div class="bar-container">
          <div class="bar-outer">
            <div class="bar-inner" style="width: ${pct}%; background: var(--sql-exec);"></div>
          </div>
          <span class="bar-label">${formatDuration(item.ela_us)}</span>
        </div>
      </td>
      <td><strong>${item.parse_cnt}</strong></td>
      <td><strong>${item.exec_cnt}</strong></td>
      <td><strong>${item.fetch_cnt}</strong></td>
      <td>${item.rows.toLocaleString()}</td>
      <td style="color: var(--wait-other);">${formatDuration(item.wait_us)}</td>
      <td>
        <div style="max-width: 420px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 11.5px; color: var(--text-muted);">
          ${htmlEscape(sqlText)}
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function sortSummaryTable(col) {
  if (summarySortCol === col) {
    summarySortAsc = !summarySortAsc;
  } else {
    summarySortCol = col;
    summarySortAsc = false;
  }
  refreshSummaryPane();
}
document.getElementById('summary-search').addEventListener('input', refreshSummaryPane);

// Feature 2b: Sequential Order Tree Activity
function toggleCallTree(topCallId) {
  if (unfoldedCallIds.has(topCallId)) {
    unfoldedCallIds.delete(topCallId);
  } else {
    unfoldedCallIds.add(topCallId);
  }
  renderSequentialTable();
}

function expandAllTrees() {
  for (let i = 0; i < DATA.events.length; i++) {
    const raw = DATA.events[i];
    if (raw[9] === 1 && raw[11] > 0) {
      unfoldedCallIds.add(raw[10]);
    }
  }
  renderSequentialTable();
}

function collapseAllTrees() {
  unfoldedCallIds.clear();
  renderSequentialTable();
}

function refreshSequentialPane() {
  if (!DATA) return;
  const typeFilter = document.getElementById('seq-filter-type').value;
  const q = document.getElementById('seq-search').value.trim().toLowerCase();

  filteredSeqIndices = [];
  for (let i = 0; i < DATA.events.length; i++) {
    const raw = DATA.events[i];
    const start_us = raw[5];
    const ela_us = raw[6];
    const end_us = start_us + ela_us;

    if (end_us >= selT1_us && start_us <= selT2_us) {
      const catCode = raw[0];
      const name = DATA.names[raw[1]];
      const sql_id = raw[2] >= 0 ? DATA.sqls[raw[2]] : 'N/A';
      const top_sql = raw[3] >= 0 ? DATA.sqls[raw[3]] : 'N/A';

      if (typeFilter === 'SQL' && catCode !== 0) continue;
      if (typeFilter === 'WAIT' && catCode !== 1) continue;
      if (typeFilter === 'CLIENT' && !name.toLowerCase().includes('client')) continue;

      if (q) {
        const matchSql = sql_id.toLowerCase().includes(q) || top_sql.toLowerCase().includes(q);
        const matchName = name.toLowerCase().includes(q);
        if (!matchSql && !matchName) continue;
      }
      filteredSeqIndices.push(i);
    }
  }

  seqPage = 1;
  renderSequentialTable();
}

function renderSequentialTable() {
  const tbody = document.getElementById('seq-tbody');
  tbody.innerHTML = '';

  const visibleIndices = [];
  for (let k = 0; k < filteredSeqIndices.length; k++) {
    const idx = filteredSeqIndices[k];
    const raw = DATA.events[idx];
    const isTop = (raw[9] === 1);
    const topCallId = raw[10];

    if (isTop) {
      visibleIndices.push(idx);
    } else if (unfoldedCallIds.has(topCallId)) {
      visibleIndices.push(idx);
    }
  }

  const total = visibleIndices.length;
  const startIdx = (seqPage - 1) * SEQ_PAGE_SIZE;
  const endIdx = Math.min(startIdx + SEQ_PAGE_SIZE, total);
  const pageIndices = visibleIndices.slice(startIdx, endIdx);

  document.getElementById('seq-meta').textContent =
    `Sequential Stream: ${total.toLocaleString()} visible row(s)`;
  document.getElementById('seq-count-label').textContent =
    total > 0 ? `Showing ${startIdx + 1} - ${endIdx} of ${total.toLocaleString()}` : '0 events';

  document.getElementById('seq-prev-btn').disabled = (seqPage <= 1);
  document.getElementById('seq-next-btn').disabled = (endIdx >= total);

  if (pageIndices.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No sequential activity matching filter criteria.</td></tr>`;
    return;
  }

  const maxDur = Math.max(...pageIndices.map(idx => DATA.events[idx][6]), 1);

  pageIndices.forEach(idx => {
    const raw = DATA.events[idx];
    const catCode = raw[0];
    const name = DATA.names[raw[1]];
    const sql_id = raw[2] >= 0 ? DATA.sqls[raw[2]] : 'N/A';
    const top_sql = raw[3] >= 0 ? DATA.sqls[raw[3]] : 'N/A';
    const tree_depth = raw[4];
    const start_us = raw[5];
    const ela_us = raw[6];
    const cpu_us = raw[7];
    const rows = raw[8];
    const isTop = (raw[9] === 1);
    const topCallId = raw[10];
    const childCount = raw[11];

    const color = getEventColor(catCode, name);
    const badge = getEventBadge(catCode, name);
    const pct = Math.max(3, (ela_us / maxDur) * 100).toFixed(1);

    const relSec = (start_us / 1e6).toFixed(4);
    const wallHMS = formatWallHMS(start_us);

    let hierarchyHtml = '';
    if (isTop) {
      if (childCount > 0) {
        const isUnfolded = unfoldedCallIds.has(topCallId);
        const arrow = isUnfolded ? '&#9660;' : '&#9654;';
        hierarchyHtml = `
          <button class="tree-toggle-btn" onclick="toggleCallTree(${topCallId})">
            <span>${arrow}</span> <span>${childCount} sub-op${childCount > 1 ? 's' : ''}</span>
          </button>
          ${badge}
          <span style="font-weight: 600; margin-left: 2px;">${htmlEscape(name)}</span>
        `;
      } else {
        hierarchyHtml = `
          ${badge}
          <span style="font-weight: 500; margin-left: 2px;">${htmlEscape(name)}</span>
        `;
      }
    } else {
      let branchLines = '&nbsp;'.repeat(Math.max(0, (tree_depth - 1) * 3)) + '└──&nbsp;';
      let depBadge = (catCode === 0 && tree_depth > 0) ? `<span class="badge badge-dep-child">dep ${tree_depth}</span>` : '';
      hierarchyHtml = `
        <span class="tree-branch">${branchLines}</span>
        ${depBadge}
        ${badge}
        <span style="font-weight: 400; margin-left: 2px;">${htmlEscape(name)}</span>
      `;
    }

    let details = '';
    if (catCode === 0) {
      details = `cpu=${formatDuration(cpu_us)} &bull; rows=${rows.toLocaleString()}`;
    }

    const tr = document.createElement('tr');
    tr.className = isTop ? 'row-top' : 'row-child';

    tr.innerHTML = `
      <td>
        <span style="font-family: monospace; font-weight: 600; color: #f1f5f9;">+${relSec}s</span>
      </td>
      <td style="font-family: monospace; font-weight: 600; color: var(--accent); font-size: 12px;">${wallHMS}</td>
      <td>
        <div class="tree-cell">
          ${hierarchyHtml}
        </div>
      </td>
      <td>
        ${top_sql !== 'N/A' ? `<span class="sql-id-code" onmouseenter="showSqlHover(event, '${top_sql}')" onmouseleave="hideSqlHover()" onclick="showSqlModal('${top_sql}')">${top_sql}</span>` : '<span style="color:#64748b;">N/A</span>'}
      </td>
      <td>
        ${sql_id !== 'N/A' ? `<span class="sql-id-code" style="color: #93c5fd;" onmouseenter="showSqlHover(event, '${sql_id}')" onmouseleave="hideSqlHover()" onclick="showSqlModal('${sql_id}')">${sql_id}</span>` : '<span style="color:#64748b;">—</span>'}
      </td>
      <td>
        <div class="bar-container">
          <div class="bar-outer">
            <div class="bar-inner" style="width: ${pct}%; background: ${color};"></div>
          </div>
          <span class="bar-label">${formatDuration(ela_us)}</span>
        </div>
      </td>
      <td style="font-size: 11.5px; color: var(--text-muted); font-family: monospace;">${details}</td>
    `;
    tbody.appendChild(tr);
  });
}

document.getElementById('seq-prev-btn').addEventListener('click', () => {
  if (seqPage > 1) { seqPage--; renderSequentialTable(); }
});
document.getElementById('seq-next-btn').addEventListener('click', () => {
  if (seqPage * SEQ_PAGE_SIZE < filteredSeqIndices.length) { seqPage++; renderSequentialTable(); }
});
document.getElementById('seq-filter-type').addEventListener('change', refreshSequentialPane);
document.getElementById('seq-search').addEventListener('input', refreshSequentialPane);

const sqlTooltip = document.getElementById('sql-hover-tooltip');
function showSqlHover(e, sqlId) {
  const text = DATA.sql_texts[sqlId];
  if (!text) return;
  sqlTooltip.style.display = 'block';
  sqlTooltip.style.left = Math.min(window.innerWidth - 450, e.pageX + 12) + 'px';
  sqlTooltip.style.top = (e.pageY + 12) + 'px';
  sqlTooltip.textContent = text;
}

function hideSqlHover() {
  sqlTooltip.style.display = 'none';
}

function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

  if (tab === 'summary') {
    document.querySelector("button[onclick*='summary']").classList.add('active');
    document.getElementById('pane-summary').classList.add('active');
  } else {
    document.querySelector("button[onclick*='sequential']").classList.add('active');
    document.getElementById('pane-sequential').classList.add('active');
  }
}

function showSqlModal(sqlId) {
  const text = DATA.sql_texts[sqlId] || 'No statement text captured for this SQL ID.';
  document.getElementById('modal-sql-id').textContent = 'SQL ID: ' + sqlId;
  document.getElementById('modal-sql-text').textContent = text;
  document.getElementById('sql-modal').style.display = 'flex';
}

function closeModal(e) {
  document.getElementById('sql-modal').style.display = 'none';
}

function htmlEscape(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

window.addEventListener('DOMContentLoaded', initData);
</script>
</body>
</html>
"""


def generate_html_report(data, output_path):
    """
    Serializes and compresses the payload using gzip + base64.
    Replaces template markers with formatted values and compressed payload.
    """
    raw_json = json.dumps(data).encode("utf-8")
    compressed_bytes = gzip.compress(raw_json, compresslevel=9)
    b64_payload = base64.b64encode(compressed_bytes).decode("ascii")

    dur_sec = "{:.3f}".format(data["summary"]["total_duration_us"] / 1e6)
    total_events_str = "{:,}".format(data["summary"]["total_events"])

    rendered = (
        HTML_TEMPLATE
        .replace("__FILE_NAME__", html.escape(data["summary"]["file_name"]))
        .replace("__TOTAL_EVENTS__", total_events_str)
        .replace("__DURATION_SEC__", dur_sec)
        .replace("__START_WALL__", data["summary"]["start_wall_hms"])
        .replace("__END_WALL__", data["summary"]["end_wall_hms"])
        .replace("__COMPRESSED_PAYLOAD__", b64_payload)
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)


def main():
    parser = argparse.ArgumentParser(
        description="Parse Oracle DB SQL trace files (10046) and generate a compressed, interactive HTML report."
    )
    parser.add_argument("tracefile", help="Path to Oracle .trc trace file")
    parser.add_argument(
        "-o", "--output", help="Output HTML file path (default: <tracefile>.html)", default=None
    )

    args = parser.parse_args()

    if not os.path.isfile(args.tracefile):
        print("Error: Trace file not found: {}".format(args.tracefile), file=sys.stderr)
        sys.exit(1)

    out_file = args.output if args.output else "{}.html".format(os.path.splitext(args.tracefile)[0])

    print("[*] Parsing Oracle trace file: {} ...".format(args.tracefile))
    parsed_data = parse_trace_file(args.tracefile)

    if not parsed_data or not parsed_data["events"]:
        print("[-] No valid SQL or WAIT trace events found in file. Ensure TIMED_STATISTICS was enabled.", file=sys.stderr)
        sys.exit(1)

    print("[+] Successfully parsed {:,} events.".format(parsed_data["summary"]["total_events"]))
    print("[*] Compressing payload and generating report: {} ...".format(out_file))
    generate_html_report(parsed_data, out_file)

    file_size_kb = os.path.getsize(out_file) / 1024
    print("[✓] Done! Generated '{}' ({:.1f} KB). Open in any web browser.".format(out_file, file_size_kb))


if __name__ == "__main__":
    main()
