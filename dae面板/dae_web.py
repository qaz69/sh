#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lightweight DAE web console."""

import argparse
import socket
import threading
import hmac
import json
import os
import platform
import re
import shutil
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.parse import unquote

import dae as dae_manager


APP_TITLE = "DAE Web Console"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
NODE_PROBE_TIMEOUT = 1.2
NODE_PROBE_CACHE_TTL = 15
NODE_PROBE_MAX_WORKERS = 6
NODE_PING_TIMEOUT = 1
SITE_PROBE_CACHE_TTL = 30
SITE_PROBE_TIMEOUT = 6
SITE_PROBE_CONNECT_TIMEOUT = 3

NODE_PROBE_CACHE = {}
NODE_PROBE_LOCK = threading.Lock()
SITE_PROBE_CACHE = {}
SITE_PROBE_LOCK = threading.Lock()

SITE_PROBE_TARGETS = {
  "baidu": ("Baidu", "https://www.baidu.com/"),
  "google": ("Google", "https://www.google.com/generate_204"),
  "youtube": ("YouTube", "https://www.youtube.com/generate_204"),
}

HTML_PAGE = r"""<!doctype html>
<html lang="zh-CN" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DAE Console</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='%230d6ccf'/><stop offset='1' stop-color='%230754a8'/></linearGradient></defs><rect x='6' y='6' width='52' height='52' rx='8' fill='url(%23g)'/><path d='M21 18h11c8.84 0 16 7.16 16 16s-7.16 16-16 16H21V18Z' fill='none' stroke='%23ffffff' stroke-width='6' stroke-linejoin='miter'/><path d='M28 26h8M28 34h10M28 42h8' fill='none' stroke='%23bfe0ff' stroke-width='4' stroke-linecap='square'/></svg>">
<script>document.documentElement.setAttribute('data-booting','1');</script>
<style>
:root{
  --r:3px;
  --r-lg:4px;
  --gap:8px;
  --font:"MiSans","HarmonyOS Sans SC","Noto Sans SC","PingFang SC","Segoe UI Variable Text","Segoe UI",ui-sans-serif,sans-serif;
}

[data-theme="light"]{
  color-scheme:light;
  --bg:#eef2f7;
  --bg-grad-1:#ffffff;
  --bg-grad-2:#e8eef7;
  --sf:#ffffff;
  --sf2:#f6f8fc;
  --sf3:#edf2f9;
  --bd:rgba(22,34,54,.12);
  --bd2:rgba(22,34,54,.2);
  --tx:#132033;
  --tx2:#425066;
  --tx3:#6f7d93;
  --acc:#0d6ccf;
  --acc-h:#0b5db2;
  --acc-bg:rgba(13,108,207,.11);
  --acc-br:rgba(13,108,207,.26);
  --good:#1f7a3d;
  --good-bg:rgba(31,122,61,.12);
  --warn:#8a5b06;
  --warn-bg:rgba(138,91,6,.12);
  --bad:#b22b2b;
  --bad-bg:rgba(178,43,43,.11);
  --shadow:0 2px 8px rgba(16,30,54,.07);
  --shadow-lg:0 10px 30px rgba(16,30,54,.14);
  --tb:rgba(244,248,253,.86);
}

[data-theme="dark"]{
  color-scheme:dark;
  --bg:#111821;
  --bg-grad-1:#182332;
  --bg-grad-2:#111821;
  --sf:#17202d;
  --sf2:#1e2a3a;
  --sf3:#263447;
  --bd:rgba(198,215,238,.14);
  --bd2:rgba(198,215,238,.24);
  --tx:#e7eefb;
  --tx2:#b6c4db;
  --tx3:#8797b0;
  --acc:#64b0ff;
  --acc-h:#7ec0ff;
  --acc-bg:rgba(100,176,255,.16);
  --acc-br:rgba(100,176,255,.34);
  --good:#7dd69b;
  --good-bg:rgba(125,214,155,.14);
  --warn:#f0c56d;
  --warn-bg:rgba(240,197,109,.14);
  --bad:#f08b8b;
  --bad-bg:rgba(240,139,139,.13);
  --shadow:0 2px 10px rgba(0,0,0,.35);
  --shadow-lg:0 12px 32px rgba(0,0,0,.44);
  --tb:rgba(18,28,40,.86);
}

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:14px;-webkit-text-size-adjust:100%;overflow-y:scroll;scrollbar-gutter:stable both-edges}
html[data-booting="1"] body{opacity:0}
*{scrollbar-width:thin;scrollbar-color:var(--bd2) var(--sf2)}
*::-webkit-scrollbar{width:10px;height:10px}
*::-webkit-scrollbar-track{background:var(--sf2)}
*::-webkit-scrollbar-thumb{background:var(--sf3);border:2px solid var(--sf2);border-radius:3px}
*::-webkit-scrollbar-thumb:hover{background:var(--tx3)}
body{
  font-family:var(--font);
  font-size:12px;line-height:1.48;
  color:var(--tx);
  background:
    radial-gradient(900px 420px at 10% -5%,var(--bg-grad-1),transparent 72%),
    radial-gradient(860px 380px at 100% 0%,var(--bg-grad-2),transparent 74%),
    var(--bg);
  min-height:100vh;
  overflow-x:hidden;
  transition:opacity .08s linear;
}

.titlebar{
  position:sticky;top:0;z-index:200;
  min-height:42px;
  display:flex;align-items:center;gap:8px;
  padding:6px 12px;
  background:var(--tb);
  backdrop-filter:blur(16px) saturate(145%);
  -webkit-backdrop-filter:blur(16px) saturate(145%);
  border-bottom:1px solid var(--bd);
}
.tb-icon{color:var(--acc);flex-shrink:0;display:flex;align-items:center}
.tb-icon svg{width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:1.7}
.tb-name{font-size:12px;font-weight:650;color:var(--tx);letter-spacing:.01em}
.tb-sep{width:1px;height:15px;background:var(--bd2);flex-shrink:0}
.svc-chip{
  display:inline-flex;align-items:center;gap:6px;
  height:24px;padding:0 9px;border-radius:3px;
  font-size:11px;font-weight:650;
  background:var(--good-bg);color:var(--good);
  border:1px solid rgba(31,122,61,.28);
  transition:background .2s,color .2s,border-color .2s;
}
.svc-chip.warn{background:var(--warn-bg);color:var(--warn);border-color:rgba(138,91,6,.3)}
.svc-chip.bad{background:var(--bad-bg);color:var(--bad);border-color:rgba(178,43,43,.3)}
.chip-dot{
  width:6px;height:6px;border-radius:50%;background:currentColor;
  animation:blink 2.2s ease-in-out infinite;
}
.svc-chip.warn .chip-dot,.svc-chip.bad .chip-dot{animation:none}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
.tb-sp{flex:1;min-width:0}
.tb-caption{
  display:inline-flex;align-items:center;
  min-height:24px;padding:0 9px;border-radius:3px;
  font-size:10.5px;font-weight:600;
  color:var(--tx3);background:var(--sf2);border:1px solid var(--bd);
  white-space:nowrap;
}
.tb-actions{display:flex;align-items:center;gap:6px}
.tb-btn{
  width:30px;height:30px;
  display:flex;align-items:center;justify-content:center;
  border-radius:3px;border:1px solid var(--bd);
  background:var(--sf2);color:var(--tx2);cursor:pointer;
  transition:background .14s,border-color .14s,color .14s,transform .12s;
  flex-shrink:0;
}
.tb-btn:hover{background:var(--sf3);border-color:var(--bd2);color:var(--tx)}
.tb-btn:active{transform:translateY(1px)}
.tb-btn svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:1.7}
.tb-btn.active{background:var(--acc-bg);border-color:var(--acc-br);color:var(--acc)}

.token-wrap{position:relative;display:flex;align-items:center}
.token-wrap svg{
  position:absolute;left:8px;width:12px;height:12px;
  fill:none;stroke:var(--tx3);stroke-width:1.7;pointer-events:none;
}
.token-field,.num-field{
  font:inherit;font-size:12px;
  height:30px;padding:0 10px 0 27px;
  border:1px solid var(--bd);border-radius:3px;
  background:var(--sf);color:var(--tx);outline:none;
  transition:border-color .15s,box-shadow .15s,background .15s;
}
.num-field{padding:0 8px;width:72px}
.token-field{width:150px}
.token-field:focus,.num-field:focus{
  border-color:var(--acc);
  box-shadow:0 0 0 3px var(--acc-bg);
  background:var(--sf2);
}
.token-field::placeholder{color:var(--tx3)}

.shell{
  max-width:1040px;margin:0 auto;
  padding:12px 12px 32px;
  display:flex;flex-direction:column;gap:var(--gap);
}

.card{
  background:var(--sf);
  border:1px solid var(--bd);
  border-radius:var(--r-lg);
  box-shadow:var(--shadow);
  overflow:hidden;
}

.hero{
  position:relative;
  padding:12px;
  overflow:hidden;
}
.hero::before{
  content:"";
  position:absolute;inset:0;
  background:
    radial-gradient(560px 220px at 0% 0%,rgba(13,108,207,.14),transparent 72%),
    linear-gradient(135deg,rgba(255,255,255,.22),transparent 42%);
  pointer-events:none;
}
.hero > *{position:relative;z-index:1}
.hero-grid{
  display:grid;
  grid-template-columns:minmax(0,1fr);
  gap:8px;
  margin-bottom:10px;
}
.hero-main,.hero-side{
  min-width:0;
  border:1px solid var(--bd);
  border-radius:4px;
  background:linear-gradient(180deg,var(--sf2),rgba(255,255,255,.02));
  box-shadow:inset 0 1px 0 rgba(255,255,255,.08);
}
.hero-main{padding:12px 13px}
.hero-side{
  padding:0;
  display:none;
}
.hero-left{display:flex;flex-direction:column;gap:8px}
.hero-top{
  display:flex;align-items:flex-start;justify-content:space-between;gap:10px;
}
.hero-copy{
  min-width:0;
  display:flex;flex-direction:column;gap:8px;
}
.hero-badge-row{
  display:flex;align-items:center;gap:6px;flex-wrap:wrap;
}
.hero-eyebrow{
  display:inline-flex;align-items:center;
  min-height:26px;padding:0 10px;
  width:max-content;max-width:100%;
  border-radius:3px;
  border:1px solid var(--acc-br);
  background:var(--acc-bg);color:var(--acc);
  font-size:10.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
}
.hero-version{
  display:inline-flex;align-items:center;
  min-height:26px;padding:0 8px;
  max-width:100%;
  border:1px solid var(--bd);
  border-radius:3px;
  background:var(--sf);
  color:var(--tx2);
  font-size:10px;font-weight:600;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.hero-title{
  display:block;
  width:auto;max-width:none;min-height:auto;padding:0;
  border:none;background:none;
  color:var(--tx);
  font-size:22px;line-height:1.08;font-weight:760;letter-spacing:-.025em;
}
.hero-summary{
  max-width:64ch;
  color:var(--tx3);
  font-size:11px;line-height:1.45;
}
.hero-pills{display:flex;flex-wrap:wrap;gap:7px}
.hero-pill{
  display:inline-flex;align-items:center;
  min-height:25px;padding:0 9px;
  border-radius:3px;border:1px solid var(--bd);
  background:var(--sf);color:var(--tx2);
  font-size:11px;font-weight:600;
}
.hero-kpis{
  display:grid;
  grid-template-columns:repeat(6,minmax(0,1fr));
  gap:4px;
}
.hero-kpi{
  min-width:0;
  min-height:46px;
  padding:5px 6px;
  border-radius:3px;
  border:1px solid var(--bd);
  background:linear-gradient(180deg,var(--sf),var(--sf2));
  display:flex;flex-direction:column;gap:3px;
  contain:layout paint style;
  transition:background .14s,border-color .14s,box-shadow .14s,transform .14s;
}
.hero-kpi-head{display:flex;align-items:center;justify-content:space-between;gap:4px}
.hero-kpi-meta{display:flex;align-items:center;gap:4px;min-width:0;line-height:1}
.hero-kpi-glyph{
  width:10px;height:10px;flex-shrink:0;
  display:inline-flex;align-items:center;justify-content:center;
  color:var(--tx3);
}
.hero-kpi-glyph svg{width:10px;height:10px;display:block;fill:none;stroke:currentColor;stroke-width:1.6}
.hero-kpi-label{
  font-size:8px;letter-spacing:.02em;text-transform:uppercase;color:var(--tx3);
  line-height:1;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.hero-kpi-value{
  display:block;
  font-size:10.5px;line-height:1.15;font-weight:700;
  color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  font-variant-numeric:tabular-nums;
  min-height:1.15em;
}
.hero-kpi-icon{
  width:10px;height:10px;flex-shrink:0;color:var(--tx3);
  display:inline-flex;align-items:center;justify-content:center
}
.hero-kpi-icon svg{width:10px;height:10px;display:block;fill:none;stroke:currentColor;stroke-width:1.7}
.hero-kpi.refreshable{cursor:pointer}
.hero-kpi:hover{transform:translateY(-1px);box-shadow:var(--shadow)}
.hero-kpi.refreshable:hover{background:var(--sf3);border-color:var(--bd2);box-shadow:var(--shadow)}
.hero-kpi[data-card-id="uptime"] .hero-kpi-value,
.hero-kpi[data-card-id="memory"] .hero-kpi-value,
.hero-kpi[data-card-id="kernel-version"] .hero-kpi-value,
.hero-kpi[data-card-id="baidu"] .hero-kpi-value,
.hero-kpi[data-card-id="google"] .hero-kpi-value,
.hero-kpi[data-card-id="youtube"] .hero-kpi-value{min-width:7ch}
.hero-kpi.accent{border-color:var(--acc-br);background:var(--acc-bg)}
.hero-kpi.accent .hero-kpi-value{color:var(--acc)}
.hero-kpi.fast{border-color:rgba(31,122,61,.32);background:var(--good-bg)}
.hero-kpi.fast .hero-kpi-value{color:var(--good)}
.hero-kpi.warn{border-color:rgba(138,91,6,.32);background:var(--warn-bg)}
.hero-kpi.warn .hero-kpi-value{color:var(--warn)}
.hero-kpi.bad{border-color:rgba(178,43,43,.32);background:var(--bad-bg)}
.hero-kpi.bad .hero-kpi-value{color:var(--bad)}
.hero-kpi.fail{border-color:rgba(178,43,43,.32);background:var(--bad-bg)}
.hero-kpi.fail .hero-kpi-value,.hero-kpi.muted .hero-kpi-value{color:var(--tx2)}
.hero-btns{display:flex;flex-wrap:wrap;gap:7px;justify-content:flex-end}

.btn{
  display:inline-flex;align-items:center;gap:5px;
  font:inherit;font-size:11.5px;font-weight:560;
  height:28px;padding:0 11px;
  border-radius:2px;border:1px solid transparent;
  cursor:pointer;
  transition:background .14s,border-color .14s,color .14s,transform .12s,opacity .1s;
  white-space:nowrap;line-height:1;
}
.btn svg{width:12px;height:12px;flex-shrink:0;fill:none;stroke:currentColor;stroke-width:2}
.btn:active{transform:translateY(1px)}
.btn:disabled{opacity:.5;cursor:wait;transform:none}
.btn-accent{background:var(--acc);border-color:var(--acc-h);color:#fff}
.btn-accent:hover:not(:disabled){background:var(--acc-h)}
.btn-success{background:var(--good-bg);color:var(--good);border-color:rgba(31,122,61,.3)}
.btn-success:hover:not(:disabled){background:rgba(31,122,61,.18)}
.btn-warn{background:var(--warn-bg);color:var(--warn);border-color:rgba(138,91,6,.3)}
.btn-warn:hover:not(:disabled){background:rgba(138,91,6,.18)}
.btn-danger{background:var(--bad-bg);color:var(--bad);border-color:rgba(178,43,43,.3)}
.btn-danger:hover:not(:disabled){background:rgba(178,43,43,.18)}
.btn-subtle{background:var(--sf2);color:var(--tx2);border-color:var(--bd)}
.btn-subtle:hover:not(:disabled){background:var(--sf3);border-color:var(--bd2);color:var(--tx)}
.btn[data-priority="high"]{
  box-shadow:0 10px 24px rgba(13,108,207,.16);
  transform:translateY(-1px);
}
.btn[data-priority="low"]{
  background:var(--sf2)!important;
  color:var(--tx2)!important;
  border-color:var(--bd)!important;
  box-shadow:none;
  opacity:.82;
}
.btn[data-priority="off"]{opacity:.5;filter:saturate(.7)}

.sec{padding:10px}
.sec-h{
  display:flex;align-items:center;justify-content:space-between;gap:7px;
  margin-bottom:6px;
}
.sec-h h2{
  display:inline-flex;align-items:center;gap:6px;
  font-size:10.5px;font-weight:700;
  letter-spacing:.08em;text-transform:uppercase;color:var(--tx3);
}
.sec-icon{
  display:inline-flex;align-items:center;flex-shrink:0;
  width:14px;height:14px;color:var(--tx3);
}
.sec-icon svg{width:14px;height:14px;display:block;fill:none;stroke:currentColor;stroke-width:1.7}
.sec-tools{display:flex;align-items:center;gap:6px}

.sec-h.toggle-h{
  cursor:pointer;user-select:none;
  margin:-4px -6px 0;
  min-height:36px;
  padding:7px 9px;
  border-radius:2px;
}
.sec-h.toggle-h:hover{background:var(--sf2)}
.sec-h.toggle-h:hover h2{color:var(--tx2)}
.toggle-chevron{
  display:flex;align-items:center;color:var(--tx3);
  transition:transform .2s ease;
}
.toggle-chevron svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2}
.card.collapsed .toggle-chevron{transform:rotate(-90deg)}
.collapsible-body{
  display:grid;grid-template-rows:1fr;
  transition:grid-template-rows .2s ease;
  overflow:hidden;
}
.card.collapsed .collapsible-body{grid-template-rows:0fr}
.collapsible-body > .collapsible-inner{
  overflow:hidden;min-height:0;
  padding-top:7px;
}

.panel-shell{
  border:1px solid var(--bd);
  border-radius:4px;
  background:linear-gradient(180deg,var(--sf2),var(--sf));
  padding:9px;
}
.panel-head{
  display:flex;align-items:flex-start;justify-content:space-between;gap:8px;
  margin-bottom:7px;
}
.panel-eyebrow{
  font-size:9.5px;font-weight:700;letter-spacing:.06em;
  text-transform:uppercase;color:var(--tx3);
}
.panel-title{
  margin-top:3px;
  font-size:12px;font-weight:700;color:var(--tx);
}
.panel-meta{
  display:inline-flex;align-items:center;
  min-height:24px;padding:0 8px;
  border-radius:3px;border:1px solid var(--bd);
  background:var(--sf);color:var(--tx3);
  font-size:10px;font-weight:600;white-space:nowrap;
}
.nodes-workbench{
  display:grid;
  grid-template-columns:minmax(0,1.2fr) minmax(280px,.9fr);
  gap:8px;
}
.nodes{
  display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;
  max-height:272px;min-height:272px;overflow:auto;align-content:start;
  padding-right:2px;
}
.node{
  display:flex;flex-direction:column;gap:6px;
  padding:9px;border-radius:3px;
  background:var(--sf);border:1px solid var(--bd);
  cursor:pointer;transition:background .14s,border-color .14s,box-shadow .14s,transform .14s;
  contain:layout paint style;
}
.node:hover{background:var(--sf3);border-color:var(--bd2);transform:translateY(-1px)}
.node.selected{border-color:var(--acc-br);background:var(--acc-bg);box-shadow:0 8px 18px rgba(13,108,207,.12)}
.node-main{display:grid;grid-template-columns:auto 1fr auto;gap:8px;align-items:start;min-width:0}
.node-latency{
  width:62px;height:22px;padding:0 6px;
  display:inline-flex;align-items:center;justify-content:center;
  border-radius:3px;border:1px solid var(--bd);
  background:var(--sf);color:var(--tx2);
  font-family:ui-monospace,"Cascadia Code","Consolas",monospace;
  font-size:10px;font-weight:700;letter-spacing:0;
  font-variant-numeric:tabular-nums;
  white-space:nowrap;overflow:hidden;
}
.node-latency.fast{color:var(--good);background:var(--good-bg);border-color:rgba(31,122,61,.3)}
.node-latency.warn{color:var(--warn);background:var(--warn-bg);border-color:rgba(138,91,6,.3)}
.node-latency.bad{color:var(--bad);background:var(--bad-bg);border-color:rgba(178,43,43,.3)}
.node-latency.muted{color:var(--tx3)}
.node-latency.fail{color:var(--bad);background:var(--bad-bg);border-color:rgba(178,43,43,.3)}
.node-left{min-width:0}
.node-name{font-size:11.5px;font-weight:700;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.node-subline{
  margin-top:3px;
  font-size:10.5px;color:var(--tx3);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.node-arrow{
  color:var(--tx3);display:inline-flex;align-items:center;justify-content:center;
  width:18px;height:18px;border-radius:3px;border:1px solid var(--bd);background:var(--sf2);
}
.node-arrow svg{width:10px;height:10px;fill:none;stroke:currentColor;stroke-width:2}
.node-detail-viewer{
  display:block;
  min-height:272px;max-height:272px;
  overflow:auto;
}
.node-detail-viewer.visible{display:block}
.node-detail-panel{padding:0}
.node-detail-empty{
  min-height:278px;display:flex;align-items:center;justify-content:center;
  color:var(--tx3);font-size:10.5px;text-align:center;line-height:1.55;
}
.node-detail-card{display:flex;flex-direction:column;gap:12px}
.node-detail-hero{display:flex;flex-direction:column;gap:8px}
.node-detail-title{font-size:15px;font-weight:760;color:var(--tx)}
.node-detail-pills{display:flex;flex-wrap:wrap;gap:7px}
.node-detail-pill{
  display:inline-flex;align-items:center;min-height:24px;padding:0 8px;
  border-radius:3px;border:1px solid var(--bd);background:var(--sf);color:var(--tx2);
  font-size:10.5px;font-weight:600;
}
.node-detail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}
.node-detail-item{
  border:1px solid var(--bd);border-radius:3px;background:var(--sf);
  padding:9px 10px;
}
.node-detail-label{
  font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--tx3);
}
.node-detail-value{
  margin-top:4px;
  font-family:ui-monospace,"Cascadia Code","Consolas",monospace;
  font-size:11px;line-height:1.6;color:var(--tx);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}

.config-frame,.log-frame{border:1px solid var(--bd);border-radius:4px;background:linear-gradient(180deg,var(--sf2),var(--sf));padding:10px}
.config-frame,.log-frame{border:1px solid var(--bd);border-radius:4px;background:linear-gradient(180deg,var(--sf2),var(--sf));padding:9px}
.cfg-editor{
  width:100%;height:260px;min-height:170px;max-height:520px;
  resize:vertical;
  font-family:ui-monospace,"Cascadia Code","Consolas",monospace;
  font-size:11px;line-height:1.58;
  padding:10px 11px;
  border:1px solid var(--bd);border-radius:3px;
  background:var(--sf);color:var(--tx);
  outline:none;display:block;
  transition:border-color .15s,box-shadow .15s,background .15s;
}
.cfg-editor:focus{
  border-color:var(--acc);
  box-shadow:0 0 0 3px var(--acc-bg);
  background:var(--sf);
}
.cfg-actions{display:flex;align-items:center;flex-wrap:wrap;gap:6px;margin-top:9px}
.cfg-hint{
  flex:1;min-width:0;text-align:right;
  font-size:10.5px;color:var(--tx3);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}

.log-overview{
  display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:4px;
  margin-bottom:5px;
}
.log-stat{
  border:1px solid var(--bd);border-radius:3px;background:var(--sf);
  min-width:0;min-height:24px;
  padding:3px 6px;
  display:flex;align-items:center;gap:5px;
}
.log-stat-label{
  display:inline-block;
  flex-shrink:0;
  font-size:8.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--tx3);
}
.log-stat strong{
  display:block;
  min-width:0;
  font-size:10.5px;line-height:1.1;font-weight:760;color:var(--tx);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
}
.log-stat:last-child strong{font-size:9px;color:var(--tx2)}
.log-panel{
  border:1px solid var(--bd);border-radius:3px;
  background:var(--sf);
  min-height:220px;max-height:360px;overflow:auto;padding:7px;
}
.log-toolbar{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:6px}
.search-field{flex:1 1 150px;min-width:104px}
.check-chip{
  display:inline-flex;align-items:center;gap:6px;
  height:30px;padding:0 10px;border-radius:3px;
  border:1px solid var(--bd);background:var(--sf2);color:var(--tx2);
  font-size:11.5px;user-select:none;cursor:pointer;
}
.check-chip input{margin:0;accent-color:var(--acc)}
.log-meta{
  display:flex;justify-content:space-between;gap:6px;flex-wrap:wrap;
  margin-bottom:7px;font-size:11px;color:var(--tx3);
}
.log-list{display:flex;flex-direction:column;gap:5px}
.log-item{
  position:relative;
  border:1px solid var(--bd);border-radius:3px;
  background:var(--sf);padding:8px 10px 8px 14px;
}
.log-item::before{
  content:"";
  position:absolute;left:0;top:8px;bottom:8px;width:3px;border-radius:0;background:var(--bd2);
}
.log-item.warn{border-color:rgba(138,91,6,.27);background:var(--warn-bg)}
.log-item.error{border-color:rgba(178,43,43,.3);background:var(--bad-bg)}
.log-item.debug{border-color:var(--acc-br);background:var(--acc-bg)}
.log-item.warn::before{background:var(--warn)}
.log-item.error::before{background:var(--bad)}
.log-item.debug::before{background:var(--acc)}
.log-head{display:flex;justify-content:space-between;gap:4px;flex-wrap:wrap;margin-bottom:3px}
.log-tags{display:flex;gap:3px;flex-wrap:wrap}
.log-tag,.log-level{
  display:inline-flex;align-items:center;height:15px;padding:0 5px;
  border-radius:3px;border:1px solid var(--bd);background:var(--sf2);
  font-size:9px;
}
.log-tag{color:var(--tx3);border-color:rgba(22,34,54,.1);background:transparent}
.log-tag.accent{color:var(--acc);border-color:var(--acc-br);background:var(--acc-bg)}
.log-tag.warn{color:var(--warn);background:var(--warn-bg);border-color:rgba(138,91,6,.27)}
.log-tag.bad{color:var(--bad);background:var(--bad-bg);border-color:rgba(178,43,43,.3)}
.log-tag.muted{color:var(--tx3)}
.log-level{font-weight:700;letter-spacing:.03em;text-transform:uppercase}
.log-level.info{color:var(--acc)}
.log-level.warn{color:var(--warn)}
.log-level.error{color:var(--bad)}
.log-level.debug{color:var(--tx2)}
.log-msg{
  font-family:ui-monospace,"Cascadia Code","Consolas",monospace;
  font-size:11.5px;line-height:1.66;color:var(--tx);
  white-space:pre-wrap;word-break:break-word
}
mark{background:rgba(255,185,0,.32);color:inherit;border-radius:1px;padding:0 2px}
.log-empty{
  min-height:154px;display:flex;align-items:center;justify-content:center;
  text-align:center;color:var(--tx3);font-size:11.5px;line-height:1.8;
  border:1px dashed var(--bd2);border-radius:3px;background:var(--sf);
}

.toast{
  position:fixed;right:12px;bottom:12px;z-index:9999;
  max-width:300px;padding:9px 12px;
  border-radius:4px;
  font-size:12px;font-weight:560;color:var(--tx);
  background:var(--sf);border:1px solid var(--bd2);
  box-shadow:var(--shadow-lg);
  opacity:0;transform:translateY(8px) scale(.97);
  transition:opacity .14s,transform .14s;
  pointer-events:none;display:flex;align-items:flex-start;gap:8px;
}
.toast.show{opacity:1;transform:translateY(0) scale(1)}
.toast-icon{flex-shrink:0;margin-top:1px}
.toast-icon svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2.2}
.toast.ok .toast-icon{color:var(--good)}
.toast.err .toast-icon{color:var(--bad)}

@media(max-width:900px){
  .shell{padding:11px 10px 34px}
  .hero-grid{grid-template-columns:1fr}
  .hero-top{flex-direction:column;align-items:stretch}
  .hero-kpis{grid-template-columns:repeat(3,minmax(0,1fr))}
  .nodes-workbench{grid-template-columns:1fr}
}

@media(max-width:700px){
  .titlebar{
    flex-wrap:wrap;
    gap:6px;
    padding:8px 10px;
  }
  .tb-sp{
    order:3;
    flex-basis:100%;
    height:0;
  }
  .tb-actions{margin-left:auto}
  .token-wrap{flex:1;min-width:0}
  .token-field{width:100%}
  .hero{padding:10px}
  .sec{padding:10px}
  .hero-title{font-size:20px}
  .hero-btns .btn{flex:1 1 calc(50% - 6px);justify-content:center}
  .hero-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}
  .log-overview{grid-template-columns:repeat(2,minmax(0,1fr))}
}

@media(max-width:560px){
  .tb-sep,.tb-name{display:none}
  .titlebar{padding:7px 8px}
  .shell{padding:8px 7px 28px;gap:8px}
  .tb-caption{display:none}
  .hero-title{max-width:100%;line-height:1.1;height:auto;font-size:18px}
  .hero-kpis{grid-template-columns:1fr}
  .nodes{grid-template-columns:1fr;max-height:260px;min-height:220px}
  .node-detail-grid{grid-template-columns:1fr}
  .sec-tools{gap:5px}
  .cfg-actions .btn{flex:1 1 calc(50% - 6px);justify-content:center}
  .cfg-hint{display:none}
  .log-toolbar .search-field{flex-basis:100%}
  .log-toolbar .check-chip{flex:1 1 auto;justify-content:center}
  .toast{left:8px;right:8px;max-width:none}
}

@media(max-width:360px){
  .tb-actions{width:100%;justify-content:flex-end}
  .hero-btns .btn,
  .cfg-actions .btn{flex:1 1 100%}
  .num-field{width:64px}
}
</style>
</head>
<body>

<header class="titlebar">
  <div class="tb-icon">
    <svg viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
      <path d="M3.5 2.75h3.9c4.37 0 7.1 2.73 7.1 7.25S11.77 17.25 7.4 17.25H3.5V2.75Z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="miter"/>
      <path d="M6.1 6.45h3.1M6.1 10h3.95M6.1 13.55h3.1" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="square"/>
    </svg>
  </div>
  <span class="tb-name">DAE Console</span>
  <div class="tb-sep"></div>
  <div id="svc-chip" class="svc-chip">
    <span class="chip-dot"></span>
    <span id="svc-label">加载中</span>
  </div>
    <span id="tb-refresh" class="tb-caption" style="display:none">同步 --</span>
  <div class="tb-sp"></div>
  <div class="tb-actions">
    <div class="token-wrap">
      <svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2" stroke-width="1.6"/><path d="M8 11V7a4 4 0 0 1 8 0v4" stroke-linecap="round"/></svg>
      <input id="api-token" class="token-field" type="password" placeholder="访问令牌（可选）" autocomplete="off">
    </div>
    <button class="tb-btn" id="theme-btn" onclick="toggleTheme()" title="切换主题" aria-label="切换主题">
      <svg viewBox="0 0 24 24" id="theme-icon">
        <path d="M12 3v1M12 20v1M4.22 4.22l.7.7M18.36 18.36l.7.7M3 12h1M20 12h1M4.22 19.78l.7-.7M18.36 5.64l.7-.7" stroke-linecap="round"/>
        <circle cx="12" cy="12" r="4.5" stroke-width="1.6"/>
      </svg>
    </button>
    <button class="tb-btn" onclick="refreshDashboard()" title="刷新面板" aria-label="刷新面板">
      <svg viewBox="0 0 24 24">
        <path d="M4 12a8 8 0 0 1 13.66-5.66M20 12a8 8 0 0 1-13.66 5.66" stroke-linecap="round"/>
        <path d="M4 7v5h5M20 17v-5h-5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </button>
  </div>
</header>

<main class="shell">

  <!-- 首屏概览 -->
  <div class="card hero">
    <div class="hero-grid">
      <div class="hero-main">
        <div class="hero-left">
          <div class="hero-top">
            <div class="hero-copy">
              <div class="hero-badge-row">
                <div class="hero-eyebrow">DAE 控制面板</div>
                <div id="hero-dae-version" class="hero-version">dae --</div>
              </div>
              <p id="hero-summary" class="hero-summary">正在读取状态</p>
            </div>
            <div class="hero-btns">
              <button id="action-start" class="btn btn-success" onclick="runAction('start')" title="启动 dae 服务">
                <svg viewBox="0 0 24 24"><polygon points="5,3 19,12 5,21" fill="currentColor" stroke="none"/></svg>
                <span>启动</span>
              </button>
              <button id="action-restart" class="btn btn-warn" onclick="runAction('restart')" title="重启 dae 服务">
                <svg viewBox="0 0 24 24">
                  <path d="M7.5 7.5A6.5 6.5 0 0 1 18 11" stroke-linecap="round"/>
                  <path d="M18 7.5V11h-3.5" stroke-linecap="round" stroke-linejoin="round"/>
                  <path d="M16.5 16.5A6.5 6.5 0 0 1 6 13" stroke-linecap="round"/>
                  <path d="M6 16.5V13h3.5" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                <span>重启</span>
              </button>
              <button id="action-stop" class="btn btn-danger" onclick="runAction('stop')" title="停止 dae 服务">
                <svg viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="1.5" fill="currentColor" stroke="none"/></svg>
                <span>停止</span>
              </button>
            </div>
          </div>
          <div class="hero-pills">
            <span id="hero-manager" class="hero-pill">管理器：--</span>
            <span id="hero-node-count" class="hero-pill">节点：--</span>
            <span id="hero-refresh" class="hero-pill">更新：--</span>
          </div>
        </div>
      </div>
    </div>
    <div id="hero-kpis" class="hero-kpis">
        <div class="hero-kpi muted" data-card-id="uptime"><div class="hero-kpi-head"><div class="hero-kpi-meta"><span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3" stroke-linecap="round" stroke-linejoin="round"/></svg></span><div class="hero-kpi-label">运行时长</div></div></div><div class="hero-kpi-value">--</div></div>
        <div class="hero-kpi muted" data-card-id="memory"><div class="hero-kpi-head"><div class="hero-kpi-meta"><span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M7 9V7a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v2" stroke-linecap="round"/><rect x="4" y="9" width="16" height="10" rx="2"/><path d="M8 13h.01M12 13h.01M16 13h.01" stroke-linecap="round"/></svg></span><div class="hero-kpi-label">内存占用</div></div></div><div class="hero-kpi-value">--</div></div>
        <div class="hero-kpi muted" data-card-id="kernel-version"><div class="hero-kpi-head"><div class="hero-kpi-meta"><span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16" stroke-linecap="round"/><path d="M8 4v16M16 4v16" stroke-linecap="round"/></svg></span><div class="hero-kpi-label">Kernel</div></div></div><div class="hero-kpi-value">--</div></div>
        <div class="hero-kpi muted refreshable" data-card-id="baidu" onclick="refreshLatencyCard('baidu')"><div class="hero-kpi-head"><div class="hero-kpi-meta"><span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="6.1" cy="7.2" r="1.75" fill="#2563EB" stroke="none"/><circle cx="11.9" cy="5.6" r="1.9" fill="#2563EB" stroke="none"/><circle cx="17.7" cy="7.2" r="1.75" fill="#2563EB" stroke="none"/><circle cx="5.4" cy="12.8" r="1.65" fill="#2563EB" stroke="none"/><circle cx="18.4" cy="12.8" r="1.65" fill="#2563EB" stroke="none"/><path d="M12 10.35c-2.84 0-4.98 2.05-4.98 4.68 0 1.97 1.39 3.34 3.18 3.34 1.01 0 1.77-.35 2.56-1.08.78.73 1.55 1.08 2.57 1.08 1.79 0 3.18-1.37 3.18-3.34 0-2.63-2.14-4.68-4.98-4.68-.51 0-.98.08-1.47.25-.48-.17-.95-.25-1.46-.25z" fill="#2563EB" stroke="none"/></svg></span><div class="hero-kpi-label">Baidu</div></div><span class="hero-kpi-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 12a8 8 0 0 1 13.66-5.66M20 12a8 8 0 0 1-13.66 5.66" stroke-linecap="round"/><path d="M4 7v5h5M20 17v-5h-5" stroke-linecap="round" stroke-linejoin="round"/></svg></span></div><div class="hero-kpi-value">--</div></div>
        <div class="hero-kpi muted refreshable" data-card-id="google" onclick="refreshLatencyCard('google')"><div class="hero-kpi-head"><div class="hero-kpi-meta"><span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M19.95 12.23c0-.62-.06-1.08-.18-1.57H12v3.06h4.56c-.09.76-.58 1.91-1.67 2.68l2.57 2.03c1.54-1.42 2.49-3.51 2.49-6.2z" fill="#4285F4" stroke="none"/><path d="M12 20.25c2.23 0 4.11-.73 5.48-1.98l-2.57-2.03c-.69.47-1.61.81-2.91.81-2.17 0-4.01-1.44-4.67-3.38l-2.65 2.08c1.36 2.72 4.16 4.5 7.32 4.5z" fill="#34A853" stroke="none"/><path d="M7.33 13.67A4.92 4.92 0 0 1 7.07 12c0-.58.1-1.14.25-1.67L4.67 8.25A8.18 8.18 0 0 0 3.82 12c0 1.35.32 2.62.85 3.75l2.66-2.08z" fill="#FBBC05" stroke="none"/><path d="M12 6.95c1.5 0 2.52.64 3.09 1.17l2.26-2.24C16.03 4.64 14.23 3.75 12 3.75c-3.16 0-5.96 1.78-7.33 4.5l2.65 2.08C7.99 8.39 9.83 6.95 12 6.95z" fill="#EA4335" stroke="none"/></svg></span><div class="hero-kpi-label">Google</div></div><span class="hero-kpi-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 12a8 8 0 0 1 13.66-5.66M20 12a8 8 0 0 1-13.66 5.66" stroke-linecap="round"/><path d="M4 7v5h5M20 17v-5h-5" stroke-linecap="round" stroke-linejoin="round"/></svg></span></div><div class="hero-kpi-value">--</div></div>
        <div class="hero-kpi muted refreshable" data-card-id="youtube" onclick="refreshLatencyCard('youtube')"><div class="hero-kpi-head"><div class="hero-kpi-meta"><span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M21.35 8.62a3.08 3.08 0 0 0-2.17-2.18C17.3 5.93 12 5.93 12 5.93s-5.3 0-7.18.51A3.08 3.08 0 0 0 2.65 8.62 32.4 32.4 0 0 0 2.14 12c0 1.12.17 2.24.51 3.38a3.08 3.08 0 0 0 2.17 2.18c1.88.51 7.18.51 7.18.51s5.3 0 7.18-.51a3.08 3.08 0 0 0 2.17-2.18c.34-1.14.51-2.26.51-3.38 0-1.12-.17-2.24-.51-3.38z" fill="#FF0033" stroke="none"/><path d="M10.05 14.78 15.42 12l-5.37-2.78v5.56z" fill="#FFFFFF" stroke="none"/></svg></span><div class="hero-kpi-label">YouTube</div></div><span class="hero-kpi-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 12a8 8 0 0 1 13.66-5.66M20 12a8 8 0 0 1-13.66 5.66" stroke-linecap="round"/><path d="M4 7v5h5M20 17v-5h-5" stroke-linecap="round" stroke-linejoin="round"/></svg></span></div><div class="hero-kpi-value">--</div></div>
      </div>
  </div>

  <!-- 节点工作台 -->
  <div class="card sec collapsed" id="card-nodes">
    <div class="sec-h toggle-h" onclick="toggleCollapse('card-nodes')" role="button" aria-expanded="false" aria-controls="body-nodes">
      <h2><span class="sec-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="19" r="2.5"/><path d="M8.5 11L15.5 6.5M8.5 13L15.5 17.5" stroke-linecap="round"/></svg></span>节点工作台</h2>
      <span class="toggle-chevron"><svg viewBox="0 0 24 24"><path d="M6 9l6 6 6-6" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
    </div>
    <div class="collapsible-body" id="body-nodes">
      <div class="collapsible-inner">
        <div class="nodes-workbench">
          <div class="panel-shell">
            <div class="panel-head">
              <div>
                <div class="panel-eyebrow">节点</div>
                <div class="panel-title">延迟排序</div>
              </div>
              <div id="node-count-badge" class="panel-meta">-- 个节点</div>
            </div>
            <div id="node-list" class="nodes">
              <div style="color:var(--tx3);font-size:11px;padding:4px 0">正在加载节点...</div>
            </div>
          </div>
          <div id="node-detail-viewer" class="panel-shell node-detail-viewer visible">
            <div class="node-detail-empty">选择节点查看详情</div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 配置编辑 -->
  <div class="card sec collapsed" id="card-config">
    <div class="sec-h toggle-h" onclick="toggleCollapse('card-config')" role="button" aria-expanded="false" aria-controls="body-config">
      <h2><span class="sec-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 6h2M10 6h10M4 12h10M18 12h2M4 18h6M14 18h6" stroke-linecap="round"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="11" cy="18" r="2"/></svg></span>配置编辑</h2>
      <span class="toggle-chevron"><svg viewBox="0 0 24 24"><path d="M6 9l6 6 6-6" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
    </div>
    <div class="collapsible-body" id="body-config">
      <div class="collapsible-inner">
        <div class="config-frame">
          <div class="panel-head">
            <div>
              <div class="panel-eyebrow">配置</div>
              <div class="panel-title">编辑与校验</div>
            </div>
            <div id="config-hint" class="panel-meta">自动加载</div>
          </div>
          <textarea id="config-editor" class="cfg-editor" spellcheck="false" placeholder="当前配置会显示在这里"></textarea>
          <div class="cfg-actions">
            <button class="btn btn-accent" onclick="saveConfig(false)">保存</button>
            <button class="btn btn-subtle" onclick="saveConfig(true)">保存并重载</button>
            <button class="btn btn-subtle" onclick="validateDraft()">校验草稿</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 更新面板 -->
  <div class="card sec collapsed" id="card-update">
    <div class="sec-h toggle-h" onclick="toggleCollapse('card-update')" role="button" aria-expanded="false" aria-controls="body-update">
      <h2><span class="sec-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 12a8 8 0 0 1 13.66-5.66M20 12a8 8 0 0 1-13.66 5.66" stroke-linecap="round"/><path d="M4 7v5h5M20 17v-5h-5" stroke-linecap="round" stroke-linejoin="round"/></svg></span>更新 dae</h2>
      <span class="toggle-chevron"><svg viewBox="0 0 24 24"><path d="M6 9l6 6 6-6" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
    </div>
    <div class="collapsible-body" id="body-update">
      <div class="collapsible-inner">
        <div class="config-frame">
          <div class="panel-head">
            <div>
              <div class="panel-eyebrow">Actions Run</div>
              <div class="panel-title">从 CI 产物更新</div>
            </div>
            <div id="update-hint" class="panel-meta">粘贴 Actions 链接或 Run ID</div>
          </div>
          <div style="display:flex;gap:7px;align-items:center;margin-bottom:9px">
            <input id="update-run-input" class="token-field" type="text"
              placeholder="https://github.com/daeuniverse/dae/actions/runs/23737285754"
              style="flex:1;font-size:12px" autocomplete="off" oninput="onUpdateInputChange()">
            <button class="btn btn-accent" id="update-btn" onclick="startUpdate()" style="white-space:nowrap;flex-shrink:0">
              <svg viewBox="0 0 24 24" style="width:14px;height:14px"><path d="M4 12a8 8 0 0 1 13.66-5.66M20 12a8 8 0 0 1-13.66 5.66" stroke-linecap="round"/><path d="M4 7v5h5M20 17v-5h-5" stroke-linecap="round" stroke-linejoin="round"/></svg>
              立即更新
            </button>
          </div>
          <div id="update-log-box" style="display:none;border:1px solid var(--bd);border-radius:4px;background:var(--sf);padding:9px 10px;max-height:260px;overflow-y:auto;font-family:monospace;font-size:11.5px;line-height:1.7"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- 日志面板 -->
  <div class="card sec collapsed" id="card-logs">
    <div class="sec-h toggle-h" onclick="toggleCollapse('card-logs')" role="button" aria-expanded="false" aria-controls="body-logs">
      <h2><span class="sec-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" stroke-linejoin="round"/><path d="M14 2v6h6" stroke-linecap="round" stroke-linejoin="round"/><path d="M8 13h8M8 17h5" stroke-linecap="round"/></svg></span>日志面板</h2>
      <div style="display:flex;align-items:center;gap:5px" onclick="event.stopPropagation()">
        <input id="log-lines" class="num-field" type="number" min="20" max="500" value="500" aria-label="日志行数" onclick="event.stopPropagation()">
        <input id="log-reverse" type="checkbox" checked style="display:none">
        <input id="log-auto-refresh" type="checkbox" checked style="display:none">
        <button class="tb-btn active" id="btn-log-reverse" title="最新在前" onclick="toggleLogReverse()" aria-label="切换最新在前">
          <svg viewBox="0 0 24 24"><path d="M3 6h18M8 12h13M13 18h8" stroke-linecap="round"/><path d="M5 15l-3 3 3 3" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
        <button class="tb-btn active" id="btn-log-auto" title="暂停刷新日志" onclick="toggleLogAuto()" aria-label="暂停刷新日志">
          <svg viewBox="0 0 24 24"><path d="M8 6v12M16 6v12" stroke-linecap="round"/></svg>
        </button>
        <button class="tb-btn" title="清空当前日志" onclick="clearLogsView()" aria-label="清空当前日志">
          <svg viewBox="0 0 24 24"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </button>
        <span class="toggle-chevron" style="pointer-events:none"><svg viewBox="0 0 24 24"><path d="M6 9l6 6 6-6" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
      </div>
    </div>
    <div class="collapsible-body" id="body-logs">
      <div class="collapsible-inner">
        <div class="log-frame">
          <div class="log-overview">
            <div class="log-stat"><span class="log-stat-label">已显示</span><strong id="log-stat-shown">0</strong></div>
            <div class="log-stat"><span class="log-stat-label">错误</span><strong id="log-stat-error">0</strong></div>
            <div class="log-stat"><span class="log-stat-label">警告</span><strong id="log-stat-warn">0</strong></div>
            <div class="log-stat"><span class="log-stat-label">来源</span><strong id="log-stat-source">-</strong></div>
          </div>
          <div class="log-toolbar">
            <input id="log-search" class="token-field search-field" type="text" placeholder="按关键字过滤" oninput="renderLogs()">
            <span id="log-summary" class="panel-meta">加载中</span>
          </div>
          <div id="log-box" class="log-panel">正在加载日志...</div>
        </div>
      </div>
    </div>
  </div>

</main>

<!-- TOAST -->
<div id="toast" class="toast" role="alert" aria-live="assertive">
  <div class="toast-icon">
    <svg viewBox="0 0 24 24" id="toast-svg"></svg>
  </div>
  <span id="toast-msg"></span>
</div>

<script>
(function(){
  var logState = { entries: [], source: '-', limit: 500, fetchedAt: '', refreshInFlight: false, clearedAfterSig: '' };
  var nodeState = { selectedSig: '' };
  var overviewRefreshState = { runtimeBusy: false, siteBusy: false };
  var dashboardState = { serviceStatus: 'unknown', serviceManager: '--', nodeCount: 0, refreshedAt: '', daeVersion: '--', runtimeCards: [] };
  var UI_CACHE_KEY = 'dae-ui-cache-v3';
  var UI_STATE_KEY = 'dae-ui-state-v1';

  // 主题
  var html = document.documentElement;

  function applyTheme(t){
    html.setAttribute('data-theme', t);
    var icon = document.getElementById('theme-icon');
    if(t === 'dark'){
      icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" stroke-linecap="round" stroke-linejoin="round"/>';
    } else {
      icon.innerHTML = '<path d="M12 3v1M12 20v1M4.22 4.22l.7.7M18.36 18.36l.7.7M3 12h1M20 12h1M4.22 19.78l.7-.7M18.36 5.64l.7-.7" stroke-linecap="round"/><circle cx="12" cy="12" r="4.5" stroke-width="1.6"/>';
    }
  }

  function toggleTheme(){
    var t = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(t);
    try{ localStorage.setItem('dae-theme', t); }catch(e){}
  }
  window.toggleTheme = toggleTheme;

  (function initTheme(){
    var saved;
    try{ saved = localStorage.getItem('dae-theme'); }catch(e){}
    if(saved === 'dark' || saved === 'light'){
      applyTheme(saved); return;
    }
    if(window.matchMedia && window.matchMedia('(prefers-color-scheme:dark)').matches){
      applyTheme('dark');
    } else {
      applyTheme('light');
    }
    // 没有手动偏好时，跟随系统主题变化
    if(!saved && window.matchMedia){
      window.matchMedia('(prefers-color-scheme:dark)').addEventListener('change', function(e){
        try{ if(!localStorage.getItem('dae-theme')) applyTheme(e.matches?'dark':'light'); }catch(x){}
      });
    }
  })();

  // 提示
  var toastEl  = document.getElementById('toast');
  var toastMsg = document.getElementById('toast-msg');
  var toastSvg = document.getElementById('toast-svg');
  var toastTimer;

  function showToast(msg, bad){
    toastMsg.textContent = msg;
    toastEl.className = 'toast show ' + (bad ? 'err' : 'ok');
    toastSvg.innerHTML = bad
      ? '<path d="M18 6L6 18M6 6l12 12" stroke-linecap="round" stroke-linejoin="round"/>'
      : '<path d="M5 13l4 4L19 7" stroke-linecap="round" stroke-linejoin="round"/>';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function(){ toastEl.classList.remove('show'); }, 3200);
  }

  // 接口
  function getToken(){
    return (document.getElementById('api-token').value || '').trim();
  }

  function api(path, opts){
    opts = opts || {};
    var headers = Object.assign({}, opts.headers || {});
    var t = getToken();
    if(t) headers['X-Auth-Token'] = t;
    return fetch(path, Object.assign({}, opts, {headers: headers}))
      .then(function(res){
        return res.json().then(function(data){
          if(!res.ok || !data.ok) throw new Error(data.message || '请求失败（' + res.status + '）');
          return data;
        });
      });
  }

  function readUiCache(){
    try{
      var raw = localStorage.getItem(UI_CACHE_KEY);
      return raw ? JSON.parse(raw) : {};
    }catch(e){
      return {};
    }
  }

  function writeUiCache(patch){
    try{
      var current = readUiCache();
      Object.keys(patch || {}).forEach(function(key){
        current[key] = patch[key];
      });
      localStorage.setItem(UI_CACHE_KEY, JSON.stringify(current));
    }catch(e){}
  }

  function readUiState(){
    try{
      var raw = localStorage.getItem(UI_STATE_KEY);
      return raw ? JSON.parse(raw) : {};
    }catch(e){
      return {};
    }
  }

  function writeUiState(patch){
    try{
      var current = readUiState();
      Object.keys(patch || {}).forEach(function(key){
        current[key] = patch[key];
      });
      localStorage.setItem(UI_STATE_KEY, JSON.stringify(current));
    }catch(e){}
  }

  function applyCollapsedState(){
    var state = readUiState();
    var collapsedCards = state.collapsedCards || {};
    ['card-nodes', 'card-config', 'card-update', 'card-logs'].forEach(function(id){
      var card = document.getElementById(id);
      if(!card) return;
      var shouldCollapse = Object.prototype.hasOwnProperty.call(collapsedCards, id)
        ? !!collapsedCards[id]
        : true;
      card.classList.toggle('collapsed', shouldCollapse);
      var btn = card.querySelector('.toggle-h');
      if(btn) btn.setAttribute('aria-expanded', String(!shouldCollapse));
    });
    nodeState.selectedSig = state.selectedNodeSig || '';
    logState.clearedAfterSig = state.clearedAfterSig || '';
  }

  function mergeCachedCardBucket(bucketName, items){
    var cache = readUiCache();
    var existing = Array.isArray(cache[bucketName]) ? cache[bucketName] : [];
    var byId = {};
    existing.forEach(function(item){ if(item && item.id) byId[item.id] = item; });
    (items || []).forEach(function(item){ if(item && item.id) byId[item.id] = item; });
    writeUiCache((function(){ var obj = {}; obj[bucketName] = Object.keys(byId).map(function(id){ return byId[id]; }); return obj; })());
  }

  function hydrateUiFromCache(){
    applyCollapsedState();
    var cache = readUiCache();
    if(cache.status){
      applyStatusState(cache.status);
    }
    var cards = [];
    if(Array.isArray(cache.runtimeCards)) cards = cards.concat(cache.runtimeCards);
    if(Array.isArray(cache.siteCards)) cards = cards.concat(cache.siteCards);
    if(cards.length){
      mergeHeroCards(cards);
    }
    if(cache.logs){
      var rawCached = Array.isArray(cache.logs.entries) ? cache.logs.entries : [];
      logState.entries = filterEntriesAfterClear(rawCached);
      logState.source = cache.logs.source || '-';
      logState.limit = cache.logs.limit || 500;
      logState.fetchedAt = cache.logs.fetched_at || '';
      renderLogs();
    }
  }

  function finishBoot(){
    requestAnimationFrame(function(){
      html.removeAttribute('data-booting');
    });
  }

  // 服务状态
  function humanServiceStatus(status){
    var value = String(status || '').toLowerCase();
    if(value === 'active') return '运行中';
    if(value === 'inactive') return '已停止';
    if(value === 'activating') return '启动中';
    if(value === 'deactivating') return '停止中';
    if(value === 'failed') return '失败';
    return value || '未知';
  }

  function setSvcChip(status){
    var chip = document.getElementById('svc-chip');
    var lbl  = document.getElementById('svc-label');
    chip.className = 'svc-chip';
    lbl.textContent = humanServiceStatus(status);
    if(status === 'active') { return; }
    if(status === 'inactive' || status === 'deactivating') {
      chip.classList.add('warn');
      return;
    }
    chip.classList.add('bad');
  }

  function setButtonPriority(id, priority, disabled){
    var button = document.getElementById(id);
    if(!button) return;
    button.setAttribute('data-priority', priority || 'low');
    button.disabled = !!disabled;
  }

  function syncDashboardChrome(){
    var status = dashboardState.serviceStatus;
    var nodeCount = dashboardState.nodeCount || 0;
    var refreshedAt = dashboardState.refreshedAt || '--';
    // 顶栏只显示状态 chip，不再重复显示同步时间
    setText('hero-manager', '管理器：' + (dashboardState.serviceManager || '--'));
    setText('hero-node-count', '节点：' + nodeCount);
    setText('hero-refresh', '更新：' + fmtShortTime(refreshedAt));
    setText('hero-dae-version', 'dae ' + (dashboardState.daeVersion || '--'));
    setText('node-count-badge', nodeCount + ' 个节点');

    if(status === 'active'){
      setText('hero-summary', nodeCount + ' 个节点');
      setButtonPriority('action-start', 'off', true);
      setButtonPriority('action-restart', 'high', false);
      setButtonPriority('action-stop', 'low', false);
      return;
    }

    if(status === 'inactive'){
      setText('hero-summary', nodeCount + ' 个节点');
      setButtonPriority('action-start', 'high', false);
      setButtonPriority('action-restart', 'low', true);
      setButtonPriority('action-stop', 'off', true);
      return;
    }

    setText('hero-summary', nodeCount + ' 个节点');
    setButtonPriority('action-start', 'low', false);
    setButtonPriority('action-restart', 'high', false);
    setButtonPriority('action-stop', 'low', false);
  }

  function applyStatusState(status){
    if(!status) return;
    dashboardState.serviceStatus = status.service_status || dashboardState.serviceStatus;
    dashboardState.serviceManager = status.service_manager || dashboardState.serviceManager;
    dashboardState.nodeCount = typeof status.node_count === 'number' ? status.node_count : ((status.nodes || []).length || dashboardState.nodeCount);
    dashboardState.refreshedAt = status.refreshed_at || dashboardState.refreshedAt;
    dashboardState.daeVersion = status.dae_version || dashboardState.daeVersion;
    setSvcChip(dashboardState.serviceStatus);
    syncDashboardChrome();
    renderNodes(status.nodes || []);
  }

  // 节点
  function renderNodes(items){
    var box = document.getElementById('node-list');
    var viewer = document.getElementById('node-detail-viewer');
    var sig = (items || []).map(function(n){
      return [n.name, n.host, n.proto, n.port, n.latency_text, n.latency_tone].join('|');
    }).join('||');
    if(box && box.dataset.renderSig === sig) return;
    if(!items || !items.length){
      if(box) box.dataset.renderSig = '__empty__';
      box.innerHTML = '<div style="color:var(--tx3);font-size:11px;padding:4px 0">暂无节点</div>';
      if(viewer){
        viewer.classList.add('visible');
        viewer.innerHTML = '<div class="node-detail-empty">暂无可查看详情</div>';
      }
      nodeState.selectedSig = '';
      return;
    }
    box.dataset.renderSig = sig;
    box.innerHTML = items.map(function(n){
      var name = escHtml(n.name || '未命名节点');
      var host = escHtml(n.host || '-');
      var proto = escHtml(n.proto || '?');
      var port  = escHtml(String(n.port || ''));
      var latencyText = escHtml(n.latency_text || '-- ms');
      var latencyTone = escHtml(n.latency_tone || 'muted');
      var latencyHint = escHtml(n.latency_hint || '探测尚未完成');
      var nodeSig = escHtml([n.name || '', n.host || '', n.proto || '', n.port || ''].join('|'));
      return '<button class="node' + (nodeState.selectedSig === nodeSig ? ' selected' : '') + '" type="button" onclick="selectNode(this)" data-node-sig="' + nodeSig + '" data-name="' + name + '" data-host="' + host + '" data-proto="' + proto + '" data-port="' + port + '" data-latency="' + latencyText + '" data-latency-hint="' + latencyHint + '" title="' + latencyHint + '">'
        + '<div class="node-main">'
        + '<span class="node-latency ' + latencyTone + '">' + latencyText + '</span>'
        + '<div class="node-left"><div class="node-name">' + name + '</div><div class="node-subline">' + proto.toUpperCase() + ' · ' + host + (port ? ':' + port : '') + '</div></div>'
        + '<span class="node-arrow" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M9 6l6 6-6 6" stroke-linecap="round" stroke-linejoin="round"/></svg></span>'
        + '</div>'
        + '</button>';
    }).join('');

    var selected = nodeState.selectedSig ? box.querySelector('.node[data-node-sig="' + cssEsc(nodeState.selectedSig) + '"]') : null;
    if(selected){
      selectNode(selected, true);
    } else if(viewer) {
      viewer.classList.add('visible');
      viewer.innerHTML = '<div class="node-detail-empty">选择节点查看详情</div>';
    }
  }

  function renderNodeViewer(button){
    var viewer = document.getElementById('node-detail-viewer');
    if(!viewer || !button) return;
    viewer.classList.add('visible');
    viewer.innerHTML = '<div class="node-detail-panel"><div class="node-detail-card">'
        + '<div class="panel-head node-detail-hero">'
        + '<div><div class="panel-eyebrow">详情</div><div class="node-detail-title">' + (button.getAttribute('data-name') || '-') + '</div></div>'
      + '<div class="node-detail-pills">'
      + '<span class="node-detail-pill">' + (button.getAttribute('data-latency') || '--') + '</span>'
      + '<span class="node-detail-pill">' + (button.getAttribute('data-proto') || '?').toUpperCase() + '</span>'
      + '</div></div>'
      + '<div class="node-detail-grid">'
        + '<div class="node-detail-item"><div class="node-detail-label">主机</div><div class="node-detail-value">' + (button.getAttribute('data-host') || '-') + '</div></div>'
        + '<div class="node-detail-item"><div class="node-detail-label">端口</div><div class="node-detail-value">' + (button.getAttribute('data-port') || '-') + '</div></div>'
        + '<div class="node-detail-item"><div class="node-detail-label">端点</div><div class="node-detail-value">' + (button.getAttribute('data-proto') || '?') + '://' + (button.getAttribute('data-host') || '-') + ':' + (button.getAttribute('data-port') || '-') + '</div></div>'
        + '<div class="node-detail-item"><div class="node-detail-label">备注</div><div class="node-detail-value">' + (button.getAttribute('data-latency-hint') || '-') + '</div></div>'
      + '</div>'
      + '</div></div>';
  }

  function cssEsc(value){
    return String(value || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }

  function renderHeroKpis(items){
    var box = document.getElementById('hero-kpis');
    if(!box || !items || !items.length) return;
    box.innerHTML = items.map(function(item){
      var cardId = escHtml(item.id || '');
      var label = escHtml(item.label || '-');
      var value = escHtml(item.value || '--');
      var hint = escHtml(item.hint || '');
      var tone = escHtml(item.tone || 'muted');
      var refreshable = !!item.refreshable;
      var glyph = heroCardGlyph(item.id || '');
      var icon = refreshable
        ? '<span class="hero-kpi-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 12a8 8 0 0 1 13.66-5.66M20 12a8 8 0 0 1-13.66 5.66" stroke-linecap="round"/><path d="M4 7v5h5M20 17v-5h-5" stroke-linecap="round" stroke-linejoin="round"/></svg></span>'
        : '';
      var attrs = ' class="hero-kpi ' + tone + (refreshable ? ' refreshable' : '') + '" data-card-id="' + cardId + '" title="' + hint + '"';
      if(refreshable){
        attrs += ' onclick="refreshLatencyCard(\'' + cardId + '\')"';
      }
      return '<div' + attrs + '>'
        + '<div class="hero-kpi-head"><div class="hero-kpi-meta">' + glyph + '<div class="hero-kpi-label">' + label + '</div></div>' + icon + '</div>'
        + '<div class="hero-kpi-value">' + value + '</div>'
        + '</div>';
    }).join('');
  }

  function heroCardGlyph(cardId){
    var icons = {
      'uptime': '<span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3" stroke-linecap="round" stroke-linejoin="round"/></svg></span>',
      'memory': '<span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M7 9V7a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v2" stroke-linecap="round"/><rect x="4" y="9" width="16" height="10" rx="2"/><path d="M8 13h.01M12 13h.01M16 13h.01" stroke-linecap="round"/></svg></span>',
      'kernel-version': '<span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16" stroke-linecap="round"/><path d="M8 4v16M16 4v16" stroke-linecap="round"/></svg></span>',
      'baidu': '<span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="6.1" cy="7.2" r="1.75" fill="#2563EB" stroke="none"/><circle cx="11.9" cy="5.6" r="1.9" fill="#2563EB" stroke="none"/><circle cx="17.7" cy="7.2" r="1.75" fill="#2563EB" stroke="none"/><circle cx="5.4" cy="12.8" r="1.65" fill="#2563EB" stroke="none"/><circle cx="18.4" cy="12.8" r="1.65" fill="#2563EB" stroke="none"/><path d="M12 10.35c-2.84 0-4.98 2.05-4.98 4.68 0 1.97 1.39 3.34 3.18 3.34 1.01 0 1.77-.35 2.56-1.08.78.73 1.55 1.08 2.57 1.08 1.79 0 3.18-1.37 3.18-3.34 0-2.63-2.14-4.68-4.98-4.68-.51 0-.98.08-1.47.25-.48-.17-.95-.25-1.46-.25z" fill="#2563EB" stroke="none"/></svg></span>',
      'google': '<span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M19.95 12.23c0-.62-.06-1.08-.18-1.57H12v3.06h4.56c-.09.76-.58 1.91-1.67 2.68l2.57 2.03c1.54-1.42 2.49-3.51 2.49-6.2z" fill="#4285F4" stroke="none"/><path d="M12 20.25c2.23 0 4.11-.73 5.48-1.98l-2.57-2.03c-.69.47-1.61.81-2.91.81-2.17 0-4.01-1.44-4.67-3.38l-2.65 2.08c1.36 2.72 4.16 4.5 7.32 4.5z" fill="#34A853" stroke="none"/><path d="M7.33 13.67A4.92 4.92 0 0 1 7.07 12c0-.58.1-1.14.25-1.67L4.67 8.25A8.18 8.18 0 0 0 3.82 12c0 1.35.32 2.62.85 3.75l2.66-2.08z" fill="#FBBC05" stroke="none"/><path d="M12 6.95c1.5 0 2.52.64 3.09 1.17l2.26-2.24C16.03 4.64 14.23 3.75 12 3.75c-3.16 0-5.96 1.78-7.33 4.5l2.65 2.08C7.99 8.39 9.83 6.95 12 6.95z" fill="#EA4335" stroke="none"/></svg></span>',
      'youtube': '<span class="hero-kpi-glyph" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M21.35 8.62a3.08 3.08 0 0 0-2.17-2.18C17.3 5.93 12 5.93 12 5.93s-5.3 0-7.18.51A3.08 3.08 0 0 0 2.65 8.62 32.4 32.4 0 0 0 2.14 12c0 1.12.17 2.24.51 3.38a3.08 3.08 0 0 0 2.17 2.18c1.88.51 7.18.51 7.18.51s5.3 0 7.18-.51a3.08 3.08 0 0 0 2.17-2.18c.34-1.14.51-2.26.51-3.38 0-1.12-.17-2.24-.51-3.38z" fill="#FF0033" stroke="none"/><path d="M10.05 14.78 15.42 12l-5.37-2.78v5.56z" fill="#FFFFFF" stroke="none"/></svg></span>'
    };
    return icons[String(cardId || '')] || '';
  }

  function logEntrySig(item){
    return [item.timestamp || '', item.service || '', item.raw || item.message || ''].join('|');
  }

  function filterEntriesAfterClear(entries){
    if(!logState.clearedAfterSig) return entries;
    var marker = logState.clearedAfterSig;
    var lastIndex = -1;
    entries.forEach(function(item, index){
      if(logEntrySig(item) === marker) lastIndex = index;
    });
    if(lastIndex >= 0) return entries.slice(lastIndex + 1);
    return entries;
  }

  function updateHeroCard(node, item){
    if(!node || !item) return;
    var labelNode = node.querySelector('.hero-kpi-label');
    var valueNode = node.querySelector('.hero-kpi-value');
    node.className = 'hero-kpi ' + (item.tone || 'muted') + (item.refreshable ? ' refreshable' : '');
    node.setAttribute('title', item.hint || '');
    if(item.refreshable){
      node.setAttribute('onclick', 'refreshLatencyCard(\'' + String(item.id || '') + '\')');
    } else {
      node.removeAttribute('onclick');
    }
    if(labelNode && labelNode.textContent !== String(item.label || '-')){
      labelNode.textContent = String(item.label || '-');
    }
    if(valueNode && valueNode.textContent !== String(item.value || '--')){
      valueNode.textContent = String(item.value || '--');
    }
    var metaNode = node.querySelector('.hero-kpi-meta');
    if(metaNode){
      metaNode.innerHTML = heroCardGlyph(item.id || '') + '<div class="hero-kpi-label">' + escHtml(item.label || '-') + '</div>';
    }
    var iconNode = node.querySelector('.hero-kpi-icon');
    if(item.refreshable && !iconNode){
      var head = node.querySelector('.hero-kpi-head');
      if(head){
        head.insertAdjacentHTML('beforeend', '<span class="hero-kpi-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4 12a8 8 0 0 1 13.66-5.66M20 12a8 8 0 0 1-13.66 5.66" stroke-linecap="round"/><path d="M4 7v5h5M20 17v-5h-5" stroke-linecap="round" stroke-linejoin="round"/></svg></span>');
      }
    }
    if(!item.refreshable && iconNode){
      iconNode.remove();
    }
  }

  function selectNode(button, silent){
    if(!button) return;
    var box = document.getElementById('node-list');
    Array.prototype.forEach.call(box.querySelectorAll('.node.selected'), function(node){
      node.classList.remove('selected');
    });
    button.classList.add('selected');
    nodeState.selectedSig = button.getAttribute('data-node-sig') || '';
    writeUiState({selectedNodeSig: nodeState.selectedSig});
    renderNodeViewer(button);
    if(!silent){
      button.scrollIntoView({block: 'nearest'});
    }
  }
  window.selectNode = selectNode;

  function escHtml(s){
    return String(s)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function escRegExp(s){
    return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function hiText(text, keyword){
    text = String(text || '');
    if(!keyword) return escHtml(text);
    var re = new RegExp('(' + escRegExp(keyword) + ')', 'ig');
    return text.split(re).map(function(part){
      return part.toLowerCase() === keyword.toLowerCase()
        ? '<mark>' + escHtml(part) + '</mark>'
        : escHtml(part);
    }).join('');
  }

  // 加载函数
  function loadStatus(){
    return api('/api/status').then(function(data){
      var s = data.status;
      applyStatusState(s);
      writeUiCache({status: {
        service_status: s.service_status,
        service_manager: s.service_manager,
        node_count: s.node_count,
        dae_version: s.dae_version,
        refreshed_at: s.refreshed_at,
        nodes: s.nodes || []
      }});
    });
  }

  function mergeHeroCards(items){
    var box = document.getElementById('hero-kpis');
    if(!box || !items || !items.length) return;
    var current = Array.prototype.slice.call(box.querySelectorAll('.hero-kpi'));
    var byId = {};
    current.forEach(function(node){
      var id = node.getAttribute('data-card-id');
      if(id) byId[id] = node;
    });
    items.forEach(function(item){
      if(!item || !item.id || !byId[item.id]) return;
      updateHeroCard(byId[item.id], item);
    });
  }

  function loadOverview(section, opts){
    opts = opts || {};
    var query = ['section=' + encodeURIComponent(section || 'all')];
    if(opts.site){ query.push('site=' + encodeURIComponent(opts.site)); }
    if(opts.force){ query.push('force=1'); }
    return api('/api/overview?' + query.join('&')).then(function(data){
      var items = data.cards || [];
      if(section === 'runtime') dashboardState.runtimeCards = items;
      if(opts.partial){ mergeHeroCards(items); }
      else{ renderHeroKpis(items); }
      if(section === 'runtime') mergeCachedCardBucket('runtimeCards', items);
      if(section === 'sites') mergeCachedCardBucket('siteCards', items);
      return data;
    });
  }

  function loadConfig(){
    return api('/api/config').then(function(data){
      var editor = document.getElementById('config-editor');
      var incoming = data.content || '';
      if(editor && document.activeElement !== editor && editor.value !== incoming){
        editor.value = incoming;
      }
      setTextTitle('config-hint', '路径：' + (data.path || ''));
    });
  }

  function loadLogs(opts){
    opts = opts || {};
    if(logState.refreshInFlight) return Promise.resolve();
    var n = parseInt(document.getElementById('log-lines').value, 10) || 500;
    n = Math.max(20, Math.min(500, n));
    document.getElementById('log-lines').value = String(n);
    logState.refreshInFlight = true;
    return api('/api/logs?lines=' + n).then(function(data){
      var incoming = Array.isArray(data.entries) ? data.entries : [];
      logState.entries = filterEntriesAfterClear(incoming);
      logState.source = data.source || '-';
      logState.limit = data.limit || 500;
      logState.fetchedAt = data.fetched_at || '';
      writeUiCache({logs: {entries: logState.entries, source: logState.source, limit: logState.limit, fetched_at: logState.fetchedAt}});
      renderLogs();
      logState.refreshInFlight = false;
      return data;
    }, function(err){
      logState.refreshInFlight = false;
      if(opts.silent) return null;
      throw err;
    });
  }

  function renderLogs(){
    var box = document.getElementById('log-box');
    var summary = document.getElementById('log-summary');
    var keyword = (document.getElementById('log-search').value || '').trim();
    var reverse = !!document.getElementById('log-reverse').checked;
    var items = (logState.entries || []).slice();
    var totalItems = (logState.entries || []).slice();

    if(keyword){
      var needle = keyword.toLowerCase();
      items = items.filter(function(item){
        return [item.raw, item.message, item.service, item.timestamp, item.level].some(function(part){
          return String(part || '').toLowerCase().indexOf(needle) !== -1;
        });
      });
    }
    if(reverse) items.reverse();

    var errorCount = 0;
    var warnCount = 0;
    totalItems.forEach(function(item){
      var level = String(item.level || 'info').toLowerCase();
      if(level === 'error') errorCount += 1;
      else if(level === 'warn') warnCount += 1;
    });
    setText('log-stat-shown', String(items.length));
    setText('log-stat-error', String(errorCount));
    setText('log-stat-warn', String(warnCount));
    setText('log-stat-source', logState.source || '-');
    summary.textContent = items.length + ' / ' + totalItems.length + (logState.fetchedAt ? ' · ' + logState.fetchedAt : '');

    if(!items.length){
      box.innerHTML = '<div class="log-empty">' + (keyword
        ? '没有匹配结果'
        : '暂无日志') + '</div>';
      return;
    }

    box.innerHTML = '<div class="log-list">' + items.map(function(item){
      var level = String(item.level || 'info').toLowerCase();
      var klass = (level === 'warn' || level === 'error' || level === 'debug') ? ' ' + level : '';
      var message = item.message || item.raw || '（空日志）';
      var extraTags = (item.tags || []).map(function(tag){
        return '<span class="log-tag ' + escHtml(tag.tone || 'muted') + '">' + hiText(tag.text || '', keyword) + '</span>';
      }).join('');
      return '<div class="log-item' + klass + '">'
        + '<div class="log-head"><div class="log-tags">'
        + '<span class="log-level ' + escHtml(level) + '">' + escHtml(level) + '</span>'
        + (item.timestamp ? '<span class="log-tag muted">' + hiText(fmtLogTime(item.timestamp), keyword) + '</span>' : '')
        + extraTags
        + '</div></div>'
        + '<div class="log-msg">' + hiText(message, keyword) + '</div>'
        + '</div>';
    }).join('') + '</div>';
  }
  window.renderLogs = renderLogs;

  function clearLogsView(){
    var current = logState.entries || [];
    if(current.length){
      logState.clearedAfterSig = logEntrySig(current[current.length - 1]);
    }
    logState.entries = [];
    logState.fetchedAt = '';
    // 清空缓存日志，避免刷新页面后又重新出现
    writeUiCache({logs: {entries: [], source: logState.source, limit: logState.limit, fetched_at: ''}});
    // 记录清空位置，刷新后依然只看新日志
    writeUiState({clearedAfterSig: logState.clearedAfterSig});
    document.getElementById('log-search').value = '';
    renderLogs();
  }
  window.clearLogsView = clearLogsView;

  function loadAll(opts){
    opts = opts || {};
    // 先刷新快速接口，不阻塞站点延迟探测
    return Promise.all([
      loadStatus().catch(handleErr),
      loadOverview('runtime', {partial: true}).catch(handleErr),
      loadConfig().catch(handleErr),
      loadLogs().catch(handleErr)
    ]).then(function(results){
      if(opts.withSites !== false){
        refreshSiteCardsAsync(!!opts.forceSites);
      }
      return results;
    });
  }
  window.loadAll = loadAll;

  function isExpanded(id){
    var card = document.getElementById(id);
    return !!(card && !card.classList.contains('collapsed'));
  }

  function refreshDashboard(){
    return Promise.all([
      loadStatus().catch(handleErr),
      loadOverview('runtime', {partial: true}).catch(handleErr)
    ]).then(function(){
      refreshSiteCardsAsync(true);
      if(isExpanded('card-logs')){
        loadLogs().catch(handleErr);
      }
    });
  }
  window.refreshDashboard = refreshDashboard;

  // ── 更新功能 ─────────────────────────────────────────────────────
  function parseRunId(val) {
    val = (val || '').trim();
    // 完整 URL：.../actions/runs/12345678
    var m = val.match(/actions\/runs\/(\d+)/);
    if (m) return m[1];
    // 纯数字
    if (/^\d+$/.test(val)) return val;
    return null;
  }

  function onUpdateInputChange() {
    var val = document.getElementById('update-run-input').value;
    var rid = parseRunId(val);
    var hint = document.getElementById('update-hint');
    if (!val) {
      hint.textContent = '粘贴 Actions 链接或 Run ID';
    } else if (rid) {
      hint.textContent = 'Run ID: ' + rid;
    } else {
      hint.textContent = '格式有误，请输入链接或纯数字 ID';
    }
  }

  var _updateRunning = false;

  function startUpdate() {
    if (_updateRunning) return;
    var val = document.getElementById('update-run-input').value;
    var rid = parseRunId(val);
    if (!rid) {
      showToast('请输入有效的 Actions Run 链接或 ID', 'warn');
      return;
    }
    var ghToken = getToken();
    var logBox = document.getElementById('update-log-box');
    logBox.style.display = 'block';
    logBox.innerHTML = '';
    _updateRunning = true;
    document.getElementById('update-btn').disabled = true;

    function appendLine(level, msg) {
      var color = {step:'var(--acc)', warn:'var(--warn)', error:'var(--bad)', done:'#22c55e'}[level] || 'var(--tx2)';
      var prefix = {step:'▶ ', warn:'⚠ ', error:'✗ ', done:'✓ '}[level] || '  ';
      var el = document.createElement('div');
      el.style.cssText = 'color:' + color + ';padding:1px 0';
      el.textContent = prefix + msg;
      logBox.appendChild(el);
      logBox.scrollTop = logBox.scrollHeight;
    }

    fetch('/api/update', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-Token': ghToken},
      body: JSON.stringify({run_id: rid, gh_token: ghToken})
    }).then(function(resp) {
      if (!resp.ok) {
        return resp.json().then(function(d) {
          throw new Error(d.message || '请求失败');
        });
      }
      var reader = resp.body.getReader();
      var decoder = new TextDecoder();
      var buf = '';
      function read() {
        return reader.read().then(function(r) {
          if (r.done) {
            _updateRunning = false;
            document.getElementById('update-btn').disabled = false;
            return;
          }
          buf += decoder.decode(r.value, {stream: true});
          var parts = buf.split('\x0a\x0a');
          buf = parts.pop();
          parts.forEach(function(part) {
            var line = part.replace(/^data: /, '').trim();
            if (!line) return;
            try {
              var obj = JSON.parse(line);
              appendLine(obj.level, obj.msg);
              if (obj.level === 'done') {
                setTimeout(function() { refreshDashboard(); }, 1500);
              }
            } catch(e) {}
          });
          return read();
        });
      }
      return read();
    }).catch(function(e) {
      appendLine('error', e.message || String(e));
      _updateRunning = false;
      document.getElementById('update-btn').disabled = false;
    });
  }
  window.startUpdate = startUpdate;
  window.onUpdateInputChange = onUpdateInputChange;

  // Refresh site latency cards asynchronously without blocking the rest of the dashboard.
  function refreshSiteCardsAsync(force){
    if(overviewRefreshState.siteBusy) return Promise.resolve();
    overviewRefreshState.siteBusy = true;
    return loadOverview('sites', {partial: true, force: !!force}).catch(function(){}).then(function(){
      overviewRefreshState.siteBusy = false;
    }, function(){
      overviewRefreshState.siteBusy = false;
    });
  }

  function refreshRuntimeCards(silent){
    if(overviewRefreshState.runtimeBusy) return Promise.resolve();
    overviewRefreshState.runtimeBusy = true;
    return loadOverview('runtime', {partial: true}).catch(function(err){
      if(!silent) handleErr(err);
    }).then(function(){
      overviewRefreshState.runtimeBusy = false;
    });
  }

  function refreshLatencyCard(cardId){
    if(overviewRefreshState.siteBusy) return Promise.resolve();
    overviewRefreshState.siteBusy = true;
    return loadOverview('sites', {site: cardId, force: true, partial: true}).catch(handleErr).then(function(){
      overviewRefreshState.siteBusy = false;
    });
  }
  window.refreshLatencyCard = refreshLatencyCard;

  function handleErr(e){
    showToast(e.message || String(e), true);
  }

  // 动作
  function runAction(action){
    var btns = Array.prototype.slice.call(document.querySelectorAll('button'));
    btns.forEach(function(b){ b.disabled = true; });
    api('/api/action', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({action: action})
    }).then(function(data){
      showToast(data.message, false);
      btns.forEach(function(b){ b.disabled = false; });
      loadAll().catch(handleErr);
      refreshSiteCardsAsync();
    }).catch(function(e){
      handleErr(e);
      btns.forEach(function(b){ b.disabled = false; });
    });
  }
  window.runAction = runAction;

  function validateDraft(){
    var content = document.getElementById('config-editor').value;
    api('/api/validate', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({content: content})
    }).then(function(data){
      showToast(data.message, false);
    }).catch(handleErr);
  }
  window.validateDraft = validateDraft;

  function saveConfig(reload){
    var content = document.getElementById('config-editor').value;
    var btns = Array.prototype.slice.call(document.querySelectorAll('button'));
    btns.forEach(function(b){ b.disabled = true; });
    api('/api/config', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({content: content, reload: !!reload})
    }).then(function(data){
      setText('config-hint', data.message);
      showToast(data.message, false);
      btns.forEach(function(b){ b.disabled = false; });
      // 保存成功后异步刷新，避免阻塞界面
      loadAll().catch(handleErr);
      if(reload){ refreshSiteCardsAsync(); }
    }).catch(function(e){
      handleErr(e);
      btns.forEach(function(b){ b.disabled = false; });
    });
  }
  window.saveConfig = saveConfig;

  window.loadConfig = function(){
    loadConfig().catch(handleErr);
  };
  window.loadLogs = function(){
    loadLogs().catch(handleErr);
  };

  function autoRefreshTick(){
    loadStatus().catch(function(){});
  }

  function logAutoRefreshTick(){
    var autoRefresh = document.getElementById('log-auto-refresh');
    if(autoRefresh && autoRefresh.checked && isExpanded('card-logs')){
      loadLogs({silent: true}).catch(function(){});
    }
  }

  function syncLogAutoButton(){
    var cb = document.getElementById('log-auto-refresh');
    var button = document.getElementById('btn-log-auto');
    if(!cb || !button) return;
    var enabled = !!cb.checked;
    button.classList.toggle('active', enabled);
    button.title = enabled ? '暂停刷新日志' : '恢复刷新日志';
    button.setAttribute('aria-label', enabled ? '暂停刷新日志' : '恢复刷新日志');
    button.innerHTML = enabled
      ? '<svg viewBox="0 0 24 24"><path d="M8 6v12M16 6v12" stroke-linecap="round"/></svg>'
      : '<svg viewBox="0 0 24 24"><polygon points="8,6 18,12 8,18" fill="currentColor" stroke="none"/></svg>';
  }

  // 辅助
  function setText(id, val){
    var el = document.getElementById(id);
    if(el) el.textContent = val;
  }

  // 将 "2026-03-30 18:03:00" 精简为 "18:03:00"（同日）或 "03-30 18:03"（跨日）
  function fmtShortTime(s){
    if(!s || s === '--') return s;
    var m = s.match(/(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2})(:\d{2})?/);
    if(!m) return s;
    var today = new Date();
    var sy = parseInt(m[1]), smo = parseInt(m[2]), sd = parseInt(m[3]);
    if(sy === today.getFullYear() && smo === (today.getMonth()+1) && sd === today.getDate()){
      return m[4] + (m[5]||'');
    }
    return m[2]+'-'+m[3]+' '+m[4];
  }

  // 日志时间戳精简：只保留 HH:MM:SS，去掉日期和时区
  function fmtLogTime(ts){
    if(!ts) return '';
    var m = ts.match(/T(\d{2}:\d{2}:\d{2})/);
    if(m) return m[1];
    m = ts.match(/\d{4}-\d{2}-\d{2}[ T](\d{2}:\d{2}:\d{2})/);
    if(m) return m[1];
    m = ts.match(/\w{3}\s+\d+\s+(\d{2}:\d{2}:\d{2})/);
    if(m) return m[1];
    return ts;
  }

  function setTextTitle(id, val){
    var el = document.getElementById(id);
    if(el){ el.textContent = val; el.title = val; }
  }

  function toggleCollapse(id){
    var card = document.getElementById(id);
    if(!card) return;
    var isCollapsed = card.classList.toggle('collapsed');
    var btn = card.querySelector('.toggle-h');
    if(btn) btn.setAttribute('aria-expanded', String(!isCollapsed));
    var state = readUiState();
    var collapsedCards = state.collapsedCards || {};
    collapsedCards[id] = isCollapsed;
    writeUiState({collapsedCards: collapsedCards});
    // 日志面板展开后补刷一次最新日志
    if(id === 'card-logs' && !isCollapsed){
      loadLogs({silent: true}).catch(function(){});
    }
  }
  window.toggleCollapse = toggleCollapse;

  function toggleLogReverse(){
    var cb = document.getElementById('log-reverse');
    cb.checked = !cb.checked;
    document.getElementById('btn-log-reverse').classList.toggle('active', cb.checked);
    renderLogs();
  }
  window.toggleLogReverse = toggleLogReverse;

  function toggleLogAuto(){
    var cb = document.getElementById('log-auto-refresh');
    cb.checked = !cb.checked;
    syncLogAutoButton();
  }
  window.toggleLogAuto = toggleLogAuto;

  // 初始化
  hydrateUiFromCache();
  syncLogAutoButton();
  finishBoot();
  loadAll({withSites: true, forceSites: true});
  setInterval(autoRefreshTick, 5000);
  setInterval(logAutoRefreshTick, 1000);
  setInterval(function(){ refreshRuntimeCards(true); }, 1000);
  setInterval(function(){ refreshSiteCardsAsync(false); }, 30000);

})();
</script>
</body>
</html>
"""


def json_bytes(payload):
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def parse_node_url(raw):
    raw = raw.strip().strip("'\"")
    fragment = re.search(r"#(.+)$", raw)
    name = unquote(fragment.group(1).strip()) if fragment else None
    body = raw[: fragment.start()] if fragment else raw

    proto_match = re.match(r"(\w+)://", body)
    proto = proto_match.group(1).lower() if proto_match else "unknown"

    if proto == "vmess":
        try:
            import base64

            payload = body[8:]
            decoded = json.loads(base64.b64decode(payload + "==" * 2).decode())
            host = decoded.get("add", "")
            port = int(decoded.get("port", 443))
            if not name:
                name = decoded.get("ps", f"vmess:{host}")
            return name or "Unnamed node", host, port, proto
        except Exception:
            return name or raw[:24], "-", 443, proto

    no_query = body.split("?")[0]
    netloc_match = re.search(r"://(.+)$", no_query)
    if not netloc_match:
        return name or raw[:24], "-", 443, proto
    netloc = netloc_match.group(1)
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    v6 = re.match(r"^\[([^\]]+)\]:(\d+)", netloc)
    if v6:
        host, port = v6.group(1), int(v6.group(2))
    else:
        parts = netloc.rstrip("/").split(":")
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 443

    return name or f"{host}:{port}", host or "-", port, proto


def read_nodes_from_config(limit=12):
    cfg_path = Path(dae_manager.DAE_CFG)
    if not cfg_path.exists():
        return [], 0, ""
    content = cfg_path.read_text(encoding="utf-8", errors="replace")
    block = re.search(r"\bnode\s*\{([^}]*)\}", content, re.DOTALL)
    if not block:
        return [], 0, ""

    nodes = []
    for raw_line in block.group(1).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        matched = re.search(r"'([^']+)'|\"([^\"]+)\"", line)
        if not matched:
            continue
        url = matched.group(1) or matched.group(2)
        name, host, port, proto = parse_node_url(url)
        nodes.append({"name": name, "host": host, "port": port, "proto": proto})

    return nodes[:limit], len(nodes), ""


def get_cached_node_probe(cache_key, now):
    with NODE_PROBE_LOCK:
        cached = NODE_PROBE_CACHE.get(cache_key)
        if not cached:
            return None
        if now - cached["checked_at"] > NODE_PROBE_CACHE_TTL:
            return None
        return dict(cached)


def store_cached_node_probe(cache_key, result, now):
    with NODE_PROBE_LOCK:
        NODE_PROBE_CACHE[cache_key] = {
            "latency_ms": result.get("latency_ms"),
            "latency_text": result.get("latency_text"),
            "latency_tone": result.get("latency_tone"),
            "latency_hint": result.get("latency_hint"),
            "checked_at": now,
        }


def get_cached_site_probe(cache_key, now):
    with SITE_PROBE_LOCK:
        cached = SITE_PROBE_CACHE.get(cache_key)
        if not cached:
            return None
        if now - cached["checked_at"] > SITE_PROBE_CACHE_TTL:
            return None
        return dict(cached)


def store_cached_site_probe(cache_key, result, now):
    with SITE_PROBE_LOCK:
        SITE_PROBE_CACHE[cache_key] = dict(result, checked_at=now)


def classify_latency_tone(latency_ms):
  if latency_ms is None or latency_ms <= 0:
    return "muted"
  if latency_ms <= 100:
    return "fast"
  if latency_ms <= 250:
    return "warn"
  return "bad"


def normalize_latency_result(latency_ms, success_hint, unavailable_hint):
    if latency_ms is None or latency_ms <= 0:
        return {
            "latency_ms": None,
            "latency_text": "--",
            "latency_tone": "muted",
            "latency_hint": unavailable_hint,
        }
    return {
        "latency_ms": latency_ms,
        "latency_text": f"{latency_ms} ms",
        "latency_tone": classify_latency_tone(latency_ms),
        "latency_hint": success_hint.format(latency_ms=latency_ms),
    }


def format_duration(seconds):
  if seconds is None or seconds < 0:
    return "--"
  seconds = int(seconds)
  days, rem = divmod(seconds, 86400)
  hours, rem = divmod(rem, 3600)
  minutes, secs = divmod(rem, 60)
  clock = f"{hours:02d}:{minutes:02d}:{secs:02d}"
  if days:
    return f"{days}d {clock}"
  return clock


def format_bytes(num_bytes):
    if num_bytes is None or num_bytes < 0:
        return "--"
    value = float(num_bytes)
    units = ["B", "KB", "MB", "GB", "TB"]
    unit = units[0]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            break
        value /= 1024.0
    if unit in ("B", "KB"):
        return f"{int(round(value))} {unit}"
    return f"{value:.1f} {unit}"


def read_proc_uptime_seconds():
    try:
        raw = Path("/proc/uptime").read_text(encoding="utf-8", errors="replace").split()[0]
        return float(raw)
    except Exception:
        return None


def get_service_uptime_seconds(service_manager, service_status):
    if service_status != "active":
        return None

    if service_manager == "systemd":
        ok, out = run_command(["systemctl", "show", "dae", "-p", "ActiveEnterTimestampMonotonic", "--value"], timeout=10)
        if ok:
            try:
                active_us = int(str(out).strip().splitlines()[-1])
                if active_us > 0:
                    boot_seconds = read_proc_uptime_seconds()
                    if boot_seconds is not None:
                        return max(0, int(round(boot_seconds - (active_us / 1000000.0))))
            except (TypeError, ValueError, IndexError):
                pass

    ok, out = run_command(["ps", "-C", "dae", "-o", "etimes="], timeout=10)
    if ok:
        for line in str(out).splitlines():
            line = line.strip()
            if line.isdigit():
                return int(line)
    return None


def get_service_memory_bytes(service_manager, service_status):
    if service_status != "active":
        return None

    # 优先使用 ps RSS，和 htop 的 RES 更接近
    ok, out = run_command(["ps", "-C", "dae", "-o", "rss="], timeout=10)
    if ok:
        for line in str(out).splitlines():
            line = line.strip()
            if line.isdigit():
                return int(line) * 1024

    # 回退到 systemd cgroup 的 MemoryCurrent，通常会比 RSS 略高
    if service_manager == "systemd":
        ok, out = run_command(["systemctl", "show", "dae", "-p", "MemoryCurrent", "--value"], timeout=10)
        if ok:
            value = str(out).strip().splitlines()[-1] if str(out).strip() else ""
            if value.isdigit():
                parsed = int(value)
                if parsed > 0:
                    return parsed

    return None


def get_kernel_version():
    release = str(platform.release() or "").strip()
    return release or "--"


def get_dae_version():
    version = str(dae_manager.local_ver() or "").strip()
    return version or "Not installed"


def probe_site_latency(card_id, label, url, force=False):
    now = time.time()
    cached = None if force else get_cached_site_probe(url, now)
    if cached:
        return cached

    if not shutil.which("curl"):
        result = {
            "id": card_id,
            "label": label,
            "value": "--",
            "tone": "muted",
        "hint": "curl is not installed on this system",
            "refreshable": True,
        }
        store_cached_site_probe(url, result, now)
        return result

    target_sink = "NUL" if os.name == "nt" else "/dev/null"
    cmd = [
        "curl",
        "-L",
        "-o",
        target_sink,
        "-sS",
        "-w",
        "%{time_total}",
        "--connect-timeout",
        str(SITE_PROBE_CONNECT_TIMEOUT),
        "--max-time",
        str(SITE_PROBE_TIMEOUT),
        url,
    ]
    ok, out = run_command(cmd, timeout=SITE_PROBE_TIMEOUT + 2)
    if ok:
        matched = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*$", str(out).strip())
        if matched:
            latency_ms = int(round(float(matched.group(1)) * 1000))
            normalized = normalize_latency_result(
                latency_ms,
                f"curl request to {label} succeeded in {{latency_ms}} ms",
                f"curl request to {label} returned 0 ms and was treated as unavailable",
            )
            result = {
                "id": card_id,
                "label": label,
                "value": normalized["latency_text"],
                "tone": normalized["latency_tone"],
                "hint": normalized["latency_hint"],
                "refreshable": True,
            }
            store_cached_site_probe(url, result, now)
            return result

    result = {
        "id": card_id,
        "label": label,
        "value": "Failed",
        "tone": "fail",
        "hint": f"curl request to {label} failed or timed out",
        "refreshable": True,
    }
    store_cached_site_probe(url, result, now)
    return result


def collect_runtime_cards(service_manager, service_status):
  uptime_seconds = get_service_uptime_seconds(service_manager, service_status)
  memory_bytes = get_service_memory_bytes(service_manager, service_status)
  kernel_version = get_kernel_version()

  return [
    {
      "id": "uptime",
      "label": "Uptime",
      "value": format_duration(uptime_seconds),
      "tone": "muted" if uptime_seconds is None else "accent",
      "hint": "Current daemon uptime" if uptime_seconds is not None else "Service is offline or uptime is temporarily unavailable",
      "refreshable": False,
    },
    {
      "id": "memory",
      "label": "Memory",
      "value": format_bytes(memory_bytes),
      "tone": "muted" if memory_bytes is None else "accent",
      "hint": "Current dae process memory footprint" if memory_bytes is not None else "Service is offline or memory data is temporarily unavailable",
      "refreshable": False,
    },
    {
      "id": "kernel-version",
            "label": "Kernel",
      "value": kernel_version,
      "tone": "accent" if kernel_version != "--" else "muted",
      "hint": "当前系统内核版本",
      "refreshable": False,
    },
  ]


def collect_site_cards(force=False, target=None):
    cards = []
    for card_id, payload in SITE_PROBE_TARGETS.items():
        if target and card_id != target:
            continue
        label, url = payload
        cards.append(probe_site_latency(card_id, label, url, force=force))
    return cards


def collect_overview_cards(service_manager, service_status, section="all", force=False, target=None):
    cards = []
    if section in {"all", "runtime"}:
        cards.extend(collect_runtime_cards(service_manager, service_status))
    if section in {"all", "sites"}:
        cards.extend(collect_site_cards(force=force, target=target))
    return cards


def probe_icmp_latency(host):
    if not shutil.which("ping"):
        return None

    cmd = ["ping", "-n", "-c", "1", "-W", str(int(NODE_PING_TIMEOUT)), host]
    rc, out = dae_manager.run(cmd, timeout=max(2, int(NODE_PING_TIMEOUT) + 1))
    if rc != 0 or not out:
        return None

    matched = re.search(r"time[=<]([0-9.]+)\s*ms", out, flags=re.IGNORECASE)
    if not matched:
        return None

    latency_ms = int(round(float(matched.group(1))))
    return normalize_latency_result(
        latency_ms,
      "ICMP ping probe succeeded in {latency_ms} ms",
      "ICMP ping returned 0 ms and was treated as unavailable",
    )


def probe_node_latency(node):
  host = str(node.get("host") or "").strip()
  port = int(node.get("port") or 0)
  cache_key = f"{host}:{port}"
  now = time.time()
  cached = get_cached_node_probe(cache_key, now)
  if cached:
    return cached

  if not host or host == "-" or port <= 0:
    result = {
      "latency_ms": None,
      "latency_text": "--",
      "latency_tone": "muted",
      "latency_hint": "Node is missing a probeable host or port",
    }
    store_cached_node_probe(cache_key, result, now)
    return result

  ping_result = probe_icmp_latency(host)
  if ping_result:
    store_cached_node_probe(cache_key, ping_result, now)
    return ping_result

  try:
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=NODE_PROBE_TIMEOUT):
      pass
    latency_ms = int(round((time.perf_counter() - started) * 1000))
    result = normalize_latency_result(
      latency_ms,
      "ICMP probe unavailable; TCP connect probe completed in {latency_ms} ms",
      "TCP connect probe returned 0 ms and was treated as unavailable",
    )
  except socket.timeout:
    result = {
      "latency_ms": None,
      "latency_text": "Timeout",
      "latency_tone": "fail",
      "latency_hint": f"TCP connect timed out after {int(NODE_PROBE_TIMEOUT * 1000)} ms",
    }
  except OSError as exc:
    result = {
      "latency_ms": None,
      "latency_text": "Failed",
      "latency_tone": "fail",
      "latency_hint": f"Probe failed: {exc}",
    }

  store_cached_node_probe(cache_key, result, now)
  return result


def sort_nodes_by_latency(nodes):
  def sort_key(node):
    latency_ms = node.get("latency_ms")
    if latency_ms is None or latency_ms <= 0:
      return (1, float("inf"), str(node.get("name") or ""))
    return (0, latency_ms, str(node.get("name") or ""))

  return sorted(nodes, key=sort_key)


def attach_node_latency(nodes):
    if not nodes:
        return []

    enriched = [dict(node) for node in nodes]
    worker_count = min(len(enriched), NODE_PROBE_MAX_WORKERS)
    if worker_count <= 0:
        return enriched

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = list(executor.map(probe_node_latency, enriched))

    for node, latency in zip(enriched, results):
        node.update(latency)
    return sort_nodes_by_latency(enriched)


def build_service_manager():
    if dae_manager.is_systemd():
        return "systemd"
    if dae_manager.is_openrc():
        return "openrc"
    return "unknown"


def run_command(cmd, timeout=30):
    rc, out = dae_manager.run(cmd, timeout=timeout)
    return rc == 0, out or ""


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

LEVEL_TOKEN_MAP = {
  "panic": "error",
  "fatal": "error",
  "crit": "error",
  "critical": "error",
  "err": "error",
  "error": "error",
  "warn": "warn",
  "warning": "warn",
  "wrn": "warn",
  "notice": "info",
  "info": "info",
  "inf": "info",
  "debug": "debug",
  "dbg": "debug",
  "trace": "debug",
  "trc": "debug",
}

FIELD_TAG_SPECS = [
  ("component", "accent"),
  ("module", "accent"),
  ("subsystem", "accent"),
  ("inbound", "accent"),
  ("outbound", "accent"),
  ("network", "muted"),
  ("proto", "muted"),
  ("transport", "muted"),
  ("group", "accent"),
  ("node", "accent"),
  ("mode", "warn"),
  ("policy", "warn"),
]

KEYWORD_TAG_SPECS = [
  ("dns", "accent"),
  ("route", "accent"),
  ("routing", "accent"),
  ("sniff", "accent"),
  ("inbound", "accent"),
  ("outbound", "accent"),
  ("proxy", "accent"),
  ("direct", "accent"),
  ("block", "warn"),
  ("reject", "bad"),
  ("tcp", "muted"),
  ("udp", "muted"),
  ("quic", "muted"),
  ("tls", "muted"),
  ("dial", "muted"),
  ("conn", "muted"),
]


def strip_ansi(value):
  return ANSI_ESCAPE_RE.sub("", str(value or ""))


def normalize_level_token(token):
  return LEVEL_TOKEN_MAP.get(str(token or "").strip().lower())


def extract_level_from_sample(sample):
  patterns = [
    r"\b(?:level|lvl|severity)\s*[=:]\s*([A-Za-z]+)",
    r"^\[([A-Za-z]{3,8})\]",
    r"\b(PANIC|FATAL|CRIT|CRITICAL|ERR|ERROR|WRN|WARN|WARNING|NOTICE|INF|INFO|DBG|DEBUG|TRC|TRACE)\b",
  ]
  for pattern in patterns:
    for token in re.findall(pattern, sample, flags=re.IGNORECASE):
      level = normalize_level_token(token)
      if level:
        return level
  return None


def infer_log_level(text, raw="", service="dae"):
  sample = f" {strip_ansi(raw or text).lower()} "
  explicit = extract_level_from_sample(sample)
  if explicit:
    return explicit
  if any(word in sample for word in (
    " panic ", " fatal ", " failed ", " failure ", " error ", " exception ", " traceback ",
    " refused ", " unreachable ", " denied ", " broken pipe ", " reset by peer ", " no route ",
    " invalid ", " corrupted ", " handshake failed ", " timed out while dialing ",
  )):
    return "error"
  if any(word in sample for word in (
    " warn ", " warning ", " timeout ", " retry ", " fallback ", " deprecated ", " stale ",
    " dropping ", " blocked ", " skipped ", " mismatch ",
  )):
    return "warn"
  if any(word in sample for word in (
    " debug ", " trace ", " verbose ", " sniffed ", " matched rule ", " selected ", " dialing ",
  )):
    return "debug"
  if "dns" in sample or "route" in sample or "routing" in sample:
    return "info"
  return "info"


def append_log_tag(items, seen, text, tone):
  normalized = str(text or "").strip().strip('"\'')
  if not normalized:
    return
  key = normalized.lower()
  if key in seen:
    return
  seen.add(key)
  items.append({"text": normalized[:48], "tone": tone})


def extract_log_tags(raw, service, message, level):
  sample = strip_ansi(raw or message).lower()
  items = []
  seen = set()

  for field_name, tone in FIELD_TAG_SPECS:
    matched = re.findall(rf"\b{field_name}\s*=\s*(\"[^\"]+\"|'[^']+'|[^\s,;]+)", raw, flags=re.IGNORECASE)
    for value in matched:
      clean = value.strip().strip('"\'')
      append_log_tag(items, seen, f"{field_name}:{clean}", tone)

  for word, tone in KEYWORD_TAG_SPECS:
    if word in sample:
      append_log_tag(items, seen, word, tone)

  if service and service.lower() not in {"dae", "dae.service"}:
    append_log_tag(items, seen, service, "muted")
  if level == "error":
    append_log_tag(items, seen, "error", "bad")
  elif level == "warn":
    append_log_tag(items, seen, "warn", "warn")

  return items[:6]


def parse_log_line(line):
  raw = strip_ansi(line).rstrip()
  if not raw.strip():
    return None

  timestamp = ""
  service = "dae"
  message = raw.strip()
  patterns = [
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<service>[\w@./:-]+?)(?:\[\d+\])?:\s*(?P<message>.*)$",
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[\w@./:-]+?)(?:\[\d+\])?:\s*(?P<message>.*)$",
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<service>[\w@./:-]+?)(?:\[\d+\])?:\s*(?P<message>.*)$",
  ]
  for pattern in patterns:
    matched = re.match(pattern, raw)
    if matched:
      timestamp = matched.groupdict().get("timestamp", "") or ""
      service = matched.groupdict().get("service", "") or service
      message = matched.groupdict().get("message", "") or raw.strip()
      break

  level = infer_log_level(message, raw=raw, service=service)
  return {
    "timestamp": timestamp,
    "service": service,
    "message": message,
    "level": level,
    "tags": extract_log_tags(raw, service, message, level),
    "raw": raw,
  }


def normalize_log_entries(raw_text, limit=500):
  entries = []
  for line in str(raw_text or "").splitlines():
    item = parse_log_line(line)
    if item:
      entries.append(item)
  if len(entries) > limit:
    entries = entries[-limit:]
  return entries


def get_logs(lines=500):
  count = max(20, min(int(lines), 500))
  source = "未知"
  raw_text = ""
  if shutil.which("journalctl") and Path(dae_manager.SYSTEMD_SVC).exists():
    source = "journalctl / dae 服务"
    _, raw_text = dae_manager.run(
      ["journalctl", "-u", "dae", "-n", str(count), "--no-pager", "-o", "short-iso"],
      timeout=20,
    )
  elif Path("/var/log/dae.log").exists():
    source = "/var/log/dae.log"
    _, raw_text = dae_manager.run(["tail", "-n", str(count), "/var/log/dae.log"], timeout=20)
  else:
    return {
      "entries": [],
      "source": "未找到日志来源",
      "limit": 500,
      "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

  return {
    "entries": normalize_log_entries(raw_text, limit=500),
    "source": source,
    "limit": 500,
    "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
  }


def validate_config_content(content):
  if not Path(dae_manager.DAE_BIN).exists():
    return False, f"dae binary not found: {dae_manager.DAE_BIN}"

  cfg_dir = Path(dae_manager.DAE_CFG).parent
  cfg_dir.mkdir(parents=True, exist_ok=True)
  with tempfile.NamedTemporaryFile(
    "w", delete=False, encoding="utf-8", dir=str(cfg_dir), suffix=".dae"
  ) as handle:
    handle.write(content)
    temp_path = handle.name
  try:
    rc, out = dae_manager.run([dae_manager.DAE_BIN, "validate", "-c", temp_path], timeout=60)
    return rc == 0, out or ("Config validation passed" if rc == 0 else "Config validation failed")
  finally:
    Path(temp_path).unlink(missing_ok=True)


def save_config(content, reload_after_save=False):
  ok, output = validate_config_content(content)
  if not ok:
    return False, f"Config validation failed\n\n{output}"

  cfg_path = Path(dae_manager.DAE_CFG)
  cfg_path.parent.mkdir(parents=True, exist_ok=True)
  backup_path = None
  if cfg_path.exists():
    backup_path = f"{dae_manager.DAE_CFG}.backup.{time.strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(cfg_path, backup_path)

  cfg_path.write_text(content, encoding="utf-8")
  os.chmod(cfg_path, 0o600)

  message = "Config saved"
  if backup_path:
    message += f" (backup: {backup_path})"

  if reload_after_save:
    ok, action_msg = perform_action("reload")
    if not ok:
      return False, f"Config saved, but reload failed\n\n{action_msg}"
    message += f" ({action_msg})"
  return True, message


def perform_action(action):
  service_manager = build_service_manager()
  if service_manager == "unknown":
    return False, "No supported service manager found for dae"

  status = dae_manager.svc_status()
  if action == "start":
    if status == "active":
      return True, "Service is already running"
    if not Path(dae_manager.DAE_BIN).exists():
      return False, f"dae binary not found: {dae_manager.DAE_BIN}"
    cmd = ["systemctl", "start", "dae"] if service_manager == "systemd" else [dae_manager.OPENRC_SVC, "start"]
    ok, out = run_command(cmd)
    return ok, out or "Service started"

  if action == "stop":
    if status != "active":
      return True, f"Service is not running (status: {status})"
    cmd = ["systemctl", "stop", "dae"] if service_manager == "systemd" else [dae_manager.OPENRC_SVC, "stop"]
    ok, out = run_command(cmd)
    return ok, out or "Service stopped"

  if action == "restart":
    cmd = ["systemctl", "restart", "dae"] if service_manager == "systemd" else [dae_manager.OPENRC_SVC, "restart"]
    ok, out = run_command(cmd)
    return ok, out or "Service restarted"

  if action == "reload":
    cfg_path = Path(dae_manager.DAE_CFG)
    if not cfg_path.exists():
      return False, f"Config file not found: {dae_manager.DAE_CFG}"
    ok, out = validate_config_content(cfg_path.read_text(encoding="utf-8", errors="replace"))
    if not ok:
      return False, out
    if service_manager == "systemd":
      ok, out = run_command(["systemctl", "reload", "dae"])
      if not ok:
        ok, out = run_command(["systemctl", "restart", "dae"])
    else:
      ok, out = run_command([dae_manager.OPENRC_SVC, "reload"])
      if not ok:
        ok, out = run_command([dae_manager.OPENRC_SVC, "restart"])
    return ok, out or "Config reloaded"

  return False, f"Unsupported action: {action}"



def perform_update(run_id, gh_token, sse):
    """
    从 GitHub Actions run_id 下载构建产物并替换本地 dae 二进制。
    sse(level, msg) 是流式回调，level 为 'info'/'step'/'warn'/'error'/'done'。
    """
    import zipfile, tempfile

    sse("step", f"获取 Run {run_id} 的构建产物列表…")
    artifacts, err = dae_manager.get_run_artifacts(run_id, gh_token)
    if err or not artifacts:
        sse("error", f"获取产物列表失败: {err or '无产物'}")
        return

    sse("info", f"找到 {len(artifacts)} 个产物: " + ", ".join(a["name"] for a in artifacts[:6]))

    # 探测系统架构
    arch, aerr = dae_manager.detect_arch()
    if aerr:
        sse("error", f"架构检测失败: {aerr}")
        return
    base_arch = re.sub(r"_v\d+_.*", "", arch)
    sse("info", f"系统架构: {arch}")

    # 按架构优先级排序产物
    def score(name):
        n = name.lower()
        if arch in n:      return 0
        if base_arch in n: return 1
        if "linux" in n:   return 2
        if n == "dae":     return 3
        return 99

    scored = sorted(artifacts, key=lambda a: score(a["name"]))

    for art in scored[:3]:
        art_name = art["name"]
        art_id   = art["id"]
        dl_url   = art.get("archive_download_url",
                   f"https://api.github.com/repos/daeuniverse/dae/actions/artifacts/{art_id}/zip")
        sse("step", f"下载产物: {art_name}")
        tmp  = tempfile.mkdtemp(prefix="dae.update.")
        dest = os.path.join(tmp, "artifact.zip")

        last_pct = [-1]
        def prog(done, total):
            if total:
                pct = int(done / total * 100)
                if pct != last_pct[0] and pct % 10 == 0:
                    last_pct[0] = pct
                    sse("info", f"下载中 {done/1048576:.1f}/{total/1048576:.1f} MB ({pct}%)")

        ok2, dl_err = dae_manager.gh_api_download(dl_url, dest, gh_token, prog)
        if not ok2:
            shutil.rmtree(tmp, ignore_errors=True)
            sse("warn", f"下载失败: {dl_err}，尝试下一个…")
            continue

        sse("info", "解压中…")
        try:
            with zipfile.ZipFile(dest) as zf:
                zf.extractall(os.path.join(tmp, "ex"))
        except Exception as ze:
            shutil.rmtree(tmp, ignore_errors=True)
            sse("warn", f"解压失败: {ze}，尝试下一个…")
            continue

        # 在解压目录中找 dae 可执行文件
        binary = None
        for root, _, files in os.walk(os.path.join(tmp, "ex")):
            for fn in sorted(files):
                if "dae" in fn.lower() and not fn.endswith((".zip", ".txt", ".md", ".sha256", ".sig")):
                    binary = os.path.join(root, fn)
                    break
            if binary:
                break

        if not binary:
            shutil.rmtree(tmp, ignore_errors=True)
            sse("warn", "压缩包中未找到可执行文件，尝试下一个…")
            continue

        # 停止服务
        was_up = dae_manager.svc_status() == "active"
        if was_up:
            sse("step", "停止服务…")
            if dae_manager.is_systemd():
                dae_manager.run(["systemctl", "stop", "dae"])
            elif dae_manager.is_openrc():
                dae_manager.run([dae_manager.OPENRC_SVC, "stop"])

        # 替换二进制
        sse("step", f"安装到 {dae_manager.DAE_BIN}…")
        Path(dae_manager.DAE_BIN).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(binary, dae_manager.DAE_BIN)
        os.chmod(dae_manager.DAE_BIN, 0o755)
        shutil.rmtree(tmp, ignore_errors=True)

        installed = dae_manager.local_ver() or "（版本未知）"
        sse("info", f"安装成功，版本: {installed}")

        # 重启服务
        if was_up:
            sse("step", "重启服务…")
            if dae_manager.is_systemd():
                dae_manager.run(["systemctl", "start", "dae"])
            elif dae_manager.is_openrc():
                dae_manager.run([dae_manager.OPENRC_SVC, "start"])
            sse("info", "服务已重启")

        sse("done", f"更新完成！当前版本: {installed}")
        return

    sse("error", "所有产物均下载/安装失败，请检查 Token 权限或稍后重试")


def get_nodes_preview(limit=12):
  try:
    nodes, node_count, node_error = read_nodes_from_config(limit=limit)
    return attach_node_latency(nodes), node_count, node_error
  except Exception as exc:
    return [], 0, str(exc)


def get_status_text(service_manager):
  if service_manager == "systemd":
    _, out = dae_manager.run(["systemctl", "status", "dae", "--no-pager"], timeout=20)
    return out or "Unable to read systemd status output"
  if service_manager == "openrc":
    _, out = dae_manager.run([dae_manager.OPENRC_SVC, "status"], timeout=20)
    return out or "Unable to read OpenRC status output"
  return "dae service definition was not found"


def collect_status():
  service_manager = build_service_manager()
  nodes, node_count, node_error = get_nodes_preview()
  cfg_path = Path(dae_manager.DAE_CFG)
  service_status = dae_manager.svc_status()
  dae_version = get_dae_version()
  status = {
    "service_status": service_status,
    "service_manager": service_manager,
    "dae_version": dae_version,
    "bin_path": dae_manager.DAE_BIN,
    "config_path": dae_manager.DAE_CFG,
    "config_exists": cfg_path.exists(),
    "node_count": node_count,
    "nodes": nodes,
    "refreshed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "status_text": get_status_text(service_manager),
  }
  if node_error:
    status["status_text"] += f"\n\nNode parsing note: {node_error}"
  return status


class DaeWebHandler(BaseHTTPRequestHandler):
    server_version = "dae-web/2.0"

    def log_message(self, fmt, *args):
        sys.stdout.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    def write_json(self, code, payload):
        raw = json_bytes(payload)
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def write_html(self, html_text):
        raw = html_text.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.end_headers()
        self.wfile.write(raw)

    def parse_json_body(self):
      length = int(self.headers.get("Content-Length", "0") or "0")
      if length <= 0:
        return {}
      if length > 2 * 1024 * 1024:
        raise ValueError("Request body too large")
      body = self.rfile.read(length)
      if not body:
        return {}
      return json.loads(body.decode("utf-8"))

    def authorized(self):
        token = self.server.auth_token
        if not token:
            return True
        query = parse_qs(urlparse(self.path).query)
        supplied = self.headers.get("X-Auth-Token", "") or query.get("token", [""])[0]
        return hmac.compare_digest(str(supplied), str(token))

    def require_auth(self):
      if self.authorized():
        return True
      self.write_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "message": "Authentication failed. Provide a valid token."})
      return False

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.write_html(HTML_PAGE)
            return
        if not self.require_auth():
            return
        if parsed.path == "/api/status":
            self.write_json(HTTPStatus.OK, {"ok": True, "status": collect_status()})
            return
        if parsed.path == "/api/overview":
          query = parse_qs(parsed.query)
          section = str(query.get("section", ["all"])[0]).strip().lower() or "all"
          if section not in {"all", "runtime", "sites"}:
            self.write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": f"不支持的 section: {section}"})
            return
          target = str(query.get("site", [""])[0]).strip().lower() or None
          if target and target not in SITE_PROBE_TARGETS:
            self.write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": f"不支持的站点: {target}"})
            return
          force = str(query.get("force", ["0"])[0]).strip() in {"1", "true", "yes"}
          service_manager = build_service_manager()
          service_status = dae_manager.svc_status()
          cards = collect_overview_cards(service_manager, service_status, section=section, force=force, target=target)
          self.write_json(HTTPStatus.OK, {"ok": True, "cards": cards})
          return
        if parsed.path == "/api/config":
            cfg_path = Path(dae_manager.DAE_CFG)
            content = (
                cfg_path.read_text(encoding="utf-8", errors="replace") if cfg_path.exists() else ""
            )
            self.write_json(HTTPStatus.OK, {"ok": True, "path": dae_manager.DAE_CFG, "content": content})
            return
        if parsed.path == "/api/logs":
            query = parse_qs(parsed.query)
            lines = query.get("lines", ["500"])[0]
            payload = get_logs(lines)
            payload["ok"] = True
            self.write_json(HTTPStatus.OK, payload)
            return
        self.write_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "Endpoint not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if not self.require_auth():
            return
        try:
            data = self.parse_json_body()
        except (json.JSONDecodeError, ValueError) as exc:
            self.write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": f"请求体无效: {exc}"})
            return

        if parsed.path == "/api/action":
            action = str(data.get("action", "")).strip().lower()
            if action not in {"start", "stop", "restart", "reload"}:
                self.write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": f"不支持的操作: {action}"})
                return
            ok, message = perform_action(action)
            self.write_json(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, {"ok": ok, "message": message})
            return

        if parsed.path == "/api/validate":
            content = str(data.get("content", ""))
            ok, message = validate_config_content(content)
            if ok and "通过" not in message:
              message = f"配置校验通过\n\n{message}"
            self.write_json(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, {"ok": ok, "message": message})
            return

        if parsed.path == "/api/config":
            content = str(data.get("content", ""))
            reload_after_save = bool(data.get("reload", False))
            ok, message = save_config(content, reload_after_save=reload_after_save)
            self.write_json(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST, {"ok": ok, "message": message})
            return

        if parsed.path == "/api/update":
            run_id   = str(data.get("run_id", "")).strip()
            gh_token = str(data.get("gh_token", "")).strip() or dae_manager.load_gh_token()
            if not run_id:
                self.write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "run_id 不能为空"})
                return
            if not run_id.isdigit():
                self.write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "message": "run_id 必须是纯数字"})
                return
            if not gh_token:
                self.write_json(HTTPStatus.BAD_REQUEST, {
                    "ok": False,
                    "message": "需要 GitHub Token（在顶栏访问令牌框输入，或保存到服务器）\nToken 需要 actions:read 权限"
                })
                return

            # SSE 流式响应
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

            def sse(level, msg):
                payload = json.dumps({"level": level, "msg": msg})
                try:
                    self.wfile.write(("data: " + payload + "\n\n").encode())
                    self.wfile.flush()
                except Exception:
                    pass

            try:
                perform_update(run_id, gh_token, sse)
            except Exception as exc:
                sse("error", f"更新异常: {exc}")
            return

        self.write_json(HTTPStatus.NOT_FOUND, {"ok": False, "message": "Endpoint not found"})


def parse_args(argv):
    parser = argparse.ArgumentParser(description="DAE Web Console")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Listen address, default 127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Listen port, default 8080")
    parser.add_argument("--token", default=os.environ.get("DAE_WEB_TOKEN", ""), help="Optional API token")
    return parser.parse_args(argv)


def main(argv=None):
    if sys.platform != "linux":
        sys.exit("This tool only runs on Linux")
    if os.geteuid() != 0:
        sys.exit("Run as root to control the dae service")

    args = parse_args(argv or sys.argv[1:])
    httpd = ThreadingHTTPServer((args.host, args.port), DaeWebHandler)
    httpd.auth_token = args.token

    print(f"{APP_TITLE} started")
    print(f"监听地址: http://{args.host}:{args.port}")
    if args.token:
      print("Token authentication is enabled. Enter the token in the page header.")
    else:
      print("Token authentication is disabled. Bind to a trusted address or protect access externally.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
      print("\nStopping web console")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

