#!/usr/bin/env python3
"""Count TODAY'S real stealth-address registries on-chain.

Grounds the scaling curve in current values: how many announcements do the
deployed SAPs actually have right now, and what would scanning them cost at
our fitted marginal rates (registry_curve.py: ours 44.31 us/ann, DKSAP
27.50 us/ann)?

Targets:
  * canonical ERC-5564 announcer (0x5564...5564, same address cross-chain)
    on mainnet, Base, and Gnosis -- Fluidkey and friends announce here;
  * Umbra's own contract on mainnet (pre-5564, the longest-running EC SAP).

Method: eth_getLogs counted over 9,999-block windows (free-tier cap),
batched 20 windows per HTTP request, adaptive: windows that error (rate
limit / too many results) are split and retried. Free drpc endpoints.

Usage: real_registries.py [--json out] [--targets eth-5564,eth-umbra,...]
"""

import argparse
import json
import os
import time
import urllib.request

ERC5564_ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564"
ERC5564_TOPIC = "0x5f0eab8057630ba7676c49b4f21a0231414e79474595be8e4c432fbf6bf0f4e7"
UMBRA_ADDR = "0xFb2dc580Eed955B528407b4d36FfaFe3da685401"  # same addr cross-chain
UMBRA_TOPIC = "0x29877766fa2bfe3b90008d6d92f965eca91cbc5757ed775740e460799fb92219"

# slug = drpc network slug; free endpoint used unless DRPC_KEY is set
# (key comes from the environment, never from this file).
TARGETS = {
    "eth-5564": dict(slug="ethereum", free="https://eth.drpc.org",
                     address=ERC5564_ANNOUNCER, topic=ERC5564_TOPIC,
                     from_block=19_000_000, block_s=12,
                     label="ERC-5564 canonical announcer, Ethereum mainnet"),
    "eth-umbra": dict(slug="ethereum", free="https://eth.drpc.org",
                      address=UMBRA_ADDR, topic=UMBRA_TOPIC,
                      from_block=12_500_000, block_s=12,
                      label="Umbra, Ethereum mainnet"),
    "base-5564": dict(slug="base", free="https://base.drpc.org",
                      address=ERC5564_ANNOUNCER, topic=ERC5564_TOPIC,
                      from_block=10_000_000, block_s=2, window=2_000,
                      label="ERC-5564 canonical announcer, Base"),
    "gnosis-5564": dict(slug="gnosis", free="https://gnosis.drpc.org",
                        address=ERC5564_ANNOUNCER, topic=ERC5564_TOPIC,
                        from_block=31_000_000, block_s=5,
                        label="ERC-5564 canonical announcer, Gnosis"),
    "op-umbra": dict(slug="optimism", free="https://optimism.drpc.org",
                     address=UMBRA_ADDR, topic=UMBRA_TOPIC,
                     from_block=3_000_000, block_s=2, window=2_000,
                     label="Umbra, Optimism"),
    "poly-umbra": dict(slug="polygon", free="https://polygon.drpc.org",
                       address=UMBRA_ADDR, topic=UMBRA_TOPIC,
                       from_block=25_000_000, block_s=2, window=2_000,
                       label="Umbra, Polygon"),
    # Umbra Arbitrum exists at the same address, but ~400M 0.3s-blocks at the
    # 10k-window cap is impractical to count on this tier; noted, not counted.
}

DRPC_KEY = os.environ.get("DRPC_KEY", "")
WINDOW = 9_999  # 10k-range cap applies on this drpc tier regardless of key
BATCH = 3       # "Batch of more than 3 requests are not allowed"
PACE_S = 0.08

# fitted marginal scan costs, us/announcement (registry_curve.py, 2026-08-02)
OURS_US, DKSAP_US = 44.31, 27.50


def rpc_call(url, payload, tries=5):
    data = json.dumps(payload).encode()
    for attempt in range(tries):
        try:
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json",
                         # drpc 403s the default urllib UA; curl's is fine
                         "User-Agent": "curl/8.4.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = b""
            try:
                body = e.read()
            except Exception:
                pass
            # drpc serves per-item JSON errors under HTTP 4xx/5xx; surface
            # them to the caller so the adaptive splitter can react.
            try:
                return json.loads(body)
            except Exception:
                pass
            wait = 2 ** attempt
            print(f"    http error ({e}) body={body[:160]!r}; retry in {wait}s",
                  flush=True)
            time.sleep(wait)
        except Exception as e:
            wait = 2 ** attempt
            print(f"    http error ({e}); retry in {wait}s", flush=True)
            time.sleep(wait)
    raise RuntimeError(f"rpc failed after {tries} tries: {url}")


def latest_block(url, tries=6):
    for attempt in range(tries):
        r = rpc_call(url, {"jsonrpc": "2.0", "id": 1,
                           "method": "eth_blockNumber", "params": []})
        if isinstance(r, dict) and "result" in r:
            return int(r["result"], 16)
        # throttle / transient error dict: wait and retry
        print(f"    blockNumber error: {str(r)[:100]}; retrying", flush=True)
        time.sleep(2 ** attempt)
    raise RuntimeError(f"eth_blockNumber failed after {tries} tries: {url}")


def count_logs(t, days=None):
    """days=None: full history from from_block. days=N: last N days only
    (bounded query set -- the default; full scans are expensive at the
    10k-window cap)."""
    url = (f"https://lb.drpc.live/{t['slug']}/{DRPC_KEY}" if DRPC_KEY
           else t["free"])
    addr, topic = t["address"], t["topic"]
    head = latest_block(url)
    start = t["from_block"]
    if days is not None:
        start = max(start, head - days * 86_400 // t["block_s"])
    t = {**t, "from_block": start}
    win = t.get("window", WINDOW)
    windows = [(a, min(a + win, head))
               for a in range(t["from_block"], head + 1, win + 1)]
    total, calls, splits = 0, 0, 0
    strikes = {}
    while windows:
        batch, windows = windows[:BATCH], windows[BATCH:]
        payload = [{"jsonrpc": "2.0", "id": i, "method": "eth_getLogs",
                    "params": [{"address": addr, "topics": [topic],
                                "fromBlock": hex(a), "toBlock": hex(b)}]}
                   for i, (a, b) in enumerate(batch)]
        resp = rpc_call(url, payload)
        calls += 1
        if isinstance(resp, dict):          # whole-batch error: split all windows
            print(f"    batch error: {str(resp.get('error'))[:120]}; splitting",
                  flush=True)
            for a, b in batch:
                if b > a:
                    mid = (a + b) // 2
                    windows += [(a, mid), (mid + 1, b)]
                    splits += 1
            time.sleep(2)
            continue
        throttled = False
        for item in resp:
            a, b = batch[item["id"]]
            if "result" in item:
                total += len(item["result"])
                continue
            msg = str(item.get("error", {}).get("message", "")).lower()
            if any(k in msg for k in ("result", "response", "size", "range",
                                      "10000", "10 000")):
                # too much data in the window: split it
                splits += 1
                if b > a:
                    mid = (a + b) // 2
                    windows += [(a, mid), (mid + 1, b)]
            else:
                # rate limit / transient: retry, but split after 3 strikes
                # (a window that keeps timing out is too dense for the tier)
                if not throttled:
                    print(f"    throttled: {msg[:100]!r}; backing off",
                          flush=True)
                    throttled = True
                strikes[(a, b)] = strikes.get((a, b), 0) + 1
                if strikes[(a, b)] >= 3 and b > a:
                    mid = (a + b) // 2
                    windows += [(a, mid), (mid + 1, b)]
                    splits += 1
                else:
                    windows.append((a, b))
        if throttled:
            time.sleep(3)
        done = t["from_block"] + (calls * BATCH * (WINDOW + 1))
        pct = min(100, 100 * (done - t["from_block"]) /
                  max(1, head - t["from_block"]))
        if calls % 10 == 0:
            print(f"    ...{pct:5.1f}%  count so far {total:,}", flush=True)
        time.sleep(PACE_S)
    return {"count": total, "head_block": head, "from_block": t["from_block"],
            "http_calls": calls, "window_splits": splits}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default=",".join(TARGETS))
    ap.add_argument("--days", type=int, default=7,
                    help="bounded query set: only the last N days (default 7)")
    ap.add_argument("--full", action="store_true",
                    help="full history from deployment (expensive)")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    days = None if args.full else args.days

    out = {"date": "2026-08-02", "mode": "full" if args.full else f"{days}d",
           "results": {}}
    for key in args.targets.split(","):
        t = TARGETS[key]
        print(f"{key}: {t['label']}", flush=True)
        try:
            r = count_logs(t, days=days)
        except RuntimeError as e:
            print(f"  FAILED: {e}", flush=True)
            out["results"][key] = {"error": str(e)}
            continue
        r["label"] = t["label"]
        if days:
            r["per_day"] = round(r["count"] / days, 1)
        out["results"][key] = r
        print(f"  => {r['count']:,} announcements"
              + (f" in {days}d ({r['per_day']}/day)" if days else "")
              + f"  ({r['http_calls']} calls)", flush=True)

    if days:
        print(f"\nCURRENT ACTIVITY (last {days} days):")
        print(f"{'registry':<48}{'announcements':>14}{'per day':>10}")
        for key, r in out["results"].items():
            if "count" in r:
                print(f"{r['label']:<48}{r['count']:>14,}{r['per_day']:>10,}")
    else:
        print("\nSCAN-TIME PROJECTIONS at fitted marginal rates "
              f"(ours {OURS_US} us/ann, DKSAP {DKSAP_US} us/ann):")
        print(f"{'registry':<48}{'announcements':>14}{'ours':>10}{'DKSAP':>10}")
        for key, r in out["results"].items():
            if "count" not in r:
                continue
            n = r["count"]
            print(f"{r['label']:<48}{n:>14,}{n*OURS_US/1e6:>9.2f}s"
                  f"{n*DKSAP_US/1e6:>9.2f}s")

    if args.json:
        json.dump(out, open(args.json, "w"), indent=2)
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
