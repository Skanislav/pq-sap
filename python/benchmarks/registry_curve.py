#!/usr/bin/env python3
"""Registry-size scaling curve: scan cost across registry sizes.

The plan's challenges section states scanning is linear in registry size and
promises "the benchmarks show the curve across registry sizes". This produces
that curve: our scheme (liboqs decaps + pure-Python derivation on tag match)
and the DKSAP baseline swept across sizes, with a least-squares linear fit so
"linear" is a measured claim (slope = marginal cost per announcement,
intercept = fixed overhead, R^2 = how straight the line really is).

View-tag false positives grow linearly too (~N/256 hits, each costing a
pure-Python derivation), so the fitted slope for ours *includes* that term --
which is the honest per-announcement figure for a wallet at steady state.

Usage: registry_curve.py [--sizes 2500,...,160000] [--reps 3] [--json out]
"""

import argparse
import json

from scan_bench import bench_ours_liboqs, bench_dksap


def linear_fit(xs, ys):
    """Plain least squares y = a*x + b, plus R^2."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    a = sxy / sxx
    b = my - a * mx
    ss_res = sum((y - (a * x + b)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - my) ** 2 for y in ys)
    r2 = 1 - ss_res / ss_tot if ss_tot else 1.0
    return a, b, r2


def sweep(fn, sizes, reps):
    rows = []
    for n in sizes:
        best, matches = None, 0
        for _ in range(reps):
            dt, matches = fn(n)
            best = dt if best is None else min(best, dt)
        rows.append({"n": n, "best_s": round(best, 4),
                     "us_per_ann": round(best / n * 1e6, 2),
                     "tag_matches": matches})
        print(f"  N={n:>7,}  {best*1e3:>9.1f} ms   "
              f"{best/n*1e6:>7.2f} us/ann   {matches} tag matches", flush=True)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="2500,5000,10000,20000,40000,80000,160000")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    sizes = [int(s) for s in args.sizes.split(",")]

    out = {}
    for name, fn in (("ours/liboqs", bench_ours_liboqs), ("dksap", bench_dksap)):
        print(f"{name}:")
        rows = sweep(fn, sizes, args.reps)
        a, b, r2 = linear_fit([r["n"] for r in rows], [r["best_s"] for r in rows])
        fit = {"slope_us_per_ann": round(a * 1e6, 2),
               "intercept_ms": round(b * 1e3, 2), "r_squared": round(r2, 5)}
        print(f"  fit: {fit['slope_us_per_ann']} us/announcement marginal, "
              f"{fit['intercept_ms']} ms fixed, R^2 = {fit['r_squared']}")
        out[name] = {"rows": rows, "fit": fit}

    ours, dk = out["ours/liboqs"]["fit"], out["dksap"]["fit"]
    print(f"\nBoth linear (R^2 {ours['r_squared']}, {dk['r_squared']}). "
          f"Marginal cost: ours {ours['slope_us_per_ann']} vs DKSAP "
          f"{dk['slope_us_per_ann']} us/announcement "
          f"({ours['slope_us_per_ann']/dk['slope_us_per_ann']:.2f}x).")

    if args.json:
        json.dump(out, open(args.json, "w"), indent=2)
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
