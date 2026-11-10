"""
ASTRA — Gas benchmark: per-record logging vs Merkle-batched anchoring.

Runs both contracts on an in-memory EVM (eth-tester) so gas numbers are exact EVM
gas, reproducible, and need no running node.

    pip install "web3[tester]" matplotlib
    python scripts/benchmark_gas.py --records 500
"""
import argparse
import json
import statistics
import sys
from pathlib import Path

from web3 import EthereumTesterProvider, Web3

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.merkle import build_tree, hash_leaf  # noqa: E402

BUILD = ROOT / "build" / "contracts"


def deploy(w3, name):
    art = json.loads((BUILD / f"{name}.json").read_text())
    c = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
    rc = w3.eth.wait_for_transaction_receipt(c.constructor().transact({"from": w3.eth.accounts[0]}))
    return w3.eth.contract(address=rc.contractAddress, abi=art["abi"])


def sample_record(i):
    return {
        "rf_prediction": "ddos", "xgb_prediction": "ddos", "rf_confidence": 0.9876,
        "xgb_confidence": 0.9931, "final_verdict": "ddos", "severity": "critical",
        "recommended_action": "Activate DDoS mitigation. Rate-limit source. Alert NOC.",
        "is_threat": True, "n": i,
    }


def per_record_gas(n):
    w3 = Web3(EthereumTesterProvider())
    log = deploy(w3, "ThreatLog")
    gas = []
    for i in range(n):
        r = sample_record(i)
        tx = log.functions.logThreat(
            r["final_verdict"], r["severity"], r["rf_prediction"], r["xgb_prediction"],
            int(r["rf_confidence"] * 10_000), int(r["xgb_confidence"] * 10_000),
            r["recommended_action"], r["is_threat"],
        ).transact({"from": w3.eth.accounts[0], "gas": 500_000})
        gas.append(w3.eth.wait_for_transaction_receipt(tx)["gasUsed"])
    return gas


def merkle_gas(n, batch_size):
    w3 = Web3(EthereumTesterProvider())
    anchor = deploy(w3, "MerkleAnchor")
    total, batches = 0, 0
    for start in range(0, n, batch_size):
        leaves = [hash_leaf(sample_record(i)) for i in range(start, min(start + batch_size, n))]
        root = build_tree(leaves)[-1][0]
        tx = anchor.functions.anchorBatch(root, len(leaves)).transact({"from": w3.eth.accounts[0]})
        total += w3.eth.wait_for_transaction_receipt(tx)["gasUsed"]
        batches += 1
    return total, batches


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", type=int, default=500)
    ap.add_argument("--out", default=str(ROOT / "docs"))
    a = ap.parse_args()

    base = per_record_gas(a.records)
    base_avg = statistics.mean(base)
    rows = [{"batch_size": 1, "mode": "per-record (ThreatLog)", "tx_count": a.records,
             "gas_per_record": base_avg, "total_gas": sum(base), "reduction_pct": 0.0}]

    for bs in (10, 50, 100, 250, 500):
        if bs > a.records:
            continue
        total, batches = merkle_gas(a.records, bs)
        rows.append({"batch_size": bs, "mode": "merkle (MerkleAnchor)", "tx_count": batches,
                     "gas_per_record": total / a.records, "total_gas": total,
                     "reduction_pct": 100 * (1 - (total / a.records) / base_avg)})

    out = Path(a.out); out.mkdir(exist_ok=True)
    (out / "gas_benchmark.json").write_text(json.dumps(rows, indent=2))

    md = ["| Mode | Batch size | Transactions | Gas / record | Total gas | Reduction |",
          "|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['mode']} | {r['batch_size']} | {r['tx_count']} | {r['gas_per_record']:,.0f} | "
                  f"{r['total_gas']:,} | {r['reduction_pct']:.1f}% |")
    (out / "gas_benchmark.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        labels = ["per-record"] + [f"Merkle\nbatch={r['batch_size']}" for r in rows[1:]]
        vals = [r["gas_per_record"] for r in rows]
        fig, ax = plt.subplots(figsize=(8, 4.2))
        bars = ax.bar(labels, vals, color=["#c0392b"] + ["#2e86de"] * (len(rows) - 1))
        ax.set_yscale("log")
        ax.set_ylabel("Gas per threat record (log scale)")
        ax.set_title(f"ASTRA audit logging cost — {a.records} records")
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v, f"{v:,.0f}", ha="center", va="bottom", fontsize=8)
        fig.tight_layout()
        fig.savefig(out / "gas_benchmark.png", dpi=150)
        print(f"\nSaved {out/'gas_benchmark.png'}")
    except ImportError:
        print("matplotlib not installed — skipped chart")


if __name__ == "__main__":
    main()
