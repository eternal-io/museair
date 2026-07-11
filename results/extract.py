import re
import sys

_TIME_LINE = (
    r"(?P<key>\S+)\s+"
    r"time:\s+\["
    r"(?P<time_lo>[\d.]+)\s+\S+\s+"
    r"(?P<time_mid>[\d.]+)\s+\S+\s+"
    r"(?P<time_hi>[\d.]+)\s+\S+"
    r"\]"
)
_THRPT_LINE = (
    r"thrpt:\s+\["
    r"(?P<thrpt_lo>[\d.]+)\s+\S+\s+"
    r"(?P<thrpt_mid>[\d.]+)\s+\S+\s+"
    r"(?P<thrpt_hi>[\d.]+)\s+\S+"
    r"\]"
)
PATTERN = re.compile(_TIME_LINE + r"\s*" + _THRPT_LINE, re.DOTALL)


def extract_bench_data(data: str) -> dict[str, dict[str, dict[str, list[str]]]]:
    results = {}
    for m in PATTERN.finditer(data):
        full_key = m.group("key")
        algo = full_key.split("/")[0]
        cate = full_key.split("/")[1].split("_")[0]
        results.setdefault(cate, {}).setdefault(algo, {"time": [], "thrpt": []})
        results[cate][algo]["time"].append(m.group("time_mid"))
        results[cate][algo]["thrpt"].append(m.group("thrpt_mid"))
    return results


def merge_bench_results(
    *results: dict[str, dict[str, dict[str, list[str]]]],
) -> dict[str, dict[str, dict[str, list[str]]]]:
    if not results:
        return {}
    merged = {}
    first = results[0]
    for cat, algos in first.items():
        merged[cat] = {}
        for algo, metrics in algos.items():
            times = list(metrics["time"])
            thrpts = list(metrics["thrpt"])
            for other in results[1:]:
                other_times = other[cat][algo]["time"]
                other_thrpts = other[cat][algo]["thrpt"]
                for i in range(len(times)):
                    times[i] = min(times[i], other_times[i], key=float)
                for i in range(len(thrpts)):
                    thrpts[i] = max(thrpts[i], other_thrpts[i], key=float)
            merged[cat][algo] = {"time": times, "thrpt": thrpts}
    return merged


all_results = []
for path in sys.argv[1:]:
    with open(path) as f:
        log = f.read()
    all_results.append(extract_bench_data(log))
results = merge_bench_results(*all_results)

if results:
    for algo, data in results.get("bulk", {}).items():
        print(f"[{algo:^25}]", ";".join(data["thrpt"]), "\n")

    print("---\n")

    for algo, data in results.get("small", {}).items():
        print(f"[{algo:^25}]", ";".join(data["time"]), "\n")
