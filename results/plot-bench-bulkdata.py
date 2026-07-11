import matplotlib.pyplot as plt

plt.rcParams["font.family"] = ["Halant"]

FREQ = 3.99  # actual frequency on my computer

SIZES = sorted(
    {1 << i for i in range(8, 19)}.union(int((1 << i) * 1.5) for i in range(8, 18))
)
TICKS = (
    [1 << i for i in range(8, 19)],
    [str((1 << i) / 1024).rstrip(".0") for i in range(8, 19)],
)
DATA = [
    [
        "MuseAir-BFast",
        "18.705;21.929;23.178;25.916;27.150;28.758;29.437;30.473;30.902;31.413;31.607;31.897;32.008;32.143;32.144;32.221;32.221;32.309;32.279;32.166;32.333",
        {"c": "#00d5be", "f": True},
    ],
    [
        "MuseAir-BFast-128",
        "16.913;20.364;21.121;24.571;26.214;27.949;28.579;29.977;30.563;31.086;31.348;31.763;31.924;32.065;32.100;32.135;32.219;32.287;32.304;32.297;32.334",
        {"c": "#00d5be", "f": True},
    ],
    [
        "rapidhash-v3",
        "16.189;19.224;20.825;23.081;24.696;27.109;27.924;29.548;30.213;30.747;31.184;31.490;31.536;31.546;31.580;30.202;30.082;30.168;29.993;29.916;29.839",
        {"c": "#193cb8", "f": True},
    ],
    [
        "MuseAir",
        "16.914;19.649;20.620;23.495;24.083;25.654;26.009;26.767;27.050;27.475;27.651;27.477;27.763;27.847;27.895;28.001;28.021;28.111;28.125;28.039;28.055",
        {"c": "#00d5be"},
    ],
    [
        "MuseAir-128",
        "15.916;18.666;19.810;22.156;23.197;24.820;25.526;26.305;26.822;27.333;27.257;27.459;27.690;27.836;27.852;27.958;27.857;28.088;28.125;28.084;28.068",
        {"c": "#00d5be"},
    ],
    [
        "wyhash-v4.2",
        "17.746;18.606;20.914;21.645;23.433;23.690;24.331;24.685;24.640;24.564;24.702;24.681;24.920;25.046;24.828;24.872;24.762;24.944;24.791;24.789;24.667",
        {"f": True},
    ],
    [
        "komihash-v5.10",
        "16.669;18.509;19.170;20.240;20.734;21.334;21.602;21.892;22.108;22.197;22.301;22.406;22.462;22.515;22.527;22.499;22.545;22.632;22.719;22.690;22.677",
        {},
    ],
    [
        "rapidhash-v3.prot",
        "12.247;15.390;15.696;16.462;18.426;19.456;20.198;20.915;21.089;21.118;21.606;21.729;21.877;21.871;21.594;20.391;20.400;20.311;20.282;20.074;20.061",
        {"c": "#193cb8"},
    ],
    [
        "wyhash-v4.2.prot",
        "14.577;15.808;17.129;17.734;18.323;18.443;18.707;19.092;19.032;19.294;19.437;19.564;19.604;19.675;19.707;19.615;19.686;19.758;19.726;19.779;19.706",
        {},
    ],
    [
        "xxh-64",
        "10.677;11.700;12.422;13.137;13.526;13.934;13.902;14.352;14.331;14.508;14.590;14.673;14.719;14.761;14.770;14.793;14.783;14.810;14.797;14.757;14.760",
        {},
    ],
    [
        "seahash-v4",
        "4.0653;4.6002;4.9235;5.2960;5.5044;5.7252;5.8431;5.9726;6.0354;6.0982;6.1362;6.1700;6.1877;6.2050;6.2136;6.2218;6.2207;6.2308;6.2330;6.2287;6.2331",
        {},
    ],
]

for item in DATA:
    item[1] = [float(v) for v in item[1].split(";")]


fig, (ax_line, ax_bar) = plt.subplots(1, 2, figsize=(10, 5))
fig.suptitle(
    "Throughput for bulk data (higher is better)", fontsize=14, weight="medium"
)
ax_line.set_title("Throughput vs Input Size")
ax_bar.set_title("Peak Throughput")

for label, thrpt_vals, kwargs in DATA:
    color = kwargs.get("c", "#d6d3d1")
    linestyle = kwargs.get("f") and "--" or "-"
    ax_line.plot(
        SIZES,
        thrpt_vals,
        linestyle,
        color=color,
        linewidth=1.1,
    )
    ax_line.text(
        SIZES[-1] * 1.1,
        thrpt_vals[-1],
        label,
        color=color,
        ha="left",
        va="center",
        clip_on=False,
        weight="medium",
    )
ax_line.set_xscale("log")
ax_line.tick_params(axis="x", which="minor", bottom=False)
ax_line.grid(axis="x", color="#CCC", linestyle="--", linewidth=0.5)
ax_line.set_xlabel("Input size (KiB)")
ax_line.set_xlim(SIZES[0], SIZES[-1])
ax_line.set_xticks(*TICKS)
ax_line.set_ylabel("Throughput @ 4.0 GHz (GiB/s)")
ax_line.set_ylim(0, 34)
ax_line.set_yticks(range(0, 33, 4))

labels = []
for i, (label, thrpt_vals, kwargs) in enumerate(DATA):
    labels.append(label)
    cpb_val = max(thrpt_vals) / FREQ
    color = kwargs.get("c", "#d6d3d1")
    hatch, edgecolor = kwargs.get("f") and ("\\\\\\", "#fcfcfc") or (None, None)
    ax_bar.bar(
        i,
        cpb_val,
        color=color,
        hatch=hatch,
        edgecolor=edgecolor,
    )
    ax_bar.text(
        i,
        cpb_val,
        f"{cpb_val:.2f}",
        ha="center",
        va="bottom",
    )
ax_bar.set_xticks(range(len(DATA)), labels)
ax_bar.set_xticklabels(labels, rotation=34, ha="right", rotation_mode="anchor")
ax_bar.set_ylabel("Peak throughput (B/cycle)")
ax_bar.set_ylim(0, ax_line.get_ylim()[1] / FREQ)

fig.tight_layout()
plt.savefig("results/bench-bulkdata.png", dpi=120, bbox_inches="tight")
