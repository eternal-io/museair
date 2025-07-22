import matplotlib.pyplot as plt

STATS_SMH3_CPP = (
    ("MuseAir-BFast\n(64 / 128-bit)", (33.3, 33.3), "#F4511E"),
    ("rapidhash", 31.9, "#01579B"),
    ("wyhash 4.2", 31.9, "#455A64"),
    ("MuseAir-Std\n(64 / 128-bit)", (28.5, 30.4), "#FBC02D"),
    ("komihash 5.7", 25.5, "#7E57C2"),
    ("wyhash 4.2\n(condom mode)", 25.3, "#90A4AE"),
)

STATS_CRIT_RS = (
    ("MuseAir-BFast\n(64 / 128-bit)", (34.3, 32.4), "#F4511E"),
    ("rapidhash", 29.7, "#01579B"),
    ("wyhash 4.2", 28.8, "#455A64"),
    ("MuseAir-Std\n(64 / 128-bit)", (31.4, 31.1), "#FBC02D"),
    ("komihash 5.10", 26.1, "#7E57C2"),
    ("wyhash 4.2\n(condom mode)", 23.2, "#90A4AE"),
)


xs = range(0, len(STATS_SMH3_CPP) * 2, 2)
width = 0.8


def plot_and_save(datas, tool, filename):
    plt.figure(figsize=(7, 4.5))
    plt.title(f"Throughput for bulk datas (using {tool})")
    plt.grid(color="#CCC", linestyle="--", linewidth=0.5)

    for i, (_, value, color) in enumerate(datas):
        if isinstance(value, tuple):
            plt.bar(xs[i] - width / 2, value[0], width=width, color=color, zorder=3)
            plt.bar(
                xs[i] + width / 2,
                value[1],
                width=width,
                color=color,
                hatch="////",
                edgecolor="#777",
                zorder=3,
            )
        else:
            plt.bar(xs[i], value, width=width * 2, color=color, zorder=3)

    plt.xticks(xs, (d[0] for d in datas), fontsize=8)

    plt.ylabel("Throughput (GiB/s)", fontsize=10)
    plt.yticks(
        list(range(0, 25, 5)) + list(range(25, 31, 2)) + list(range(31, 37)),
        fontsize=8,
    )

    plt.savefig(filename, bbox_inches="tight")
    plt.clf()


plot_and_save(STATS_SMH3_CPP, "SMHasher3", "bench-bulkdatas-smhasher3.png")
plot_and_save(STATS_CRIT_RS, "Criterion.rs", "bench-bulkdatas-crit.rs.png")
