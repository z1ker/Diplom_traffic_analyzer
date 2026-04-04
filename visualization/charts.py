import matplotlib.pyplot as plt

def plot_top_ips(data):

    ips = [x[0] for x in data]
    counts = [x[1] for x in data]

    plt.figure()

    plt.bar(ips, counts)

    plt.title("Top Active IP Addresses")

    plt.xlabel("IP")

    plt.ylabel("Packets")

    plt.xticks(rotation=45)

    plt.tight_layout()

    plt.show()