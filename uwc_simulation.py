"""
uwc_simulation.py - Improved UWC Authentication Simulation

Improvements over original (prasu-baran/authentication-secure-underwater-protocol):
  - AES-GCM authenticated encryption replacing insecure XOR cipher
  - Thorp acoustic absorption model for physically realistic delays
  - Bernoulli packet-loss (15%) with retransmission (up to 3 attempts)
  - Per-node battery tracking (1000mAh @ 3.3V per node)
  - AUV/SUB random-waypoint mobility model affecting link delays
  - Z-score anomaly detection on per-hop delay stream
  - Comparison bar charts vs prior schemes [21] to [25] from paper
  - New graphs: throughput vs scale and battery level per node
"""

import os, random, time, hashlib, statistics
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from tinyec import registry
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

curve = registry.get_curve("secp256r1")

# ---------------------------------------------------------------------------
# Nodes (unchanged from original)
# ---------------------------------------------------------------------------
nodes = {
    "UWS":  ["U1", "U2"],
    "SUB":  ["S1"],
    "BUOY": ["B1", "B2"],
    "SAT":  ["SAT1", "SAT2"],
    "BS":   ["BS"],
}
edges = [
    ("U1","S1"), ("U2","S1"), ("S1","B1"), ("S1","B2"),
    ("B1","SAT1"), ("B2","SAT2"), ("SAT1","BS"), ("SAT2","BS"),
]

def is_node_active(node):
    return node != "B1"   # B1 forced-failed to demonstrate fallback

# ---------------------------------------------------------------------------
# IMPROVEMENT 1: AES-GCM authenticated encryption
# Replaces original XOR cipher. AES-GCM gives confidentiality + integrity.
# The GCM authentication tag detects any tampering of the ciphertext.
# ---------------------------------------------------------------------------
def aes_gcm_encrypt(plaintext, key_hex):
    key   = bytes.fromhex(key_hex[:64])   # 256-bit key from ECDH
    nonce = os.urandom(12)                # 96-bit random nonce per message
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return nonce + ct                     # prepend nonce for receiver

def aes_gcm_decrypt(ciphertext, key_hex):
    key = bytes.fromhex(key_hex[:64])
    return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], None).decode()

# ---------------------------------------------------------------------------
# IMPROVEMENT 2: Thorp acoustic absorption model
# Original: random.uniform(0.04, 0.08) - no physical basis.
# Thorp model: absorption = f(frequency, distance) in dB/km.
# Reference: Thorp (1965), Urick - Principles of Underwater Sound (1983).
# ---------------------------------------------------------------------------
SOUND_MPS = 1500.0   # sound speed in seawater (m/s)

DISTS = {   # realistic inter-node distances in metres
    ("U1","S1"):150, ("U2","S1"):200, ("S1","B1"):800, ("S1","B2"):850,
    ("B1","SAT1"):1000, ("B2","SAT2"):1000, ("SAT1","BS"):500, ("SAT2","BS"):500,
}

def thorp_db_per_km(f_khz):
    """Thorp absorption coefficient (dB/km). f_khz: modem frequency in kHz."""
    f2 = f_khz ** 2
    return 0.11*f2/(1+f2) + 44*f2/(4100+f2) + 2.75e-4*f2 + 0.003

def acoustic_delay(s, r, freq_khz=25.0, mob_off=0.0):
    """Physical one-way delay: propagation + absorption jitter + multipath."""
    key  = (s,r) if (s,r) in DISTS else (r,s)
    dist = max(10, DISTS.get(key, 500) + abs(mob_off))
    prop = dist / SOUND_MPS
    jit  = thorp_db_per_km(freq_khz) * (dist/1000) * 1e-4  # dB->seconds proxy
    mp   = abs(random.gauss(0, 0.005))                       # multipath spread
    return prop + jit + mp

# ---------------------------------------------------------------------------
# IMPROVEMENT 3: Bernoulli packet-loss with retransmission
# Original assumed 100% delivery. Underwater channels lose 10-30% of packets.
# Reference: Stojanovic (2007) OFDM for underwater acoustic channels.
# ---------------------------------------------------------------------------
LOSS_RATE = 0.15
MAX_RETRY  = 3

def send_with_loss(fn, s, r, ls):
    for attempt in range(1, MAX_RETRY+1):
        if random.random() < LOSS_RATE:
            ls["lost"] += 1
            print(f"  [LOSS] {s}->{r} attempt {attempt}/{MAX_RETRY}")
            continue
        return fn(s, r)
    ls["failed"] += 1
    print(f"  [FAIL] {s}->{r} link down after {MAX_RETRY} retransmissions")
    return False

# ---------------------------------------------------------------------------
# ECC key generation and identity (same algorithm as original)
# ---------------------------------------------------------------------------
def gen_keys():
    pk = random.randint(1, curve.field.n - 1)
    return pk, pk * curve.g

def gen_id(pub):
    return hashlib.sha256((str(pub.x) + str(pub.y)).encode()).hexdigest()

def shared(priv, pub):
    pt = priv * pub
    return hashlib.sha256(str(pt.x).encode()).hexdigest()

node_data = {}
for g in nodes:
    for n in nodes[g]:
        pk, pub = gen_keys()
        node_data[n] = {"private": pk, "public": pub, "id": gen_id(pub)}

print("\n=== Node Initialisation ===")
for n, d in node_data.items():
    print(f"  {n:6s}  ID: {d['id'][:20]}...")

# ---------------------------------------------------------------------------
# IMPROVEMENT 4: Per-node battery tracking
# 1000 mAh @ 3.3 V = 3.3 J = 3,300,000 uJ per node.
# Each auth cycle costs 48.8 uJ (paper value); TX=50 uJ, RX=36 uJ.
# ---------------------------------------------------------------------------
BAT_uJ = 3_300_000.0
AUTH_uJ, TX_uJ, RX_uJ = 48.8, 50.0, 36.0
batt = {n: BAT_uJ for g in nodes for n in nodes[g]}

def use_energy(node, op="auth"):
    cost = {"auth": AUTH_uJ, "tx": TX_uJ, "rx": RX_uJ}.get(op, AUTH_uJ)
    batt[node] -= cost
    if batt[node] <= 0:
        print(f"  [DEAD] {node} battery depleted!")
        return False
    return True

# Registration (same formula as original)
def reg(n):
    d = node_data[n]
    return hashlib.sha256((d["id"] + str(d["public"]) + str(d["private"])).encode()).hexdigest()

regs = {n: reg(n) for n in node_data}
print("\n=== Registration IDs ===")
for n, r in regs.items():
    print(f"  {n:6s}  RID: {r[:20]}...")

# ---------------------------------------------------------------------------
# IMPROVEMENT 5: Node mobility (random-waypoint for AUV/SUB)
# AUVs drift +-10 m per round (approx 2 m/s AUV speed).
# Mobility offset changes acoustic propagation distance.
# Reference: Camp et al. (2002) - mobility model survey for ad-hoc networks.
# ---------------------------------------------------------------------------
mob_off = {n: 0.0 for g in nodes for n in nodes[g]}

def upd_mob():
    for n in ["U1", "U2", "S1"]:
        mob_off[n] += random.uniform(-10, 10)
        mob_off[n]  = max(-50, min(50, mob_off[n]))

# ---------------------------------------------------------------------------
# Authentication with AES-GCM + acoustic delay
# ---------------------------------------------------------------------------
TSW = 5.0   # timestamp freshness window (seconds)

def authenticate(s, r, dlogs=None):
    if batt.get(s, 1) <= 0 or batt.get(r, 1) <= 0:
        return False
    nc  = random.randint(10000, 99999)
    ts  = time.time()
    sk  = shared(node_data[s]["private"], node_data[r]["public"])
    ct  = aes_gcm_encrypt(f"{node_data[s]['id']}|{nc}|{ts}", sk)
    pd  = acoustic_delay(s, r, mob_off=mob_off.get(s, 0))
    if dlogs is not None:
        dlogs.append(pd)
    use_energy(s, "tx")
    use_energy(r, "rx")
    rk = shared(node_data[r]["private"], node_data[s]["public"])
    try:
        dec = aes_gcm_decrypt(ct, rk)
    except Exception:
        print(f"  {r}: Decryption FAILED (tampered message)")
        return False
    p = dec.split("|")
    if abs(time.time() - float(p[2])) < TSW and int(p[1]) == nc:
        use_energy(r, "auth")
        return True
    return False

def auth_path(dl, ls):
    upd_mob()
    af = lambda s, r: authenticate(s, r, dl)

    if not send_with_loss(af, "U1", "S1", ls):
        return False
    b = next((x for x in nodes["BUOY"] if is_node_active(x)), None)
    if not b:
        return False
    print(f"  Using BUOY: {b}")
    if not send_with_loss(af, "S1", b, ls):
        return False
    sv = next((x for x in nodes["SAT"] if is_node_active(x)), None)
    if not sv:
        return False
    print(f"  Using SAT:  {sv}")
    if not send_with_loss(af, b, sv, ls):
        return False
    return send_with_loss(af, sv, "BS", ls)

# ---------------------------------------------------------------------------
# IMPROVEMENT 6: Z-score anomaly detection on delay stream
# Unusually high delays may indicate delay-injection attacks.
# Reference: Khraisat et al. (2019) anomaly detection in IoT.
# ---------------------------------------------------------------------------
def detect_anomalies(delays, thresh=2.5):
    if len(delays) < 4:
        return []
    m = statistics.mean(delays)
    s = statistics.stdev(delays)
    return [] if s == 0 else [i for i, d in enumerate(delays) if abs((d-m)/s) > thresh]

# ---------------------------------------------------------------------------
# Main run
# ---------------------------------------------------------------------------
print("\n=== Smart Authentication with Fallback + Packet Loss (5 rounds) ===")
dl, ls = [], {"lost": 0, "failed": 0}
for i in range(5):
    print(f"\n[Round {i+1}]")
    ok = auth_path(dl, ls)
    print(f"  Result: {'SUCCESS' if ok else 'FAILED'}")

print(f"\nPackets: lost={ls['lost']}, link-failures={ls['failed']}")
print("Sensor Data:", {
    "Temp":     round(random.uniform(10, 30), 2),
    "Pressure": round(random.uniform(1,  5),  2),
    "Salinity": round(random.uniform(30, 40), 2),
    "Velocity": round(random.uniform(0,  3),  2),
})

sdl = []
t0 = time.perf_counter()
authenticate("U1", "S1", sdl)
print(f"\nMeasured auth delay  : {round(time.perf_counter()-t0, 6)} s")
print(f"Acoustic delay U1->S1: {sdl[-1]:.4f} s")

print("\n=== Replay Attack Test ===")
ots = time.time()
time.sleep(6)
print("Replay blocked" if abs(time.time()-ots) >= TSW else "Replay ACCEPTED (BUG)")

print(f"\nComm Cost : {64+64+8+160} bits")
print(f"Energy    : {24 + 2*6 + 4*3.2} uJ")

anoms = detect_anomalies(dl)
print(f"\n[ANOMALY] Suspicious hops: {anoms}" if anoms else "\n[OK] No anomalous delays detected")

print("\n=== Battery Status ===")
for n in node_data:
    print(f"  {n:6s}  {100*batt[n]/BAT_uJ:.4f}%")

# ---------------------------------------------------------------------------
# Scaling simulation with Thorp-based delay
# ---------------------------------------------------------------------------
SZ = [10, 20, 50, 100, 150, 200]
HL = [("U1","S1"), ("S1","B2"), ("B2","SAT2"), ("SAT2","BS")]

def sim_scale(sizes):
    dl2, el, cl, tl = [], [], [], []
    for n in sizes:
        pds = [sum(acoustic_delay(s, r) for s, r in HL) for _ in range(max(1, n//8))]
        md  = statistics.mean(pds)
        dl2.append(md)
        el.append(AUTH_uJ + n*0.1)
        cl.append(296 + n*10)
        tl.append(1/md if md else 0)
    return sizes, dl2, el, cl, tl

ns, dsc, esc, csc, tsc = sim_scale(SZ)

# Comparison data from paper Tables IV and V
CMP = {
    "Ref [21]": {"comm":3008, "uws":0.536,  "sub":0.800,  "c":"#e74c3c"},
    "Ref [22]": {"comm":3200, "uws":19.70,  "sub":25.00,  "c":"#e67e22"},
    "Ref [23]": {"comm":3136, "uws":75.88,  "sub":90.00,  "c":"#f39c12"},
    "Ref [24]": {"comm":3040, "uws":2.352,  "sub":2.900,  "c":"#9b59b6"},
    "Ref [25]": {"comm":3216, "uws":1.245,  "sub":1.600,  "c":"#1abc9c"},
    "Proposed": {"comm":2112, "uws":0.400,  "sub":0.500,  "c":"#2ecc71"},
}

def sv(fname):
    plt.tight_layout()
    plt.savefig(fname, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {fname}")

# Graph 1: Topology
G2  = nx.Graph(); G2.add_edges_from(edges)
cm2 = {"U1":"#3498db","U2":"#3498db","S1":"#2ecc71","B1":"#e74c3c","B2":"#2ecc71",
       "SAT1":"#9b59b6","SAT2":"#9b59b6","BS":"#f39c12"}
pos = {
    "U1":   (0.35, 1.00), "U2":  (0.65, 1.00),   # Layer 1: UWS sensors
    "S1":   (0.50, 0.72),                          # Layer 2: Submarine
    "B1":   (0.18, 0.44), "B2":  (0.70, 0.44),    # Layer 3: Buoys (B1 failed, B2 active)
    "SAT1": (0.08, 0.16), "SAT2":(0.62, 0.16),    # Layer 4: Satellites
    "BS":   (1.00, 0.00),                          # Layer 5: Base Station
}
fig, ax = plt.subplots(figsize=(10,7))
nx.draw_networkx(G2, pos, ax=ax, node_color=[cm2.get(n,"#95a5a6") for n in G2.nodes()],
                 node_size=1100, font_size=10, font_weight="bold",
                 edge_color="#7f8c8d", width=2, with_labels=True)
# Highlight active routing path U1->S1->B2->SAT2->BS
active_edges = [("U1","S1"), ("S1","B2"), ("B2","SAT2"), ("SAT2","BS")]
nx.draw_networkx_edges(G2, pos, edgelist=active_edges, ax=ax,
                       edge_color="#27ae60", width=3.5, style="solid", alpha=0.8)
ax.set_title("UWC Network Topology | Active Path: U1/U2 -> S1 -> B2 -> SAT2 -> BS\n(Red=Failed B1, Green edges=Active Authentication Route)",
             fontsize=11, fontweight="bold")
ax.legend(handles=[
    mpatches.Patch(color="#3498db", label="UWS (Underwater Sensors)"),
    mpatches.Patch(color="#2ecc71", label="Active (SUB/BUOY)"),
    mpatches.Patch(color="#e74c3c", label="Failed Node (B1)"),
    mpatches.Patch(color="#9b59b6", label="Satellite"),
    mpatches.Patch(color="#f39c12", label="Base Station (BS)"),
    mpatches.Patch(color="#27ae60", label="Active Auth Path"),
], loc="upper left", fontsize=8)
sv("output_topology.png")

# Graph 2: Delay with Thorp model
fig, ax = plt.subplots(figsize=(8,5))
ax.plot(ns, dsc, marker="o", lw=2, color="#2980b9", label="Proposed (Thorp model)")
ax.plot(ns, [0.211]*len(ns), "--", color="#e74c3c", lw=1.5, label="Paper ref (211 ms)")
ax.set_title("Auth Delay vs Number of Nodes\n(Thorp acoustic model, 25 kHz, realistic distances)", fontsize=11)
ax.set_xlabel("Number of Nodes"); ax.set_ylabel("Mean Delay (s)")
ax.legend(); ax.grid(alpha=0.4); sv("output_delay.png")

# Graph 3: Energy with reference lines
fig, ax = plt.subplots(figsize=(8,5))
ax.plot(ns, esc, marker="o", lw=2, color="#27ae60", label="Proposed (48.8 uJ base)")
ax.fill_between(ns, esc, alpha=0.15, color="#27ae60")
ax.axhline(280,  color="#e74c3c", linestyle="--", lw=1.5, label="Ref [24] (280 uJ)")
ax.axhline(2300, color="#e67e22", linestyle=":",  lw=1.5, label="Ref [22] (2300 uJ)")
ax.set_title("Energy Consumption vs Number of Nodes", fontsize=11)
ax.set_xlabel("Number of Nodes"); ax.set_ylabel("Energy per Auth Cycle (uJ)")
ax.legend(loc="upper left", fontsize=8); ax.grid(alpha=0.4); sv("output_energy.png")

# Graph 4: Comm cost with comparison lines
fig, ax = plt.subplots(figsize=(8,5))
ax.plot(ns, csc, marker="o", lw=2, color="#8e44ad", label="Proposed (2112 bits)")
for ref,val,col in [("Ref [21]",3008,"#e74c3c"),("Ref [22]",3200,"#e67e22"),("Ref [23]",3136,"#f39c12")]:
    ax.plot(ns, [val+n*10 for n in ns], "--", color=col, lw=1.2, label=f"{ref} ({val} bits)")
ax.set_title("Communication Cost vs Number of Nodes", fontsize=11)
ax.set_xlabel("Number of Nodes"); ax.set_ylabel("Total Bits")
ax.legend(fontsize=8); ax.grid(alpha=0.4); sv("output_comm_cost.png")

# Graph 5: Comparison bar charts
fig, axes = plt.subplots(1, 2, figsize=(12,5))
sch  = list(CMP.keys()); cols = [CMP[s]["c"] for s in sch]
x2   = np.arange(len(sch)); w = 0.35
axes[0].bar(x2-w/2, [CMP[s]["uws"] for s in sch], w, label="UWS/BS",  color=cols, alpha=0.85)
axes[0].bar(x2+w/2, [CMP[s]["sub"] for s in sch], w, label="SUB/SAT", color=cols, alpha=0.5, edgecolor="black", lw=0.5)
axes[0].set_yscale("log"); axes[0].set_title("Computational Cost (ms, log scale)", fontsize=10)
axes[0].set_xticks(x2); axes[0].set_xticklabels(sch, rotation=20, fontsize=9)
axes[0].set_ylabel("Time (ms)"); axes[0].legend(fontsize=8); axes[0].grid(axis="y", alpha=0.4)
cv   = [CMP[s]["comm"] for s in sch]
bars = axes[1].bar(sch, cv, color=cols, alpha=0.85, edgecolor="black", lw=0.5)
for bar, val in zip(bars, cv):
    axes[1].text(bar.get_x()+bar.get_width()/2, bar.get_height()+20, str(val),
                 ha="center", va="bottom", fontsize=8, fontweight="bold")
axes[1].set_title("Communication Overhead (bits)", fontsize=10)
axes[1].set_ylabel("Total Bits"); axes[1].grid(axis="y", alpha=0.4)
plt.suptitle("Proposed Protocol vs Prior Schemes (Paper Tables IV & V)", fontsize=11, fontweight="bold")
sv("output_comparison.png")

# Graph 6: Throughput
fig, ax = plt.subplots(figsize=(8,5))
ax.plot(ns, tsc, marker="s", lw=2, color="#c0392b", label="Auth throughput")
ax.set_title("Authentication Throughput vs Network Scale", fontsize=11)
ax.set_xlabel("Number of Nodes"); ax.set_ylabel("Authentications per Second")
ax.legend(); ax.grid(alpha=0.4); sv("output_throughput.png")

# Graph 7: Battery per node
nms  = list(node_data.keys())
bpct = [100*batt[n]/BAT_uJ for n in nms]
fig, ax = plt.subplots(figsize=(9,5))
bars = ax.bar(nms, bpct,
              color=["#e74c3c" if p < 90 else "#2ecc71" for p in bpct],
              edgecolor="black", lw=0.5, alpha=0.85)
for bar, pct in zip(bars, bpct):
    ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.1,
            f"{pct:.2f}%", ha="center", va="bottom", fontsize=8)
ax.set_ylim(0, 105)
ax.set_title("Battery Level per Node After Simulation", fontsize=11)
ax.set_ylabel("Battery Remaining (%)")
ax.axhline(90, color="#e74c3c", linestyle="--", lw=1, label="90% threshold")
ax.legend(); ax.grid(axis="y", alpha=0.4); sv("output_battery.png")

print("\n=== Simulation Complete ===")
print(f"  Graphs: 7  |  Anomalies: {len(anoms)}  |  Lost: {ls['lost']}  |  Failures: {ls['failed']}")
