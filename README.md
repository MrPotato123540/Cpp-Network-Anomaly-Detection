# Network Anomaly Detection

A flow-based intrusion detection system in C++17. It reads packets from a PCAP file or off a live
interface, groups them into flows, and scores each finished flow against a statistical model of what
normal traffic looked like. Anything that scores too far from normal shows up in an ImGui dashboard,
in a log file, and on stdout.

No signature database, no labels. You point it at a capture you believe is clean, it learns what that
looks like, and after that everything is unsupervised. Two detectors are available and you pick one
at startup: a robust z-score, or k-means distance.

## The pipeline

Packets arrive through an `IPacketSource`. `PcapFileSource` replays a file, `LiveNetworkSource` reads
an interface through libpcap, and both hand packets to the same callback, so nothing downstream knows
which one it got.

`FlowManager` puts each packet into a flow keyed by the usual 5-tuple (source IP, destination IP,
source port, destination port, protocol). The hash is deliberately symmetric:

```cpp
return k.srcIP ^ k.dstIP ^ (k.srcPort << 16) ^ k.dstPort ^ k.protocol;
```

XOR is commutative, so A→B and B→A land on the same bucket and a connection stays one flow instead of
becoming two half-flows pointing in opposite directions. The `srcPort << 16` is there because
otherwise ports 80 and 80 would cancel each other out and you'd lose the port information entirely on
symmetric pairs. I got that wrong the first time around and spent a while wondering why port scans
looked so boring.

Flows don't get scored as packets come in. They get scored when they finish, and "finish" means one
of two timeouts: 15 seconds with no packets, or 120 seconds since the first packet regardless of
activity. The timeout sweep runs every 1000 packets rather than every packet, since walking the whole
flow table per packet is wasteful when the table has thousands of entries in it.

Each expired flow becomes nine numbers:

| Feature | Why it's there |
|---|---|
| duration | port scans are extremely short, transfers are long |
| packet count | |
| byte count | separates a DNS lookup from a download |
| IAT mean | time between packets, automated traffic is more regular than human traffic |
| IAT standard deviation | |
| SYN count | a scan is almost all SYN and almost nothing else |
| ACK count | |
| RST count | connections refused, which is what a scan hitting closed ports produces |
| average TCP window size | |

Inter-arrival statistics are accumulated online rather than kept as a list. `FlowData` holds a running
sum and a running sum of squares, and standard deviation falls out of `E[X²] - E[X]²` at the end. A
flow with 40,000 packets costs the same memory as one with three.

Every feature goes through `log1p` on the way out. Network traffic isn't Gaussian, it's closer to
Pareto: one flow is 60 bytes, the next is a gigabyte. Feed that into a distance metric raw and byte
count drowns out all eight other features, plus the standard deviation gets so inflated by the tail
that the z-score threshold ends up above everything you were trying to catch. `log(1+x)` squashes the
tail and keeps zero at zero, which matters because plenty of flows legitimately have zero RSTs.

## The two detectors

### Robust z-score

The obvious version of this uses mean and standard deviation, and the obvious version doesn't work.
The outliers you want to find are the same outliers inflating your standard deviation, which raises
your threshold, which hides them. Median Absolute Deviation has no such loop, since a handful of
extreme values barely move a median.

```
score = 0.6745 * (x - median) / MAD
```

The constant makes MAD line up with the standard deviation of a normal distribution, so the number
you get back reads like an ordinary z-score. Default cutoff is 3.5.

Median and MAD are computed per feature at training time using `nth_element`, which gets you the
median in O(n) without sorting the whole column.

### K-means

Training clusters the benign flows into k=5 groups, capped at 100 iterations or until no point
changes cluster. Initialisation is Forgy, and I should be upfront that it takes the first k points of
the training set rather than k random ones, so the result depends on capture order. Deterministic,
which is convenient, but not great.

Each cluster gets its own threshold instead of sharing a global one: the 99th percentile of the
distances from that cluster's own training points to its centroid, with a floor of 0.5 so a very
tight cluster can't end up rejecting everything. This matters more than I expected. Benign traffic
isn't one blob. A cluster of short DNS lookups is naturally tight and a cluster of long transfers is
naturally spread out, and one global threshold is simultaneously too strict for the first and useless
for the second.

At detection time a flow goes to its nearest centroid, and if the distance is past that cluster's
threshold, the overshoot is the score. Everything inside a threshold scores zero.

The scaler only exists on this side. Euclidean distance needs features on comparable scales, so
`KMeansStrategy` owns a `StandardScaler` and stores its fitted parameters in the model JSON.
`ZScoreStrategy` doesn't have one and doesn't need one, because it works per feature anyway.

## Design

Four things move independently here: where packets come from, how flows are built, how they're
scored, and where alerts end up. `PacketReceiver` is where they meet, and it holds references to
interfaces only:

```cpp
IPacketSource&           packetSource;
IFlowManager&            flowManager;
IDetectionStrategy&      strategy;
IFalsePositiveEvaluator* evaluator;   // null while training
```

No concrete types anywhere in it. All the actual wiring happens in `main.cpp`, which is also the only
file that touches `argv`.

**Strategy**, for the detectors. `IDetectionStrategy` is five methods: train, detect, getName,
saveModel, loadModel. `ZScoreStrategy` and `KMeansStrategy` implement it and you choose between them
with the fourth command-line argument. Because both sit behind the same interface, comparing them is
honest: identical flows, identical features, identical code path, one line different. A third
detector would mean writing a class and adding one branch in `main.cpp`, and `PacketReceiver`
wouldn't change at all.

Preprocessing lives inside the strategy rather than in front of it, which is why the scaler is a
k-means detail and not a pipeline stage.

**Observer**, for the outputs. `PacketReceiver` keeps a `std::vector<IAnomalyListener*>` and pushes
every detection to all of them. Three are attached at startup and none of them know about each other:
`ConsoleAnomalyLogger` prints, `FileAnomalyLogger` appends to `detected_anomalies.log`, and
`GuiAnomalyListener` feeds the dashboard table and score plot behind a mutex, because detection runs
on a background thread while ImGui renders on the main one.

There is no `#include "imgui.h"` anywhere in the detection code. The GUI came late in the project and
adding it required no changes to anything below `main.cpp`, which was the whole reason for setting it
up this way.

`IAnomalyListener` has two methods rather than one. Whitelist hits go out through
`onFalsePositiveDetected` instead of being silently dropped, so the dashboard can render them green
and `printStats` can tell you what fraction of your alerts the whitelist ate. If you can't see what
it suppressed you have no way to tell whether it's tuned or just broad.

**Small interfaces.** `IFalsePositiveEvaluator` is a single method, `isKnownBenign(const FlowKey&)`.
`IPacketSource` is two. Nothing implementing them has to stub out methods it doesn't care about. The
evaluator is also optional: `PacketReceiver` holds a raw pointer that stays null during training,
since suppressing flows while learning a baseline would poison the baseline.

## SOLID

Where the principles landed, briefly:

**SRP.** Each stage does one thing. `FlowManager` builds flows, `FlowData::toFeatureVector` produces
the nine numbers, the strategies score them, the listeners output. Results used to be printed with a
`cout` inside `PacketReceiver`; replacing that with `notifyListener` is what pulled output out of the
detection path.

**OCP.** A new detector is a class implementing `IDetectionStrategy` plus one branch in the argument
parsing. A new output is a class implementing `IAnomalyListener` plus one `addListener` call. The
file logger and the GUI listener were both added without modifying an existing class.

**LSP.** `PcapFileSource` walks a file to EOF, `LiveNetworkSource` blocks on a device until told to
stop, and `runDetectMode` never checks which one it has. The one line in `main.cpp` that picks
between them is the only place the difference exists.

**ISP.** `IFalsePositiveEvaluator` is one method, `IPacketSource` two, `IAnomalyListener` two.
Nothing implements an interface and leaves half of it empty.

**DIP.** `PacketReceiver` holds `IPacketSource&`, `IFlowManager&`, `IDetectionStrategy&` and
`IFalsePositiveEvaluator*`. Four dependencies, no concrete types, everything constructed in
`main.cpp`. References rather than smart pointers because ownership stays in `main` and the receiver
only borrows. The evaluator is a raw pointer because it's genuinely absent during training.

### Where it's looser than the above makes it sound

`PacketReceiver` does more than dispatch. It also collects training samples, keeps counters, and
prints the end-of-run report, which is three jobs in one class. The whitelist path
`trusted_ips.txt` is hardcoded in `main.cpp` instead of being an argument. `GuiAnomalyListener` is
defined twice, once in `include/GuiAnomalyListener.h` and again inside `main.cpp`, and the one in
main is the one actually used. All three are on my list.

### Small things that took longer than they should have

The scaler has a floor on standard deviation: anything below 0.5 gets clamped to 0.5. Without it, a
feature that happens to be constant across the whole training set (RST count on a clean capture is a
good candidate, it's zero almost everywhere) gives you a standard deviation of zero and then a
division by zero, and every flow afterwards comes out as infinitely anomalous in that dimension. My
first fix was a `1e-9` guard, which technically avoids the crash and then produces astronomically
large scores instead, so the floor moved up to something that actually damps the feature.

`euclideanDistance` clamps its loop to `min(a.size(), b.size())`. That's defensive rather than
principled. If a model file were ever loaded with a different feature count than the running binary
produces, the alternative is reading off the end of a vector.

`FileAnomalyLogger` opens in append mode and flushes after every line. Flushing per line is slower
than letting the stream buffer, but if the process is killed while watching a live interface, an
unflushed buffer means the alerts you wanted are exactly the ones you don't have.

## Building

Linux. I've only built it on Debian and Ubuntu.

```bash
sudo apt update
sudo apt install -y build-essential cmake git libpcap-dev libglfw3-dev libgl1-mesa-dev
```

PcapPlusPlus isn't packaged in a form `find_package` will pick up, so build and install it once:

```bash
git clone --depth 1 https://github.com/seladb/PcapPlusPlus.git
cd PcapPlusPlus
cmake -B build && cmake --build build -j$(nproc)
sudo cmake --install build
```

Then the project itself. Dear ImGui is pulled in by CMake at configure time, so a plain clone is all
you need and the first configure will want network access:

```bash
git clone https://github.com/MrPotato123540/Cpp-Network-Anomaly-Detection.git
cd Cpp-Network-Anomaly-Detection
cmake -B build
cmake --build build -j$(nproc)
```

## Running

```
netanomaly <MODE> <INPUT> <MODEL> [ALGO]

  MODE   train | detect | live
  INPUT  a .pcap path for train and detect, an interface name for live
  MODEL  file to write (train) or read (detect, live)
  ALGO   kmeans (default) | zscore
```

Learn a baseline:

```bash
./build/netanomaly train Monday-WorkingHours.pcap models/model_monday.json
```

Score a capture against it:

```bash
./build/netanomaly detect Friday-WorkingHours.pcap models/model_monday.json
```

Watch an interface:

```bash
sudo ./build/netanomaly live eth0 models/model_monday.json zscore
```

Live capture needs raw socket access. Rather than sudo every time:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip build/netanomaly
```

Two files come from the working directory. `trusted_ips.txt` holds one IPv4 address per line and is
loaded in detect and live modes; if it isn't there you just get no whitelist and a warning. Matching
is on source IP only, the destination check is commented out in `WhitelistEvaluator`.
`detected_anomalies.log` is written, not read.

Detect mode prints a summary when the capture runs out: flows checked, alerts, how many the whitelist
suppressed, and the overall anomaly rate with a pass/fail against the 5% target.

The dashboard opens in every mode including training, and closing the window stops capture and joins
the backend thread cleanly.

`models/model_monday.json` ships with the repo. It's trained on the Monday capture from CIC-IDS2017,
which is the clean day with no attacks in it. If you train your own, use traffic you're confident
about, because anything malicious in there becomes part of the definition of normal.

## What works and what doesn't

Offline it does what it should. On the Friday CIC-IDS2017 capture the port scan and DDoS flows sit
clearly above the threshold and most benign traffic sits at zero. I never sat down and computed a
proper false positive rate over the whole file, so treat that as an impression from reading output
rather than a measurement.

Live is a different story, and there are two reasons for it.

The first is latency and truncation, which both come out of the same design decision. A flow is only
scored once it times out, so the fastest you can hear about anything is 15 seconds after its last
packet, and a long-lived connection gets chopped at 120 seconds and scored as if it had ended there.
Half of a 10-minute transfer looks nothing like a whole one, and the model was trained on whole ones.
Shortening the timeouts trades accuracy for latency and doesn't remove the problem.

The second is that bursty legitimate traffic looks like an attack. Open a browser with twenty tabs
and you get a burst of short connections to many hosts in a few hundred milliseconds, high SYN
counts, short durations, small byte counts. That is close to indistinguishable from a scan when all
you have is flow statistics and no application context. The whitelist patches over the worst of it
but it's a blunt instrument, since it works on source IP and takes whole hosts out of consideration.

The target I set for myself was under 5% false positives on live traffic. Offline that's comfortable.
Live it isn't, for the two reasons above, and I'd rather say so here than have you find out.

## Stack

C++17, CMake 3.14+, `-O3 -Wall -Wextra`.

[PcapPlusPlus](https://pcapplusplus.github.io/) for capture and packet parsing over libpcap,
[Dear ImGui](https://github.com/ocornut/imgui) with the GLFW and OpenGL3 backends for the dashboard,
and [nlohmann/json](https://github.com/nlohmann/json) for the model file.

## Dataset

**CIC-IDS2017**, from the Canadian Institute for Cybersecurity. Their terms ask for a citation:

> I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion Detection
> Dataset and Intrusion Traffic Characterization", 4th International Conference on Information
> Systems Security and Privacy (ICISSP), Portugal, January 2018.

It isn't in this repo. Get it from https://www.unb.ca/cic/datasets/ids-2017.html.
