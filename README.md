# C++ Network Anomaly Detection System

![C++](https://img.shields.io/badge/Language-C++17-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)
![GUI](https://img.shields.io/badge/GUI-ImGui-red.svg)

A lightweight Network Intrusion Detection System written in C++17. This tool analyzes network flows to flag anomalies like DDoS attacks, Port Scans, and Brute Force attempts using unsupervised learning (K-Means) and statistical analysis (Z-Score).

It supports both **offline PCAP analysis** (forensics) and **live network monitoring** with a real-time ImGui dashboard.

> **Target:** Achieving a False Positive Rate (FPR) of **< 5%** on the CIC-IDS2017 dataset.

---

## Table of Contents
- [Key Features](#key-features)
- [Architecture & Design](#architecture--design)
- [Algorithms](#algorithms)
- [Performance & "Real World" Constraints](#performance--real-world-constraints)
- [Tech Stack](#tech-stack)
- [Setup](#setup)

---

## Key Features

* **Flow Aggregation:** Processes raw packets into 5-tuple flows.
* **Dual Mode:** * *Training Mode:* Learns baseline statistics from "normal" traffic PCAPs.
    * *Detection Mode:* Scores live traffic or files against the trained model.
* **Visualization:** Real-time plots and logs using Dear ImGui.

---

## Architecture & Design

The codebase emphasizes modularity and clean code practices to ensure maintainability.

* **Decoupled Components (SOLID):** We strictly separated concerns. For example, `FlowManager` handles packet aggregation, while `FeatureExtractor` does the math. The detection engine is completely isolated from the GUI via the **Observer Pattern**.
* **Flexible Detection:** Used the **Strategy Pattern** for the detection logic. You can hot-swap between `ZScoreStrategy` and `KMeansStrategy` at runtime without restarting the application.
* **Hardware Abstraction:** The packet capture layer (`IPacketSource`) abstracts the underlying source, making `LiveNetworkSource` and `PcapFileSource` interchangeable.

---

## Algorithms

### 1. Data Preprocessing
Network features (like Duration or IAT) are rarely normally distributed. We apply **Log Transformation (`log1p`)** followed by **Standard Scaling** to normalize inputs before feeding them to the detector.

### 2. Z-Score with MAD
Standard deviation is too sensitive to outliers. We use **Median Absolute Deviation (MAD)** for a more robust statistical threshold:
$$Score = \frac{0.6745 \times (X_i - Median)}{MAD}$$

### 3. K-Means Clustering
Normal traffic is grouped into $k$ clusters. Anomalies are flagged based on their distance to the nearest cluster center (99th percentile threshold).

---

## Performance & "Real World" Constraints

Honest notes on where the system shines and where it struggles:

### Offline Analysis (Forensics)
The system performs very well on the **CIC-IDS2017 dataset**. When analyzing complete flows from PCAP files, it successfully detects Port Scans and DDoS patterns with a low False Positive Rate.

### Live Monitoring Challenges
Running this on a live interface is trickier. Achieving < 5% FPR is hard due to:
1.  **Partial Flows:** We have to evaluate flows *before* they close to give real-time alerts. This means the feature vectors are sometimes incomplete compared to the training data.
2.  **Burstiness:** Legitimate spikes (e.g., opening a browser with 20 tabs) can look statistically similar to a flood attack.
3.  **K-Means Limitations:** K-Means assumes spherical clusters. Complex real-world traffic is often density-based, so a move to **DBSCAN** or **Isolation Forest** is planned for future updates to handle noise better.

---

## Tech Stack

* **Core:** C++17
* **Packet Capture:** [PcapPlusPlus](https://pcapplusplus.github.io/) (Wrapper for libpcap)
* **UI/Rendering:** [Dear ImGui](https://github.com/ocornut/imgui) + OpenGL3 / GLFW
* **Data:** [nlohmann/json](https://github.com/nlohmann/json)
* **Build:** CMake

---

## Setup

### Prerequisites (Linux/Debian)

```bash
# Build tools
sudo apt update && sudo apt install build-essential cmake git

# PcapPlusPlus dependencies
sudo apt install libpcap-dev

# GUI dependencies (GLFW & OpenGL)
sudo apt install libglfw3-dev libgl1-mesa-dev
