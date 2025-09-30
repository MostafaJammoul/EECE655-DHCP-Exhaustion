# EECE655 DHCP Exhaustion Project

## Overview

This repository contains materials and scripts for a project on DHCP exhaustion / starvation attacks and detection. The project demonstrates how to compromise a DHCP server's IP address pool through a starvation attack, how to detect such an attack, the evolutions of both the attacker and detector over 3 rounds, and includes annotated versions of the scripts to pinpoint authors, as well as supporting materials.

## Repository structure

* **onedrive_demoVideo_link.txt** - Contains the OneDrive link for our demo video, presenting the attacker/detector scripts in action and round-by-round.

* **Ai_prompts/** – Prompts and outputs between us (Authors Mostafa Jammoul and Omar Kaaki) and LLMs (ChatGPT) ( `Assignment overview EECE655.pdf`, `DHCP starvation game theory.pdf`).
* **scripts_by_rounds/** – Organized baseline and round-specific scripts:

  * `scripts_by_rounds/DHCP_Server.py` — DHCP server implementation (baseline).
  * `scripts_by_rounds/attacker/` — Attacker variants:

    * `attacker-round0.py`
    * `attacker-round1_2.py`
    * `attacker-round3.py`
  * `scripts_by_rounds/detector/` — Detector variants:

    * `detector-round0.py`
    * `detector-round1.py`
    * `detector-round2.py`
    * `detector-round3.py`
      These scripts depend on the `scapy` library and must be run with administrative/root privileges.
* **annotated_scripts_by_author/** – Annotated scripts to pinpoint function/section authors (NOTE THAT these scripts are not meant to be run, as they only serve informative reasons):

  * `annotated_DHCP_Server.py`
  * `annotated_attacker_final.py`
  * `annotated_detector_final.py`
* **EECE655_DHCP_Exhaustion_Report.pdf** – Project report describing objectives, methodology, results, and conclusions.
* **LICENSE** – License file for the project.

## Requirements

* Python 3
* `scapy` (for crafting and sending packets):

  ```bash
  pip install scapy
  ```
* Administrative / root privileges to run network scripts (use `sudo` on Linux/macOS, run command prompt or powershell as administrator on Windows).

## Usage

1. **Clone the repository**

```bash
git clone https://github.com/MostafaJammoul/EECE655-DHCP-Exhaustion.git
cd EECE655-DHCP-Exhaustion
```

2. **Install dependencies**

```bash
pip install scapy
```

3. **Run the DHCP server** (on the machine that will act as the DHCP server)

```bash
sudo python3 scripts_by_rounds/DHCP_Server.py
```

4. **Run an attacker script** (choose the round/version you want)

```bash
sudo python3 scripts_by_rounds/attacker/attacker-round0.py -i <interface>
# or
sudo python3 scripts_by_rounds/attacker/attacker-round1_2.py -i <interface>
```

5. **Run the detector** (choose the detector round/version)

```bash
sudo python3 scripts_by_rounds/detector/detector-round0.py -i <interface>
# or
sudo python3 scripts_by_rounds/detector/detector-round1.py -i <interface>
```

Replace `<interface>` with your network interface identifier (for example `eth0`, `enp3s0`, or `wlan0`).

## Notes

* Attacker scripts typically spoof many MAC addresses and send DHCP DISCOVER/REQUEST messages at configurable intervals to exhaust the DHCP server's lease pool.
* Detector scripts listen for DHCP traffic and flag suspicious patterns, such as a high number of unique MACs requesting leases in a short time, or server lease exhaustion.
* For full methodology, data, and results, see **EECE655_DHCP_Exhaustion_Report.pdf**.
