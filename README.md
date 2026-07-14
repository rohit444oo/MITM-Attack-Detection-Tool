# MITM Attack Detection Tool

A Python-based network security monitoring tool designed to detect common Man-in-the-Middle (MITM) attack techniques in real time on Linux networks.

## Features

* ARP Spoofing Detection
* TCP Session Monitoring
* Port Scan Detection
* DDoS Traffic Detection
* Real-time Alerts and Logging
* GUI Dashboard Support

## Technologies Used

* Python
* Scapy
* Tkinter
* Multithreading
* Socket Programming

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
sudo python3 main.py
```

For GUI mode:

```bash
sudo python3 gui_dashboard.py
```

## Project Structure

```text
mitmdec/
├── main.py
├── gui_dashboard.py
├── src/
├── config/
├── logs/
└── requirements.txt
```

## Future Improvements

* DNS Spoofing Detection
* HTTPS Stripping Detection
* SIEM Integration
* Machine Learning Based Anomaly Detection

## Disclaimer

This project is intended for educational purposes and authorized security testing only.
