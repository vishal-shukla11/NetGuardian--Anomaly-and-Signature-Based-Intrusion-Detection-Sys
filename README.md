# NetGuardian Intrusion Detection System (IDS)

A Python-based Intrusion Detection System that uses both signature-based and anomaly-based detection methods to identify potential network threats.

## Features

- Real-time packet capture and analysis
- Signature-based detection for known attack patterns
- Anomaly-based detection using Isolation Forest
- Configurable detection rules and thresholds
- Email alerts for high-confidence threats
- IP blocking capability
- Periodic retraining of the anomaly detector
- Comprehensive logging

## Requirements

- Python 3.8+
- Network interface with promiscuous mode support
- Root/Administrator privileges (for packet capture)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-directory>
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure the IDS:
   - Edit `ids_config.yaml` to set your network interface and other parameters
   - For email alerts, configure your SMTP settings in the config file

## Usage

1. Run the IDS:
```bash
sudo python ids2_improved.py
```

2. The system will:
   - First collect training data (if no existing data is found)
   - Train the anomaly detector
   - Start monitoring network traffic
   - Generate alerts for detected threats
   - Block suspicious IPs (if enabled)

## Configuration

The `ids_config.yaml` file contains all configurable parameters:

- `interface`: Network interface to monitor
- `training`: Training data collection settings
- `detection`: Detection thresholds and rules
- `alert`: Alert configuration including email settings
- `blocking`: IP blocking settings

## Logs

The system generates two log files:
- `ids_system.log`: General system logs
- `ids_alerts.log`: Detailed threat alerts

## Security Notes

- The system requires root/administrator privileges to capture packets
- Email passwords should be app-specific passwords, not your main account password
- IP blocking is implemented in software and may not be as effective as hardware-based blocking

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
