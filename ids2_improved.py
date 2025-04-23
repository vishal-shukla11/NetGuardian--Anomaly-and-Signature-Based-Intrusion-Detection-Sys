from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import threading
import queue
import logging
import json
from datetime import datetime
import psutil
from sklearn.ensemble import IsolationForest
import numpy as np
import time
import os
import yaml
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pickle
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ids_system.log"),
        logging.StreamHandler(),
        logging.FileHandler("ids_alerts.log")
    ]
)
logger = logging.getLogger("IDS")

class ConfigManager:
    def __init__(self, config_file="ids_config.yaml"):
        self.config_file = config_file
        self.config = self.load_config()
        
    def load_config(self) -> dict:
        default_config = {
            'interface': 'Ethernet',
            'training': {
                'sample_size': 1000,
                'retrain_interval': 3600,  # 1 hour
                'save_path': 'training_data'
            },
            'detection': {
                'contamination': 0.1,
                'anomaly_threshold': -0.5,
                'signature_rules': {
                    'syn_flood': {'threshold': 50, 'rate': 100},
                    'fin_flood': {'threshold': 50, 'rate': 100},
                    'port_scan': {'threshold': 100, 'rate': 50},
                    'raw_ip_attack': {'threshold': 50},
                    'icmp_flood': {'threshold': 50},
                    'flood_attack': {'threshold': 100}
                }
            },
            'alert': {
                'email': {
                    'enabled': False,
                    'smtp_server': '',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'recipients': []
                },
                'severity_levels': {
                    'critical': 0.9,
                    'high': 0.7,
                    'medium': 0.5,
                    'low': 0.3
                }
            },
            'blocking': {
                'enabled': False,
                'block_duration': 3600,  # 1 hour
                'max_blocks': 100
            }
        }
        
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                loaded_config = yaml.safe_load(f)
                default_config.update(loaded_config)
        
        return default_config
    
    def save_config(self):
        with open(self.config_file, 'w') as f:
            yaml.dump(self.config, f)

class PacketCapture:
    def __init__(self, interface: str):
        if interface not in psutil.net_if_addrs():
            available_interfaces = list(psutil.net_if_addrs().keys())
            raise ValueError(f"Interface {interface} not found. Available: {available_interfaces}")

        self.interface = interface
        self.packet_queue = queue.Queue(maxsize=1000)
        self.stop_capture = threading.Event()
        self.blocked_ips = set()
        self.block_times = {}

    def packet_callback(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip in self.blocked_ips:
                return  # Drop packets from blocked IPs
            
            if packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP):
                try:
                    self.packet_queue.put(packet, timeout=1)
                except queue.Full:
                    logger.warning("Packet queue is full, dropping packet.")

    def block_ip(self, ip: str, duration: int = 3600):
        self.blocked_ips.add(ip)
        self.block_times[ip] = time.time() + duration
        logger.warning(f"Blocked IP {ip} for {duration} seconds")

    def unblock_expired_ips(self):
        current_time = time.time()
        expired_ips = [ip for ip, expiry in self.block_times.items() if expiry <= current_time]
        for ip in expired_ips:
            self.blocked_ips.remove(ip)
            del self.block_times[ip]
            logger.info(f"Unblocked IP {ip}")

    def start_capture(self):
        def capture_thread():
            try:
                logger.info(f"Starting packet capture on {self.interface}")
                sniff(
                    iface=self.interface,
                    prn=self.packet_callback,
                    store=0,
                    stop_filter=lambda _: self.stop_capture.is_set(),
                )
            except Exception as e:
                logger.error(f"Error during packet capture: {e}")

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        if self.capture_thread.is_alive():
            self.capture_thread.join()

class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'syn_count': 0,
            'fin_count': 0,
            'port_scan_count': 0,
            'raw_ip_count': 0,
            'flood_count': 0,
            'icmp_count': 0,
            'ports_scanned': set(),
            'last_reset': time.time()
        })
        self.reset_interval = 300  # 5 minutes

    def reset_old_stats(self):
        current_time = time.time()
        for flow_key, stats in list(self.flow_stats.items()):
            if stats['last_reset'] + self.reset_interval <= current_time:
                del self.flow_stats[flow_key]

    def analyze_packet(self, packet):
        self.reset_old_stats()
        
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = 0
            port_dst = 0

            if packet.haslayer(TCP):
                port_src = packet[TCP].sport
                port_dst = packet[TCP].dport
            elif packet.haslayer(UDP):
                port_src = packet[UDP].sport
                port_dst = packet[UDP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)
            stats = self.flow_stats[flow_key]

            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if stats['start_time'] is None:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            if packet.haslayer(TCP):
                if packet[TCP].flags == 2:  # SYN flag
                    stats['syn_count'] += 1
                elif packet[TCP].flags == 1:  # FIN flag
                    stats['fin_count'] += 1
            elif packet.haslayer(UDP):
                stats['port_scan_count'] += 1
                stats['ports_scanned'].add(port_dst)
            elif packet.haslayer(ICMP):
                stats['icmp_count'] += 1

            if packet.haslayer(IP) and not packet.haslayer(TCP) and not packet.haslayer(UDP) and not packet.haslayer(ICMP):
                stats['raw_ip_count'] += 1

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        duration = stats['last_time'] - stats['start_time']
        if duration <= 0:
            duration = 1e-6

        flood_count = 0
        if packet.haslayer(TCP):
            if packet[TCP].flags == 2:
                flood_count = stats['packet_count']

        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,
            'syn_count': stats['syn_count'],
            'fin_count': stats['fin_count'],
            'port_scan_count': stats['port_scan_count'],
            'raw_ip_count': stats['raw_ip_count'],
            'icmp_count': stats['icmp_count'],
            'flood_count': flood_count,
            'unique_ports_scanned': len(stats['ports_scanned']),
        }

class DetectionEngine:
    def __init__(self, config: dict):
        self.config = config
        self.anomaly_detector = IsolationForest(
            contamination=config['detection']['contamination'],
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.last_retrain_time = 0
        self.retrain_interval = config['training']['retrain_interval']

    def load_signature_rules(self):
        rules = {}
        for rule_name, params in self.config['detection']['signature_rules'].items():
            if rule_name == 'syn_flood':
                rules[rule_name] = {
                    'condition': lambda features, p=params: (
                        features['syn_count'] > p['threshold'] and
                        features['packet_rate'] > p['rate']
                    )
                }
            elif rule_name == 'fin_flood':
                rules[rule_name] = {
                    'condition': lambda features, p=params: (
                        features['fin_count'] > p['threshold'] and
                        features['packet_rate'] > p['rate']
                    )
                }
            elif rule_name == 'port_scan':
                rules[rule_name] = {
                    'condition': lambda features, p=params: (
                        features['port_scan_count'] > p['threshold'] and
                        features['packet_rate'] > p['rate']
                    )
                }
            elif rule_name == 'raw_ip_attack':
                rules[rule_name] = {
                    'condition': lambda features, p=params: features['raw_ip_count'] > p['threshold']
                }
            elif rule_name == 'icmp_flood':
                rules[rule_name] = {
                    'condition': lambda features, p=params: features['icmp_count'] > p['threshold']
                }
            elif rule_name == 'flood_attack':
                rules[rule_name] = {
                    'condition': lambda features, p=params: features['flood_count'] > p['threshold']
                }
        return rules

    def save_training_data(self, data, path):
        os.makedirs(path, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(path, f"training_data_{timestamp}.pkl")
        with open(filename, 'wb') as f:
            pickle.dump(data, f)
        logger.info(f"Saved training data to {filename}")

    def load_training_data(self, path):
        if not os.path.exists(path):
            return []
        
        training_data = []
        for filename in os.listdir(path):
            if filename.endswith('.pkl'):
                with open(os.path.join(path, filename), 'rb') as f:
                    data = pickle.load(f)
                    training_data.extend(data)
        return training_data

    def train_anomaly_detector(self, normal_traffic_data):
        if len(normal_traffic_data) > 0:
            self.anomaly_detector.fit(normal_traffic_data)
            self.save_training_data(normal_traffic_data, self.config['training']['save_path'])
            self.last_retrain_time = time.time()
            logger.info("Anomaly detector trained successfully")

    def should_retrain(self):
        return time.time() - self.last_retrain_time >= self.retrain_interval

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Anomaly-based detection
        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate'],
            features['syn_count'],
            features['fin_count'],
            features['port_scan_count'],
            features['raw_ip_count'],
            features['icmp_count'],
            features['flood_count'],
            features['unique_ports_scanned']
        ]])
        
        anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
        if anomaly_score < self.config['detection']['anomaly_threshold']:
            threats.append({
                'type': 'anomaly',
                'score': anomaly_score,
                'confidence': min(1.0, abs(anomaly_score))
            })

        return threats

class AlertSystem:
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger("IDS_Alerts")
        self.email_config = config['alert']['email']
        self.severity_levels = config['alert']['severity_levels']
        self.setup_logging()

    def setup_logging(self):
        if not self.logger.hasHandlers():
            self.logger.setLevel(logging.INFO)
            handler = logging.FileHandler("ids_alerts.log")
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def send_email_alert(self, alert):
        if not self.email_config['enabled']:
            return

        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['username']
            msg['To'] = ', '.join(self.email_config['recipients'])
            msg['Subject'] = f"IDS Alert: {alert['threat_type']}"

            body = json.dumps(alert, indent=2)
            msg.attach(MIMEText(body, 'plain'))

            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['username'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")

    def get_severity(self, confidence):
        for level, threshold in self.severity_levels.items():
            if confidence >= threshold:
                return level
        return 'low'

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat,
            'severity': self.get_severity(threat.get('confidence', 0.0))
        }

        self.logger.warning(json.dumps(alert))
        
        if threat['confidence'] > self.severity_levels['high']:
            self.logger.critical(f"High confidence threat detected: {json.dumps(alert)}")
            self.send_email_alert(alert)

class IntrusionDetectionSystem:
    def __init__(self, config_file="ids_config.yaml"):
        self.config_manager = ConfigManager(config_file)
        self.config = self.config_manager.config
        self.packet_capture = PacketCapture(self.config['interface'])
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine(self.config)
        self.alert_system = AlertSystem(self.config)

    def collect_training_data(self):
        sample_size = self.config['training']['sample_size']
        logger.info(f"Collecting {sample_size} packets of normal traffic for training...")
        training_data = []

        self.packet_capture.start_capture()
        try:
            while len(training_data) < sample_size:
                packet = self.packet_capture.packet_queue.get(timeout=10)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    training_data.append([
                        features['packet_size'],
                        features['packet_rate'],
                        features['byte_rate'],
                        features['syn_count'],
                        features['fin_count'],
                        features['port_scan_count'],
                        features['raw_ip_count'],
                        features['icmp_count'],
                        features['flood_count'],
                        features['unique_ports_scanned']
                    ])
        except queue.Empty:
            logger.warning("Timeout while collecting training data. Proceeding with collected data...")
        finally:
            self.packet_capture.stop()

        logger.info(f"Collected {len(training_data)} packets for training.")
        return training_data

    def start(self):
        # Load existing training data if available
        existing_data = self.detection_engine.load_training_data(self.config['training']['save_path'])
        if existing_data:
            logger.info("Using existing training data")
            self.detection_engine.train_anomaly_detector(existing_data)
        else:
            # Collect new training data
            normal_traffic_data = self.collect_training_data()
            if len(normal_traffic_data) > 0:
                self.detection_engine.train_anomaly_detector(normal_traffic_data)
            else:
                logger.error("Failed to collect sufficient training data. Exiting...")
                return

        # Start real-time IDS
        logger.info(f"Starting IDS on interface {self.config['interface']}")
        self.packet_capture.start_capture()

        try:
            while True:
                try:
                    # Check if retraining is needed
                    if self.detection_engine.should_retrain():
                        logger.info("Retraining anomaly detector...")
                        training_data = self.collect_training_data()
                        if training_data:
                            self.detection_engine.train_anomaly_detector(training_data)

                    # Process packets
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    features = self.traffic_analyzer.analyze_packet(packet)

                    if features:
                        threats = self.detection_engine.detect_threats(features)

                        for threat in threats:
                            packet_info = {
                                'source_ip': packet[IP].src,
                                'destination_ip': packet[IP].dst,
                                'source_port': packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else 0,
                                'destination_port': packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else 0,
                            }
                            
                            # Generate alert
                            self.alert_system.generate_alert(threat, packet_info)
                            
                            # Block IP if configured and threat is high confidence
                            if (self.config['blocking']['enabled'] and 
                                threat['confidence'] > self.config['alert']['severity_levels']['high']):
                                self.packet_capture.block_ip(packet[IP].src, self.config['blocking']['block_duration'])

                    # Clean up expired blocks
                    self.packet_capture.unblock_expired_ips()

                except queue.Empty:
                    continue

        except KeyboardInterrupt:
            logger.info("Stopping IDS...")
            self.packet_capture.stop()

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start() 