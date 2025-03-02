import argparse
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
from scapy.all import rdpcap, IP, TCP
from collections import defaultdict

# Menambahkan counter untuk setiap IP
ip_count = defaultdict(int)
packet_size = defaultdict(int)
packet_frequency = defaultdict(int)

# Menyimpan timestamp terakhir untuk setiap IP, digunakan untuk menghitung frekuensi
last_packet_timestamp = defaultdict(float)

def packet_callback(packet):
    try:
        if IP in packet:
            src_ip = packet[IP].src
            # Hitung request count
            ip_count[src_ip] += 1

            # Hitung ukuran paket (jika ada payload TCP)
            packet_size[src_ip] += len(packet)

            # Menghitung frekuensi pengiriman paket
            current_timestamp = packet.time
            if src_ip in last_packet_timestamp:
                # Jika sudah ada timestamp sebelumnya, hitung frekuensi berdasarkan selisih waktu
                time_diff = current_timestamp - last_packet_timestamp[src_ip]
                if time_diff < 1:  # Perhitungan frekuensi per detik
                    packet_frequency[src_ip] += 1
            last_packet_timestamp[src_ip] = current_timestamp
    except IndexError:
        pass

def read_pcap(file_path):
    print(f"Reading PCAP file: {file_path}")
    packets = rdpcap(file_path)
    for packet in packets:
        packet_callback(packet)

def prepare_features(ip_count, packet_size, packet_frequency):
    # Menjamin bahwa semua fitur memiliki panjang yang sama dengan mengisi data yang hilang
    all_ips = set(ip_count.keys()).union(set(packet_size.keys()), set(packet_frequency.keys()))
    
    # Mengisi dictionary dengan nilai 0 jika tidak ada data untuk IP tertentu
    data = {
        'source_ip': [],
        'request_count': [],
        'packet_size': [],
        'packet_frequency': []
    }
    
    for ip in all_ips:
        data['source_ip'].append(ip)
        data['request_count'].append(ip_count.get(ip, 0))  # Default ke 0 jika tidak ada
        data['packet_size'].append(packet_size.get(ip, 0))  # Default ke 0 jika tidak ada
        data['packet_frequency'].append(packet_frequency.get(ip, 0))  # Default ke 0 jika tidak ada

    # Membuat dataframe dengan panjang array yang sama
    df = pd.DataFrame(data)
    features = df[['request_count', 'packet_size', 'packet_frequency']]
    return df, features

def detect_anomalies(features):
    # Standarisasi fitur menggunakan MinMaxScaler
    scaler = MinMaxScaler()
    features_scaled = scaler.fit_transform(features)

    # Gunakan Isolation Forest untuk deteksi anomali
    model = IsolationForest(contamination=0.2, random_state=42)  # Menyesuaikan contamination
    labels = model.fit_predict(features_scaled)

    # Anomali diberi label -1, data normal diberi label 1
    return labels

def main(pcap_file):
    # Membaca PCAP
    read_pcap(pcap_file)
    
    # Menyiapkan fitur
    df, features = prepare_features(ip_count, packet_size, packet_frequency)

    # Deteksi anomali menggunakan Isolation Forest
    labels = detect_anomalies(features)

    # Menambahkan hasil deteksi ke dataframe
    df['anomaly'] = labels
    df['anomaly'] = df['anomaly'].map({-1: "Anomaly", 1: "Normal"})

    print(df[['source_ip', 'request_count', 'packet_size', 'packet_frequency', 'anomaly']].head())

if __name__ == "__main__":
    # Setup parser untuk menangani input file PCAP dari command line
    parser = argparse.ArgumentParser(description="Analyze PCAP file for IP traffic anomalies.")
    parser.add_argument('pcap_file', type=str, help="Path to the PCAP file to analyze.")

    args = parser.parse_args()

    # Jalankan analisis dengan file PCAP yang diberikan
    main(args.pcap_file)
