from scapy.all import *
from collections import Counter

# Словарь для хранения количества запросов к каждому домену
dns_queries = Counter()

def process_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # Проверяем, является ли пакет запросом DNS
        dns_query = packet[DNS].qd.qname.decode('utf-8')  # Получаем имя домена из запроса
        print(f"DNS Query: {dns_query}")
        dns_queries[dns_query] += 1  # Увеличиваем счетчик запросов для данного домена

# Запускаем захват пакетов
print("Starting DNS query capture...")
try:
    sniff(filter="udp port 53", prn=process_packet, store=0)  # Захватываем только UDP-пакеты на порту 53 (DNS)
except KeyboardInterrupt:
    print("nStopping capture...")
    print("nDNS Query Statistics:")
    for domain, count in dns_queries.items():
        print(f"{domain}: {count} times")
