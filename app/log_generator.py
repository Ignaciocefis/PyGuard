from kafka import KafkaProducer
import time
import random

producer = KafkaProducer(bootstrap_servers = ['localhost:9093'])

events = ['LOGIN_SUCCESS', 'LOGIN_FAILURE', 'PORT_SCAN', 'SQL_INJECTION', 'MALWARE']
sources = ['firewall', 'ids', 'webserver', 'endpoint']

while True:
    log = f'{random.choice(sources)}, {random.choice(events)}, {random.randint(100,10000)}'
    producer.send('logs_topic', log.encode('utf-8'))
    print(f'Sent log: {log}')
    time.sleep(1)