# %%
# %%
# network libraries
import socket
import pymysql
import schedule
import threading
import ipaddress

# general libraries
import os
import time
import json
import random
import struct
import platform
import subprocess
import pandas as pd
from typing import List
from datetime import datetime

# blockchain libraries
import hashlib
import plyvel

## RGB LED SETUP FOR RASPBERRY PI ONLY ##################################################################################
try: 
    import RPi.GPIO as GPIO
    from rgb_controller import *
except:
    pass

def turn_on_light(color):
    try:
        if color == "white": white()
        if color == "red": red()
        if color == "green": green()
        if color == "blue": blue()
        if color == "yellow": yellow()
        if color == "purple": purple()
        if color == "light_blue": light_blue()
        if color == "turn_off": turn_off()
    except:
        pass
#########################################################################################################################
def get_ip_address():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip


def get_wifi_ip_address():
    os_type = platform.system()

    if os_type == "Windows":
        try:
            output = subprocess.check_output("ipconfig").decode("utf-8")
            lines = output.split("\n")
            for line in lines:
                if "Wireless LAN adapter Wi-Fi" in line:
                    break
            for line in lines[lines.index(line):]:
                if "IPv4 Address" in line:
                    wifi_ip = line.split(":")[-1].strip()
                    return wifi_ip
        except Exception as e:
            print(f"Error: {e}")
            return None

    elif os_type == "Linux":
        try:
            output = subprocess.check_output(["ifconfig", "-a"]).decode("utf-8")
            lines = output.split("\n")
            for line in lines:
                if "wlan0" in line or "wlp" in line:
                    break
            for line in lines[lines.index(line):]:
                if "inet" in line and "inet6" not in line:
                    wifi_ip = line.split()[1]
                    return wifi_ip
        except Exception as e:
            print(f"Error: {e}")
            return None

    else:
        print("Unsupported platform.")
        return None

# Global Variables ######################################################################################################
# NODE CONFIGURATION SETTINGS

LOCAL_IP = get_wifi_ip_address()
print(LOCAL_IP)
LOCAL_IP_RANGE = [LOCAL_IP]
LOCAL_ROUTING_PREFIX = "/22"
PORT_RANGE = (5000, 5002)

# AWS MySQL server
HOST = "device.cbkd9ijescfh.us-east-1.rds.amazonaws.com"
PORT = "3306"
DB_NAME = "device_database"
USERNAME = "sensor"
PASSWORD = "helloworld123!"

# read database and dataframe
try:
    DB = pd.read_csv("blockchain.csv")
except:
    DB = pd.DataFrame()

PLYVEL_DB = plyvel.DB('plyvel_blockchain', create_if_missing=True)

BLOCKCHAIN_INDEX = 0
PREVIOUS_HASH = None
for key, value in PLYVEL_DB:
    BLOCKCHAIN_INDEX += 1
    block_dict = json.loads(value.decode('utf-8'))
    PREVIOUS_HASH = block_dict["block_hash"]
print("INDEX IS CURRENTLY", BLOCKCHAIN_INDEX)

is_running = False

#########################################################################################################################

# define a class Node for each node in the network ######################################################################
class Node:
    def __init__(self, ip: str, port: int, rand_num: int, hash_num: str):
        # information to store from each node in the network
        self.ip = ip
        self.port = port
        self.rand_num = rand_num
        self.hash_num = hash_num
        self.neighbors: List[Node] = []

    def __repr__(self):
        return f"{self.ip}:{self.port}"
    
    def print_neighbors(self):
        # outputs all connected nodes
        print("Neighbors:")
        for neighbor in self.neighbors:
            print(f"{neighbor.ip}:{neighbor.port} with {neighbor.rand_num}|{neighbor.hash_num}")
#########################################################################################################################

# find an open port to connect to #######################################################################################
def get_open_port():
    for port in range(PORT_RANGE[0], PORT_RANGE[1]):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex((LOCAL_IP, port)) != 0:
                return port
    raise Exception("No open ports available in the specified range.")
#########################################################################################################################

# find all active nodes on the network ##################################################################################
def scan_for_nodes(network, ip_network_str: str, port_range: tuple):
    print("Scanning for active nodes on network...")
    own_ip, own_port = network.node.ip, network.node.port

    ip_network = LOCAL_IP_RANGE

    # Iterate through IP addresses in the network
    for target_ip in ip_network:
        target_ip_str = target_ip
        for port in range(port_range[0], port_range[1] + 1):
            if f"{own_ip}:{own_port}" != f"{target_ip_str}:{port}" and (target_ip_str, port) not in network.node.neighbors:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        s.connect((target_ip_str, port))
                        network.add_neighbor(ip = target_ip_str, port = port)
                except Exception as e:
                    pass
#########################################################################################################################

# block for the blockchain ##############################################################################################
class Block:
    def __init__(self, index, sender, timestamp, db_hash, who=None, device=None, previous_hash=None):
        self.index = index
        self.timestamp = timestamp
        self.sender = sender
        self.who = who
        self.device = device
        self.previous_hash = previous_hash
        self.db_hash = db_hash
        self.block_hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps(self.hash_dict(), sort_keys=True, default=str)
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

    def hash_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'sender': self.sender,
            'who': self.who,
            'device': self.device,
            'previous_hash': self.previous_hash,
            'db_hash': self.db_hash
        }
    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'sender': self.sender,
            'who': self.who,
            'device': self.device,
            'previous_hash': self.previous_hash,
            'db_hash': self.db_hash,
            'block_hash': self.block_hash
        }
#########################################################################################################################

# defines a class to handle each node in the network ####################################################################
class P2PNetwork:
    def __init__(self, node: Node, db, who=None, device=None):
        self.node = node
        self.node.neighbors.append(node)
        self.db = db
        self.who = who
        self.device = device
    
    # updates values for each node
    def update_values(self, ip: str, port: int, value_type: str, value: int):
        for neighbor in self.node.neighbors:
            if (neighbor.ip, neighbor.port) == (ip, port):
                if value_type == "hash":
                    neighbor.hash_num = value
                    return
                elif value_type == "non_hashed":
                    neighbor.rand_num = value
                    return
        print("Error, neighbor not found!")

    # listens for incoming information and accepts 
    # need to add check to see if a connection is valid
    def listen(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.node.ip, self.node.port))
            s.listen(len(self.node.neighbors) * 2)
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self.handle_connection, args=(conn,)).start()

    # segregates connections based on type of message
    def handle_connection(self, conn):
        global BLOCKCHAIN_INDEX
        global PREVIOUS_HASH

        data = conn.recv(1024).decode()
        if data:
            message = json.loads(data)
            if message["type"] == "add_neighbor":
                self.add_neighbor(message["ip"], message["port"], message["node"])
            elif message["type"] == "sync":
                self.miner_selection_wrapper()
            elif message["type"] == "change_detection":
                self.who = message["who"]
                self.device = message["device"]
                self.miner_selection_wrapper()
            elif message["type"] == "mining":
                self.validate_and_store_mined_data(message["data"])
            elif message["type"] == "db_hash":
                print("Verifying and adding hash to LevelDB...")
                # connect to server and create a command line instance
                connection = pymysql.connect(host=HOST, 
                                            user=USERNAME, 
                                            password=PASSWORD,
                                            db=DB_NAME)
                cursor = connection.cursor()

                # query all data from server
                cursor.execute("SELECT * FROM device_database.device_settings")
                table_data = cursor.fetchall()
                # store all data into dataframe
                df = pd.DataFrame(table_data)
                # rename columns in dataframe to columns name from query
                df.columns = [i[0] for i in cursor.description]
                db_hash = hashlib.sha256(pd.util.hash_pandas_object(df).values).hexdigest()

                new_block_hash = message["block_hash"]
                new_block = message["block"]

                block_string = json.dumps(new_block, sort_keys=True, default=str)
                block_hash = hashlib.sha256(block_string.encode('utf-8')).hexdigest()

                try:
                    assert(db_hash == new_block["db_hash"])
                    assert(block_hash == new_block_hash)
                except:
                    print("Error: Hashes do not match!")
                
                new_block["block_hash"] = new_block_hash

                PLYVEL_DB.put(struct.pack('>I', new_block["index"]), json.dumps(new_block, default=str).encode('utf-8'))

                self.db = pd.concat([self.db, pd.DataFrame([new_block])], ignore_index=True)
                self.db.to_csv("blockchain.csv", index=False)

                BLOCKCHAIN_INDEX += 1
                PREVIOUS_HASH = new_block["block_hash"]
                
                self.node.neighbors = [self.node]

    # broadcasts information to all  known neighbors
    def broadcast(self, message: str):
        for neighbor in self.node.neighbors:
            if neighbor != self.node:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    print(f"Sending message: {message} to: {neighbor.ip}:{neighbor.port}")
                    s.connect((neighbor.ip, neighbor.port))
                    s.sendall(message.encode())

    # add a new neighbor
    def add_neighbor(self, ip: str, port: int):
        for neighbor in self.node.neighbors:
            if (neighbor.ip, neighbor.port) == (ip, port):
                return
        print(f"Adding {ip}:{port} as a neighbor...")
        self.node.neighbors.append(Node(ip, port, None, None))

    # miner selection algorithm as defined by Dr. Yu
    def miner_selection(self, user=None):
        global BLOCKCHAIN_INDEX
        global PREVIOUS_HASH

        turn_on_light("red")
        scan_for_nodes(network=self, ip_network_str=LOCAL_IP + LOCAL_ROUTING_PREFIX, port_range=PORT_RANGE)
        
        # sort the neighbors by IP
        self.node.neighbors.sort(key=lambda node: node.ip + str(node.port))
        self.broadcast(json.dumps({"type": "sync"}))
        time.sleep(3)

        turn_on_light("blue")
        # select a random number between 1 - 99999
        non_hashed = random.randint(1, 99999)
        self.update_values(self.node.ip, self.node.port, 'non_hashed', non_hashed)
        # hash that number
        hashed_value = hashlib.sha256(str(non_hashed).encode()).hexdigest()
        self.update_values(self.node.ip, self.node.port, 'hash', hashed_value)

        self.broadcast(json.dumps({"type": "mining", "data": {"hash": hashed_value, "origin": str(self.node)}}))
        
        time.sleep(5)  # Give time for other nodes to send their hashes

        self.broadcast(json.dumps({"type": "mining", "data": {"non_hashed": non_hashed, "origin": str(self.node)}}))

        time.sleep(5)

        turn_on_light("yellow")
        total = 0
        for neighbor in self.node.neighbors:
            print(f"Adding {neighbor.rand_num}")
            total = total + neighbor.rand_num
        selected_index =  total % len(self.node.neighbors)

        selected_node = self.node.neighbors[selected_index]
            
        print(f"Total: {total} Selected index: {selected_index} Selected node: {selected_node}")

        time.sleep(3)

        if selected_node == self.node:
            turn_on_light("green")
            print("This node is selected to generate a hash of an AWS SQL database.")

            # connect to server and create a command line instance
            connection = pymysql.connect(host=HOST, 
                                        user=USERNAME, 
                                        password=PASSWORD,
                                        db=DB_NAME)
            cursor = connection.cursor()

            # query all data from server
            cursor.execute("SELECT * FROM device_database.device_settings")
            table_data = cursor.fetchall()
            # store all data into dataframe
            df = pd.DataFrame(table_data)
            # rename columns in dataframe to columns name from query
            df.columns = [i[0] for i in cursor.description]

            new_block = Block(index=BLOCKCHAIN_INDEX, 
                              sender=self.node.ip + ":" + str(self.node.port), 
                              timestamp=datetime.now(),
                              db_hash=hashlib.sha256(pd.util.hash_pandas_object(df).values).hexdigest(),
                              who=user,
                              previous_hash=PREVIOUS_HASH)
        
            self.broadcast(json.dumps({"type": "db_hash", "block_hash": new_block.block_hash, "block": new_block.hash_dict()}, default=str))
            
            self.db = pd.concat([self.db, pd.DataFrame([new_block.to_dict()])], ignore_index=True)
            self.db.to_csv("blockchain.csv", index=False)

            print("Adding hash to local LevelDB...")
            PLYVEL_DB.put(struct.pack('>I', new_block.index), json.dumps(new_block.to_dict(), default=str).encode('utf-8'))
            BLOCKCHAIN_INDEX += 1
            PREVIOUS_HASH = new_block.block_hash
        else:
            print(f"Node {selected_index} is selected to generate a hash of an AWS SQL database.")
        time.sleep(3)
        turn_on_light("turn_off")

    def miner_selection_wrapper(self):
        global is_running
        
        if not is_running:
            is_running = True
            try:
                self.miner_selection()
            finally:
                is_running = False
    # validate the information sent by other nodes
    def validate_and_store_mined_data(self, data):
        if "hash" in data and "origin" in data:
            hashed_value = data["hash"]
            origin = data["origin"]
            received_port_number = int(origin.split(":")[1])
            received_ip_number = str(origin.split(":")[0])
            self.update_values(received_ip_number, received_port_number, 'hash', hashed_value)
        elif "non_hashed" in data and "origin" in data:
            non_hashed = data["non_hashed"]
            origin = data["origin"]
            received_port_number = int(origin.split(":")[1])
            received_ip_number = str(origin.split(":")[0])
            for neighbor in self.node.neighbors:
                if (neighbor.ip, neighbor.port) == (received_ip_number, received_port_number):
                    stored_hash = neighbor.hash_num

            if stored_hash == hashlib.sha256(str(non_hashed).encode()).hexdigest():
                self.update_values(received_ip_number, received_port_number, 'non_hashed', non_hashed)
            else:
                print("Error hash numbers do not match!")
#########################################################################################################################

# %%
#########################################################################################################################
# initializes the server
port = get_open_port()
node = Node(LOCAL_IP, port, None, None)
network = P2PNetwork(node, DB)
print(f"Node started on {LOCAL_IP}:{port}")
threading.Thread(target=network.listen).start()

schedule.every(120).seconds.do(network.miner_selection_wrapper)  # Schedule miner_selection every x minutes
while True:
    schedule.run_pending()
#########################################################################################################################
