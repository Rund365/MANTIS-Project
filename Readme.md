# MANTIS - Monitoring And Network Traffic Interception System

## Overview
MANTIS (Monitoring And Network Traffic Interception System) is a network monitoring and manipulation tool developed as part of the **Technion Industrial Projects (234313)** in collaboration with **Rafael**. It allows real-time packet sniffing, filtering, and traffic control through a **Flask-based web application**.

## Features
- **Real-time Network Traffic Monitoring**: Capture and analyze packets in real-time.
- **Advanced Filtering**: Apply filters based on IP, port, and protocol.
- **Traffic Manipulation**: Implement bandwidth control and network delay.
- **User-Friendly Web Interface**: Interactive UI for configuring network monitoring and control.

## Prerequisites
Ensure the following dependencies are installed before running the project:

### System Requirements
- **Linux (Ubuntu recommended)**
- **Python 3.12+**
- **sudo privileges** (required for traffic control operations)

### Required Python Packages
Run the following command to install required dependencies:
```bash
pip install -r requirements.txt
```

If `requirements.txt` is missing, manually install dependencies:
```bash
pip install flask flask-cors scapy
```

## Installation & Setup

### Step 1: Clone the Repository
```bash
git clone <repository_link>
cd MANTIS
```

### Step 2: Create a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate 
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

## Running the Project

### **Step 1: Start the Flask Backend**
The backend handles network monitoring and traffic control.

#### **Run with Root Privileges (Recommended)**
Since `tc` and `scapy` require administrative rights:
```bash
sudo $(which python3) main.py
```

#### **Run Without Root Privileges (Not Recommended)**
```bash
python3 main.py
```

### **Step 2: Start the Frontend**
The frontend provides a web-based interface to interact with MANTIS.
Since it's a static HTML page, it needs to be served with a simple HTTP server.


#### **Start a Local HTTP Server**
Open a **new terminal** (separate from the backend) and navigate to the project directory:
```bash
cd /path/to/MANTIS
```
Then, run:
```bash
python3 -m http.server 8000
```

the Flask server will run at:
```
http://127.0.0.1:5004
```


#### **Access the Web Interface**
Once the server is running, open a web browser and visit:
```
http://127.0.0.1:8000/front2.html
```

## Using MANTIS

### Starting Packet Sniffing
1. Select the **Network Interface** (e.g., `eth0`, `lo`).
2. Define filters:
   - Source/Destination IP
   - Port
   - Protocol
3. Click **Start Sniffing**.

### Applying Bandwidth Limits
1. Enter the **Port Number** and desired **Bandwidth (Kbps)**.
2. Select the **Interface** from the dropdown.
3. Click **Apply Limit**.

### Stopping Packet Sniffing
- Click **Stop Sniffing** to halt monitoring.

### Removing Bandwidth Limits
- Click **Remove Limit** under the bandwidth section.

## Troubleshooting

### 1. `ModuleNotFoundError: No module named 'flask'`
Ensure you are using the virtual environment:
```bash
source venv/bin/activate
pip install flask flask-cors scapy
```

### 2. Flask Server Not Responding
Check if another process is using port `5004`:
```bash
sudo lsof -i :5004
```
Kill the process:
```bash
sudo kill -9 <PID>
```
Restart Flask.

### 3. Permission Denied for `tc` Commands
Ensure the script is run with `sudo`:
```bash
sudo $(which python3) main.py
```

## Contributors
- Rund Subih & Ameer Nasr-Al-Deen
- **Project Supervisor:** Mr. Adam Zaft (Rafael)
- **Institution:** Technion - Israel Institute of Technology

