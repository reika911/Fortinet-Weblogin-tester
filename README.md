# Network Scanning Automation System

## Purpose
Automation of corporate network penetration testing through VPN access. 
Searches for compromised accounts and vulnerable services in internal networks.

## How It Works
- Takes a database of VPN credentials (logins/passwords)
- Creates isolated containers for each connection  
- Scans internal networks for SMB services and port 9501
- Filters and sends significant results

## Key Technical Detail - PPP0 Interface
- **ppp0** is the VPN connection interface (Point-to-Point Protocol)
- Traffic to internal networks is routed through it
- Shows which networks are accessible through the VPN tunnel
- **Result:** The program automatically discovers all private networks available via VPN and scans only them, avoiding the public internet

## Operation Scheme
1. Load VPN credentials
2. Initialize Docker network  
3. Create containers
4. Connect to corporate VPN
5. Discover CIDR networks via ppp0
6. Parallel scanning (SMB + Port 9501)
7. Filter results
8. Generate reports
9. Send to Telegram
10. Save to database

## Features
- Multi-threaded container management
- Automated network discovery
- Real-time reporting via Telegram
- SQLite database for result storage
- Docker-based isolation

## Requirements
- Docker
- Python 3.8+
- VPN credentials database
- Telegram Bot API key
