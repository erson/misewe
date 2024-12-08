#!/bin/bash

# Colors
BLUE='\033[0;34m'
NC='\033[0m'

# Function to display server status
show_status() {
    clear
    echo -e "${BLUE}Server Status${NC}"
    echo "----------------"
    echo "Active Connections: $(netstat -an | grep :8000 | grep ESTABLISHED | wc -l)"
    echo "Recent Requests: $(tail -n 10 logs/access.log | wc -l)"
    echo "Error Count: $(tail -n 100 logs/error.log | wc -l)"
    echo "Blocked Attempts: $(grep "BLOCKED" logs/security.log | wc -l)"
    
    echo -e "\n${BLUE}Recent Access Log${NC}"
    echo "----------------"
    tail -n 5 logs/access.log
    
    echo -e "\n${BLUE}Recent Error Log${NC}"
    echo "----------------"
    tail -n 5 logs/error.log
    
    echo -e "\n${BLUE}Security Events${NC}"
    echo "----------------"
    tail -n 5 logs/security.log
}

# Main monitoring loop
while true; do
    show_status
    sleep 2
done