#!/bin/bash
cd "$(dirname "$0")"
# Start the server in the background
node server.js & 
sleep 2
# Automatically open the dashboard in their default browser
open http://localhost:3000