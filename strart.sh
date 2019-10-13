#!/bin/bash
ssh -t -o "ConnectionAttempts 60" -p 1111 mininet@localhost \
"cd ~/SimpleRouter && (xterm -hold -e './run_mininet.sh' &) && sleep 10 && (xterm -iconic -hold -e './run_pox.sh' & bash --login)"