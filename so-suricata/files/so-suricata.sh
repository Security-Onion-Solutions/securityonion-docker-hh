#!/bin/bash

# Start Suricata - --init-errors-fatal could be added to make it die if rules are wrong
/opt/suricata/bin/suricata -c /etc/suricata/suricata.yaml --enable-rust --af-packet=$INTERFACE --user=940 --group=940
