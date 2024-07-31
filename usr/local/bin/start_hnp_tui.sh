#!/bin/bash
if [ "$USER" != "root" ]; then
    sudo /usr/bin/python3 /opt/TUI/hnp_tui.py
else
    /usr/bin/python3 /opt/TUI/hnp_tui.py
fi
