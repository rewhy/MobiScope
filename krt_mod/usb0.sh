#!/bin/bash
ifconfig usb0 down
ifconfig usb0 hw ether 02:11:22:33:44:55
ifconfig usb0 192.168.42.1
ifconfig usb0 up
