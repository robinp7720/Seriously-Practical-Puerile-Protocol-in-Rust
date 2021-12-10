#!/bin/bash

#
# This script will set up your loopback address to simulate an intercontinental network connection
#
# !! This script is not meant to be run on your computer directly. It will probably lead to some problems.
# You can revert all changes made by this script by simply running the following command:
#     "sudo tc qdisc del dev lo root netem"
#
# The syntax of the tc command is not that easy to understand. Therefore I'll summarize the important bits here.
#
# delay: [defualt latency] [+- x millis] [correlation]
# loss: [percentage of random droped packages] [correlation]
# duplicate: [amount of duplicate packages]
# corrupt: [amount of corrupt packages]
# reorder: [amount of reorder packages] [correlation]
#
# correlation: how is the probably dependent on the previous packet

tc qdisc add dev lo root netem \
  delay 250ms 40ms 25% \
  loss 15.3% 25% \
  duplicate 1% \
  corrupt 0.1%  \
  reorder 5% 50%