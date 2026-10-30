#!/bin/bash

./ns3 build scratch-mptcp-transfile
echo "" > ./tmp.log
for i in {1..10}; do
     ./build/scratch/mptcp-transfile/ns3.46.1-scratch-mptcp-transfile-debug >> tmp.log
done
grep "execute time:" tmp.log;
