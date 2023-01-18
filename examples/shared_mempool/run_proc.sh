#!/bin/bash

#Turn off ASLR to ensure the virtual address is the same between runs
sudo echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

#Run the proc
sudo ./proc

#Turn ASLR back on to ensure security
sudo echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
