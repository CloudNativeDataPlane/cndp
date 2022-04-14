#Example CNDP DLB Test Example

## Overview

The example code uses the Intel's Dynamic Load Balancer (DLB) device formerly
known as Hardware Queue Manager (HQM) to load balance the packets over given
number of workers cores. It uses an externally linked libdlb user space library
developed by Intel. A producer core receives packets from the NIC and enqueues
them in the DLB. Worker/s dequeue them and re-enqueue them into DLB from which
a consumer core dequeues them and transmits them through the NIC.

## Install DLB driver

Pull the latest libdlb source code from: https://01.org/group/37165/downloads

The tarball contains a DLB driver and libdlb (user space library).

Make sure to install graphviz: $ apt-get install graphviz

Follow the instructions from the extracted tarball in docs/DLB_Driver_User_Guide.pdf
to install the DLB driver and library.

## Copy the library into /usr/local/lib/x86_64-linux-gnu
$ cp libdlb.so /usr/local/lib/x86_64-linux-gnu/ && ldconfig

## Copy the header file into /usr/local/include
Create a directory named dlb and copy all the header files from 
$BASE_DLB_DIR/libdlb*.h into /usr/local/include/dlb
CNDP will then link the library to the app if added as a dependency in the 
example's meson file
  deps += [libdlb]
