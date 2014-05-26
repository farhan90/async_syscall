#!/bin/sh
set -x
lsmod
rmmod async_mod
insmod async_mod.ko
lsmod
