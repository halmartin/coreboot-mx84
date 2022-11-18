#!/bin/sh

make clean
cd payloads/external/SeaBIOS/seabios/
make
cd ../../../..
make
