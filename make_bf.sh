#!/bin/bash

for f in `ls password_lists/`; do
    echo $f
    time ./adv_go_bf password_lists/$f  > output/$f.otpt.txt 2>&1
done;