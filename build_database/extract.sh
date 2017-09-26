#!/bin/bash

for file in lbl-mr2*.tar.gz
do
    echo $file
    tar -xzf $file
done


