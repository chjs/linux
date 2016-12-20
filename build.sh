#!/bin/bash
sudo make -j 32 2> make.log
sudo make -j 32 modules
sudo make -j 32 modules_install
sudo make -j 32 install
