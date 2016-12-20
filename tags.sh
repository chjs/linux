#!/bin/bash
make -j 32 O=. SRCARCH=x86 SUBARCH=x86_64 COMPILED_SOURCE=1 cscope tags 

