#!/bin/bash

declare -a arr=(bt cg dc ep ft is lu mg sp ua)

X86=_x86-64
ARM=_aarch64

USER=$(whoami)

BASE=/home/$USER

for i in "${arr[@]}"
do
   rm -rf $BASE/$i
   mkdir $BASE/$i
   mkdir $BASE/$i/bin
   cp $i/$i$X86 $BASE/$i/bin/.
   cp $i/$i$ARM $BASE/$i/bin/.
   cp $i/$i$X86 $BASE/$i/$i
   cp $i/Makefile $BASE/$i/.
done
