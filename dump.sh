#!/bin/bash
# FIXME: Change to the Dapper(criu) path and the binary path
DAPPER_PATH=./
BIN_PATH=~/

criu=$DAPPER_PATH/criu-3.15/criu/criu
tracer=$DAPPER_PATH/tools/tracer

## Check CRIU executable
if [ ! -f "$criu" ]
then
    echo "Cannot find criu! Please set the DAPPER_PATH correctly!"
    exit 1
fi

## Check command line parameters
if [ $# != 1 ]; then
    echo "Use ./dump.sh <program name>"
    exit 1
fi

## Check the program binary
if [ ! -f "$BIN_PATH/$1" ]
then
    echo "Cannot find the binary! Please set the BIN_PATH correctly!"
    exit 1
fi

pid=$(pidof $1)
#path=/tmp/$pid
path=./default-dump-dir
if [[ -z $pid ]]; then
    echo $1 "process does not exist"
    exit 1
fi

## Prepare the dir for process dump and transform
mkdir -p $path
rm $path/* -rf
mkdir -p $path/bin
cp $BIN_PATH/$1_* $path/bin
cp $BIN_PATH/$1 $path

## Suspend the process with the tracer tool
sudo $tracer $pid

echo "Dump process:" $pid
## Run criu dump and change the dump image ownership
sudo $criu dump -D $path -j -t $(pidof $1)
sudo chown $(id -un):$(id -gn) $path -R

## Transform the process image with Dapper
python3 $DAPPER_PATH/criu-3.15/crit/crit recode $path ./aarch64/ aarch64 $1 $path/bin/ n

## scp the transformed process images to the ARM node
echo "Copying process images to the remote machine..."
scp -q -r ./aarch64 arm:~

## Execute restoration on the remote node
#ssh -t arm 'sudo ~/TransProc/criu-3.15/criu/criu restore -vv -o restore.log -j -D aarch64'
