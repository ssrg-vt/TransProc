#!/bin/bash
# FIXME: Change to the following variables
x86=ms1111.utah.cloudlab.us
arm=ms2222.utah.cloudlab.us
user=xgwang
home=/users
hostname=cloudlab
keyfile=dapper-vms
apt='sudo apt install -y libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler python-protobuf pkg-config libnl-3-dev libnet1-dev libcap-dev libbsd-dev python3-pip cmake'
pip='python3 -m pip install pyelftools jsonpath-ng pyro4 psutil protobuf==3.20 capstone keystone keystone-engine'
DAPPER_GIT='https://github.com/xjtuwxg/TransProc.git'

# Generate ssh keys
ssh_key()
{
echo "Generate ssh keys and copy them to the VMs."
ssh-keygen -f $keyfile -C $user@$hostname
ssh-copy-id -i $keyfile $user@$x86
ssh-copy-id -i $keyfile $user@$arm

scp $keyfile $keyfile.pub $user@$x86:~/.ssh
scp $keyfile $keyfile.pub $user@$arm:~/.ssh
}

# Setup .ssh/config
setup_config()
{
echo "Setting up .ssh/config files."
ssh $user@$x86 'echo "Host arm" >> .ssh/config'
ssh $user@$x86 'echo "  HostName '$arm'" >> .ssh/config'
ssh $user@$x86 'echo "  User '$user'" >> .ssh/config'
ssh $user@$x86 'echo "  Port 22" >> .ssh/config'
ssh $user@$x86 'echo "  IdentityFile '$home'/'$user'/.ssh/'$keyfile'" >> ~/.ssh/config'

ssh $user@$arm 'echo "Host x86" >> .ssh/config'
ssh $user@$arm 'echo "  HostName '$x86'" >> .ssh/config'
ssh $user@$arm 'echo "  User '$user'" >> .ssh/config'
ssh $user@$arm 'echo "  Port 22" >> .ssh/config'
ssh $user@$arm 'echo "  IdentityFile '$home'/'$user'/.ssh/'$keyfile'" >> ~/.ssh/config'
}

# Install necessary software dependencies
dependency()
{
echo "Install necessary software dependencies."
ssh -t $user@$x86 'sudo apt-get -y update;'$apt
ssh -t $user@$arm 'sudo apt-get -y update;'$apt

ssh -t $user@$x86 $pip
ssh -t $user@$arm $pip
}

# Clone Dapper and build from the source code
clone_build()
{
echo "Clone Dapper and build from the source code."
ssh -t $user@$x86 'git clone '$DAPPER_GIT' ~/TransProc'
ssh -t $user@$arm 'git clone '$DAPPER_GIT' ~/TransProc'

ssh -t $user@$x86 'cd TransProc; make; make vdso'
ssh -t $user@$arm 'cd TransProc; make; make vdso'

ssh -t $user@$arm 'scp ~/TransProc/criu-3.15/lib/py/templates/aarch64_vdso.img.tmpl x86:~/TransProc/criu-3.15/lib/py/templates/aarch64_vdso.img.tmpl'
ssh -t $user@$x86 'scp ~/TransProc/criu-3.15/lib/py/templates/x86_64_vdso.img.tmpl arm:~/TransProc/criu-3.15/lib/py/templates/x86_64_vdso.img.tmpl'
}

# Do all steps in one command
all()
{
    ssh_key
    setup_config
    dependency
    clone_build
}

Help()
{
   # Display Help
   echo "Setup Dapper Hosts via scripts."
   echo
   echo "Syntax: setup-hosts.sh [-g|h|v|V]"
   echo "options:"
   echo "s     Generate SSH keys."
   echo "c     Setting up .ssh/config files."
   echo "d     Install necessary software dependencies"
   echo "b     Clone Dapper and build from the source code."
   echo "a     Do all steps in one command."
   echo
}

############################################################
# Main program                                             #
############################################################
# Process the input options.                               #
############################################################
# Get the options
while getopts ":hscdba" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      s) # setup ssh keys
         ssh_key
         exit;;
      c) # setup .ssh/config files
         setup_config
         exit;;
      d) # install dependencies
         dependency
         exit;;
      b) # clone the source code and build Dapper
         clone_build
         exit;;
      a) # do all steps in one command
         all
         exit;;
      \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done