# Tools

## Debugger
Used to suspend an application at a program point specified by the address. 

### Running the app
./debugger [/path/to/application/binary] [addressOfLineWhereToSuspendInHex]

eg. `./debugger ~/temp/testBin 0x00501031` 
The above command will suspend the testBin app at address `0x00501031`.