# Pymavlink for secure mavlink
This repository(branch) contains 'secure mavlink' implementation.
Please see the below link for the original pymavlink README document.

[README](./README_orig.md/)

# Secure mavlink
Below list is implementations to enhance security of mavlink protocol.  
* Add payload encryption support, for protocol v2.0, C language.

## Payload encryption support
Location of modified code is [v2.0 C fixed header](./generator/C/include_v2.0).  
See the comment of [this file](./generator/C/include_v2.0/mavlink_mesl_crypto.h) to use encryption support (MESL_CRYPTO).  
Program that use MAVLink, can decide if encryption is enabled, per MAVLink frame.  
Program that use MAVLink, can decide what encryption method will be used, per MAVLink frame.  
Program that use MAVLink, should implement actual encryption process.  
For now payload encryption support is only available for protocol v2.0, C language.  
Added / modified components:  
* Modify 'finalize' process and parsing process, for en/de-cryption.
* Add some functions that should be implemented by other program, for actual en/de-cryption process etc.
* Modify 'iflag' of MAVLink frame to use 3 bit more, this saves encryption method value in frame.
* Modify 'mavlink_status_t', to track encryption method, etc.

## Other features - time debugging support
Location of modified code is [v2.0 C fixed header](./generator/C/include_v2.0).  
See the comment of [this file](./generator/C/include_v2.0/mavlink_mesl_crypto.h) to use encryption support (MESL_MAV_TEBUG).

