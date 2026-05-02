# YAMIR Android app

This is a custom admin tool for managing the YAMIR router on android devices.

These are packaged together into an android apk file yamir-android.apk. 

Code includes parts of iwconfig (GPLv2) and WiFi firmware to enable 802.11 Ad-hoc mode.   
Note the app also needs a rooted handset (su installed) to start/stop the MANET.

The application consists of 2 parts.

- A backend with shell scripts and binaries for running the MANET
- A frontend GUI to control it

## Backend

This contains the following scripts and binaries

- yamir_sh script to start and stop MANET
- samsung_s2_sh and htc_desire_shd scripts to enable Ad-Hoc mode
- HTC Desire firmware file fw_bcm4329_bin
- kyamir.ko compiled for both HTC Desire and Samsung S2
- yamird routing daemon compiled for ARM
- iwconfig to enable Ad-hoc mode (from wireless-tools) 
- killall (from psmisc)

Note the app needs a complied kyamir and shell script for each Android device.  
This is because the kernel and insmod method to control the Wi-Fi interface differ.

The iwconfig and killall are needed as these are not standard on android handsets. 

As yamir, iwconfig, killall are all userspace binaries they can be compiled for generic ARM.

All of the binaries and shell scripts are located in the raw resource folder where they must be first unpacked before use.  
This is because the Android apk build tool and the handset apk installer only allow native libraries, blacklisting executables.

## Frontend

The GUI consists of 2 files

- YamirActivity
- SettingsActivity

*YamirActvity* contains most of the code for starting and stopping the MANET. 

On first being started by Android the app locates its installation dir and the the su tool.   
The app unpacks the backend binaries and shell scripts into its work area with the correct permissions.

On pressing the “Start” button the app checks if the backend has been installed correctly and then writes the settings to a config file that is read by the yamir.sh script. It then execute with su the yamir.sh script with the start option and the config file path, displaying the results to the user in the status log. 

Pressing “Stop” likewise calls yamir.sh with the stop option and the config file path.

*SettingsActivity* allows the following settings to be modified:

- Device:  Used to select both the device script and kernel module to load.
- Interface: the network interface to use (default eth0)
- SSID: ad-hoc SSID network name to associate with (default yamir)
- Channel: The wireless channel to use (default  6)
- IP Address:  The MANET IPv4 address to  (default 192.168.1.10)
- Netmask:  the address mask to use (default 255.255.255.0)

