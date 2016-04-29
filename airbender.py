import sys, os, subprocess, shutil
import argparse
from argparse import ArgumentParser
import tempfile
import atexit
# import pandas
import time


###############################################################
# Specify directory to store temporary intercepted packets
# Default: Creates folder in current directory
packetPath = ""

# Specify path to custom dictionary for cracking
# Default: Uses included dictionary 
dictionaryPath = ""

# Specify file to store passwords in
# Default: Creates file "passwords.txt"
passwordsPath = ""

# Specify interface name of the monitor-mode-capable device you
# would like to use.
# Default: Searches for monitor-mode-capable devices at runtime
interfaceName = ""

# Specify access point MAC address (BSSID) to target
# Default: Present user with detected access points to choose from
targetAP = ""
###############################################################


def main():
	if not os.geteuid() == 0:
		sys.exit('Please run as root')
	try:
		environmentSetup()
		getTargetAccessPoint()
		captureHandshake()
		# Next steps here
	finally:
		# this ensures that clean up occurs even on error
		cleanUp()

def is_valid_path(parser, arg):
    if not os.path.exists(arg):
        parser.error("The path %s does not exist!" % arg)


def bash_command(cmd, timeout=None):
	return subprocess.Popen(['/bin/bash', '-c', cmd], stdout=subprocess.PIPE)


class readable_dir(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        prospective_dir=values
        if not os.path.isdir(prospective_dir):
            raise argparse.ArgumentTypeError("readable_dir:{0} is not a valid path".format(prospective_dir))
        if os.access(prospective_dir, os.R_OK):
            setattr(namespace,self.dest,prospective_dir)
        else:
            raise argparse.ArgumentTypeError("readable_dir:{0} is not a readable dir".format(prospective_dir))


def environmentSetup():
	global packetPath
	global dictionaryPath
	global passwordsPath

	# Prep ArgumentParser
	# ldir = tempfile.mkdtemp()
	# atexit.register(lambda dir=ldir: shutil.rmtree(ldir))

	# parser = ArgumentParser(description='test', fromfile_prefix_chars="@")
	# parser.add_argument('--packetPath', action=readable_dir, default=ldir)
	# parser.add_argument('--dictionaryPath', action=readable_dir, default=ldir) # How will this work?
	# parser.add_argument('--passwordsPath', action=readable_dir, default=ldir)
	# args = parser.parse_args()

	# read args, if any
	args = list(sys.argv)
	for i, arg in enumerate(args):
		if i == 0:
			continue
		setGlobalAttribute(arg)

	''' The following if statements will only execute if the user
	user did NOT specify that particular attribute either global (in this file)
	or via the commandline. '''
	# use default path for packets	
	if not packetPath and not os.path.exists(os.getcwd() + "/packets"):
		os.makedirs(os.getcwd() + "/packets")
		packetPath = os.getcwd() + "/packets"
	# use included dictionary
	if not dictionaryPath and os.path.isfile(os.getcwd() + "/dictionary.txt"):
		dictionaryPath = os.getcwd() + "/dictionary.txt"
	# use default passwords file
	if not passwordsPath and os.path.isfile(os.getcwd() + "/passwords.txt"):
		# TODO: Make passwords.txt file if there isn't one
		passwordsPath = os.getcwd() + "/passwords.txt"


def setGlobalAttribute(arg):
	attributeAndPath = arg.split('=')
	attribute = attributeAndPath[0]
	path = attributeAndPath[1]

	if not os.path.exists(path):
		raise ValueError("Path not found: " + path)

	if attribute == 'packetPath':
		packetPath = path
	elif attribute == 'dictionaryPath':
		dictionaryPath = path
	elif attribute == 'passwordsPath':
		passwordsPath = path
	else:
		raise ValueError("Invalid argument: " + attribute)


def getTargetAccessPoint():
	''' airdump setup '''
	global interfaceName

	print("Killing potential interfering processes...")
	process = bash_command("airmon-ng check kill")
	print(process.stdout.read().decode('utf-8').strip()) # TODO: strip whitespace out of here
	# TODO: Handle error output

	print("Stopping avahi-daemon...")
	process = bash_command("/etc/init.d/avahi-daemon stop")
	print(process.stdout.read().decode('utf-8'))
	# TODO: Handle error output

	# TODO: Check for eth0 interface
	# Use 'ifconfig'
	print("Taking your eth0 down...")
	process = bash_command("ifconfig eth0 down")
	print(process.stdout.read().decode('utf-8'))
	# TODO: Handle error output

	while True:
		if interfaceName == '':
			print("Listing interface types...")
			interfaceName = getInterfaceName()

		if interfaceName == '':
			# TODO: raise no capatable inteface exception?
			return
		channel = input("Channel number to listen to (0 to scan multiple): ")
		scanTime = input("Time limit to listen: ")
		scanAccessPoints(interfaceName, channel, scanTime)
		result = input("Start new scan? (y=yes): ")
		if result == 'y' or result == 'yes' or result == '1':
			continue
		else:
			break
		# TODO: Add repeat option?


def scanAccessPoints(interfaceName, channel, scanTime):
	print("Using interface: " + interfaceName)
	# Allow user to select an AP (access point) by MAC address
	print("Listing routers close to user's location...")
	# TODO: What if it's listed as wlan0 but changes to wlan0mon?
	if int(channel) > 0:
		airodump = bash_command("airodump-ng -c " + str(channel) + " " + str(interfaceName) + " -w dump --output-format csv")
	else:
		airodump = bash_command("airodump-ng " + str(interfaceName) + " -w dump --output-format csv")
	time.sleep(int(scanTime))
	airodump.terminate()
	print("Scan complete.")


def getInterfaceName():
	# get device names and their corresponding physical names
	dev_name = {}
	output = bash_command("iw dev").stdout.read().decode('utf-8').splitlines()
	for i, line in enumerate(output):
		if line.startswith('phy'):
			dev_name[output[i].strip().replace('#','')] = output[i+1].split()[1]

	# find out what modes each device supports
	modes = {}
	for phy in dev_name.keys():
		i=0
		# call "iw <dev> info"
		output = bash_command("iw "+phy+" info").stdout.read().decode('utf-8').splitlines()
		# read indented block following "Supported interface modes:" line
		while i<len(output):
			if output[i].strip() == "Supported interface modes:":
				modes[phy] = []
				level = len(output[i]) - len(output[i].lstrip('\t'))
				i+=1
				while (len(output[i]) - len(output[i].lstrip('\t'))) > level:
					modes[phy].append(output[i].strip())
					i += 1
			i+=1

	# count how many devices support monitor mode
	compatible_devices = []
	for phy in modes.keys():
		if any("monitor" in s for s in modes[phy]):
			compatible_devices.append(dev_name[phy])

	# check if there are 1 or fewer compatible devices
	# TODO: throw exception instead of returning empty string
	chosen_interface = ''
	if len(compatible_devices) == 0:
		print("No compatible wireless devices found.")
		return ''
	elif len(compatible_devices) == 1:
		print("Found one compatible wireless device: " + compatible_devices[0])
		return compatible_devices[0]
		chosen_interface = compatible_devices[0]

	# ask the user to choose a wireless interface
	while chosen_interface == '':
		for i, v in enumerate(compatible_devices):
			print("\t["+str(i)+"] "+v)
		choice = input(str(len(compatible_devices)) + " compatible wireless devices found. Please choose: ")
		if choice.isdigit() and (int(choice) >= 0) and (int(choice) < len(compatible_devices)):
			chosen_interface = compatible_devices[int(choice)]
			break;
		else:
			print(choice + " is an invalid option, please try again.\n")

	# enable monitor mode on chosen interface
	print("Enabling monitor mode on " + chosen_interface + "...")
	process = bash_command("airmon-ng start " + chosen_interface)

	# check if interface name updated
	output = bash_command("iwconfig").stdout.read().decode('utf-8').splitlines()
	for line in output:
		if any(chosen_interface in s for s in line.split()):
			chosen_interface = line.split()[0]
	# else:
	# 	print("Can't find updated interface name after putting it into monitor mode")
	# 	return ''

	return chosen_interface

	# TODO: Handle error output


def captureHandshake():
	# Get MAC address of the target access point (router)
	routerBSSID = input("Please select router MAC address (BSSID 1): ")

	# List all clients connected to target AP
	bash_command("airodump-ng -c 6 --bssid " + routerBSSID + " -w packet " + interfaceName)
	# TODO: Parse input - insert colon delimiters, make all-caps?

	# TODO: Allow for option to choose strongest
	# colnames = ['BSSID', 'ESSID']
	# accessPoints = pandas.read_csv('dump-01.csv', names=colnames)
	# bssids = accessPoints.BSSID.tolist()
	# essids = accessPoints.ESSID.tolist()
	# print(bssids)
	# print("\n\n" + essids)




def cleanUp():
	# TODO: remove dump file
	if os.path.exists(os.getcwd() + "/packets"):
		shutil.rmtree(os.getcwd() + "/packets")

	if os.path.isfile(os.getcwd() + "/dump-01.csv"):
		os.remove(os.getcwd() + "/dump-01.csv")


if __name__ == "__main__":
	main()

