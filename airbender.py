import sys, os, subprocess, shutil
import argparse
from argparse import ArgumentParser
import tempfile
import atexit
import pandas
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
###############################################################


def main():
	try:
		environmentSetup()
		airdump()
		# Next steps here
	finally:
		# this ensures that clean up occurs even on error
		cleanUp()


def is_valid_path(parser, arg):
    if not os.path.exists(arg):
        parser.error("The path %s does not exist!" % arg)


def bash_command(cmd):
	(stdout, stderr) = subprocess.Popen(['/bin/bash', '-c', cmd], stdout=subprocess.PIPE, 
                           stderr=subprocess.PIPE).communicate()
	return stdout.decode("utf-8"), stderr.decode("utf-8")


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


def airdump():
	''' airdump setup '''
	print("Killing potential interfering processes...")
	(stdout, stderr) = bash_command("airmon-ng check kill")
	print(stdout.strip()) # TODO: strip whitespace out of here
	# TODO: Handle error output

	print("Stopping avahi-daemon...")
	(stdout, stderr) = bash_command("/etc/init.d/avahi-daemon stop")
	print(stdout)
	# TODO: Handle error output

	# TODO: Check for eth0 interface
	# Use 'ifconfig'

	print("Taking your eth0 down...")
	(stdout, stderr) = bash_command("ifconfig eth0 down")
	print(stdout)
	# TODO: Handle error output

	# TODO: List available network interfaces that can switch to monitor mode,
	# else elicit message stating that user has an incompatible network card.
	# Maybe use 'iw list'

	# TODO: Must figure out which wlan[number] to use
	print("Listing interface types...")
	(stdout, stderr) = bash_command("airmon-ng")
	print(stdout)
	interfaceName = input("Please type which interface (listed above) you would like to use: ")

	print("Starting airmon-ng...")
	(stdout, stderr) = bash_command("airmon-ng start " + interfaceName)
	print(stdout)
	# TODO: Handle error output

	# Allow user to select an AP (access point) by MAC address
	print("Listing routers close to user's location...")
	if "mon" not in interfaceName: # TODO: hacky
		interfaceName = interfaceName + "mon"
	if os.path.isfile(os.getcwd() + "/dump-01.csv"):
		os.remove(os.getcwd() + "/dump-01.csv")
	process = subprocess.Popen(['/bin/bash', '-c', "airodump-ng " + interfaceName + " -w dump --output-format csv"], stdout=subprocess.PIPE, 
                           stderr=subprocess.PIPE)
	# print(process.stdout.decode("utf-8"))
	# for line in iter(process.stdout.readline, ''):
		# sys.stdout.write(line)
	# stdout = process.stdout.decode("utf-8")
	# stderr = process.stderr.decode("utf-8")
	# Wait a bit then kill process? Might have to localize bash_command to have access to the process variable to kill.
	# colnames = ['BSSID', 'ESSID']
	# accessPoints = pandas.read_csv('dump-01.csv', names=colnames)
	# bssids = accessPoints.BSSID.tolist()
	# essids = accessPoints.ESSID.tolist()
	# print(bssids)
	# print("\n\n" + essids)

	# airodump-ng -c 6 --bssid 10:05:B1:C5:39:30 -w dump wlan0mon --output-format csv


def cleanUp():
	# TODO: remove temporary directories and files
	if os.path.exists(os.getcwd() + "/packets"):
		shutil.rmtree(os.getcwd() + "/packets")


if __name__ == "__main__":
	main()

