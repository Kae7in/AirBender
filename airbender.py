import sys, os, subprocess, shutil
import argparse
from argparse import ArgumentParser
import tempfile
import atexit


###############################################################
# Specify directory to store temporary intercepted packets
# Default: Creates folder in current directory
packetPath = ""

# Specify path to custom dictionary for cracking
# Default: Uses included dictionary 
dictionaryPath = ""

# Specify file to store passwords in
# Default: Creates file "passwords"
passwordsPath = ""
###############################################################


def main():
	try:
		environmentSetup()
		airdumpSetup()
		# Next steps here
	finally:
		# this ensures that clean up occurs even on error
		cleanUp()


def is_valid_path(parser, arg):
    if not os.path.exists(arg):
        parser.error("The path %s does not exist!" % arg)


def bash_command(cmd):
	return subprocess.Popen(['/bin/bash', '-c', cmd]).communicate()


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
	ldir = tempfile.mkdtemp()
	atexit.register(lambda dir=ldir: shutil.rmtree(ldir))

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
	user did NOT specify that particular attribute. '''
	# use default path for packets	
	if not packetPath and not os.path.exists(os.getcwd() + "/packets"):
		os.makedirs(os.getcwd() + "/packets")
		packetPath = os.getcwd() + "/packets"
	# use included dictionary
	if not dictionaryPath and os.path.isfile(os.getcwd() + "/dictionary.txt"):
		dictionaryPath = os.getcwd() + "/dictionary.txt"
	# use default passwords file
	if not passwordsPath and os.path.isfile(os.getcwd() + "/passwords.txt"):
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


def airdumpSetup():
	(stdout, stderr) = bash_command("airmon-ng check kill")
	# TODO: Handle output
	(stdout, stderr) = bash_command("/etc/init.d/avahi-daemon stop")
	# TODO: Handle output
	(stdout, stderr) = bash_command("ifconfig eth0 down")
	# TODO: Handle output
	(stdout, stderr) = bash_command("airmon-ng start wlan1")
	# TODO: Handle output


def cleanUp():
	# TODO: remove temporary directories and files
	if os.path.exists(os.getcwd() + "/packets"):
		shutil.rmtree(os.getcwd() + "/packets")


if __name__ == "__main__":
	main()

