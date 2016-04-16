import sys, os, subprocess, shutil


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


def bash_command(cmd):
	return subprocess.Popen(['/bin/bash', '-c', cmd]).communicate()


def environmentSetup():
	global packetPath
	global dictionaryPath
	global passwordsPath

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

