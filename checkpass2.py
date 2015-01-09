#!/usr/bin/python

from __future__ import print_function
import sys
import time
import argparse
import string
import bisect
from bisect import bisect_left

########################################################################################
#
# Checks to see if a password cracking program would crack a list of plaintext passwords
# and if so, how many guesses it takes to crack them
#
# Written by Matt Weir
# www.reusablesec.blogspot.com
# cweir@vt.edu
#
########################################################################################



########################################################################################
# Holds the cracking session values
########################################################################################
class crackingSession:
	def __init__(self):
		
		##Holds the plaintext passwords
		## The values of dict are (Password_String: [Number_of_Passwords, isCracked, Number_Of_Guesses_To_Crack])
		self.passwords = dict()

		##Total number of passwords, (includes duplicates
		self.numPasswords = 0

		##Total number of passwords cracked
		self.numCracked = 0

		##Total number of guesses so far
		self.numGuesses = 0

#########################################################################################
# Holds the command line values
#########################################################################################
class commandLineVars:
	def __init__(self):

		##Name of the file containing all the target passwords
		self.targetFile = ""

		##Name of the output file to save the results
        	self.outputFile = ""

		##Maximum number of guesses to allow. If '-1' then unlimited guesses are allowed
        	self.maxGuesses = -1

		##Used to "continue" a cracking session from a previous test. Aka it just increments the number of guesses recorded
		self.startCount = 0

		##Used to "continue" a cracking session from a previous test. Aka it just increments the number of cracked passwords recorded
                self.startCracked = 0

		##At the end of a session, save all uncracked passwords to the following file. Used to model multiple cracking sessions
		self.uncrackedFile = ''

####################################################
# Simply parses the command line
####################################################
def parseCommandLine(c_vars):
        parser = argparse.ArgumentParser(description='Used to test the effectiveness of a password cracking session against a known set of plaintext passwords')
	parser.add_argument('--target','-t', help='The set of passwords to use as a target',metavar='TARGET_SET',required=True)
        parser.add_argument('--output','-o', help='Filename to save the results to. Default is to output to stdout',metavar='OUTPUTFILE_NAME',required=False,default="")
	parser.add_argument('--maxGuesses','-m', help='If specified, limits the number of guesses to what is specified',metavar='MAX_GUESSES',required=False,default=-1)
	parser.add_argument('--startCount','-s', help='Used to continue a previous cracking session. Aka just starts with *count* number of guesses already',metavar='NUM_GUESSS',required=False,default=0)
	parser.add_argument('--startCracked','-c', help='Used to continue a previous cracking session. Aka just starts with *cracked* number of passwords already',metavar='NUM_CRACKED',required=False,default=0)
	parser.add_argument('--uncrackedFile','-u', help='Save all uncracked passwords at the end of the session to file',metavar='SAVEFILE',required=False,default="")
        args=vars(parser.parse_args())
        c_vars.targetFile = args['target']
	c_vars.outputFile = args['output']
	c_vars.maxGuesses = int(args['maxGuesses'])
	c_vars.startCount = int(args['startCount'])
	c_vars.startCracked = int(args['startCracked'])
	c_vars.uncrackedFile = args['uncrackedFile']


        return 0


#################################################################
# Reads in the target file
#################################################################
def readTargetFile(targetFile,cs):

	try:	
		file = open(targetFile, 'r')
	except:
		print('Error opening the target file:',targetFile, file=sys.stderr)
		return -1

	for password in file:
		## Do not read in blank lines
		if len(password)!=1:
			cs.numPasswords = cs.numPasswords + 1

			## If the password has already been read in, (aka multiple people used the same password), increment the count
			if password in cs.passwords:
				cs.passwords[password][0] = cs.passwords[password][0] + 1

			## Otherwise insert the password into the list if it is the first time it has been seen
			else:
				## The values of cs.passwords are (Password_String: [Number_of_Passwords, isCracked, Number_Of_Guesses_To_Crack])	
				cs.passwords[password] = [1,False,-1]

	file.close()
	return 0


##################################################################
# Checks the input and sees if it would crack passwords in the
# target set
##################################################################
def testCrackingSession(c_vars,cs):

	## I only want to print out 1000 items + the last count to make graphing easier
	stepSize = cs.numPasswords * 0.001
	stepSize = int(stepSize)
	if stepSize == 0:
		stepSize = 1
	curStepLimit=stepSize

	cs.numGuesses=c_vars.startCount
	cs.numCracked=c_vars.startCracked
	cs.numPasswords=cs.numPasswords + c_vars.startCracked
	print(cs.numGuesses,"\t",cs.numCracked)

	for guess in sys.stdin:
		cs.numGuesses = cs.numGuesses + 1
		## If it is a match
		if guess in cs.passwords and cs.passwords[guess][1] == False:
			cs.passwords[guess][1] = True
			cs.passwords[guess][2] = cs.numGuesses
			cs.numCracked = cs.numCracked + cs.passwords[guess][0]
			if cs.numCracked >= curStepLimit:
				print(cs.numGuesses, "\t", cs.numCracked, "\t")
				curStepLimit = stepSize + curStepLimit
			
			#If all passwords have been cracked, exit
			if cs.numCracked >= cs.numPasswords:
				return 0

		if (c_vars.maxGuesses != -1) and (cs.numGuesses >= c_vars.maxGuesses):
			return 0	

	return 0


##################################################################
# Main function, not that exciting
##################################################################
def main():
	c_vars = commandLineVars()
	cs = crackingSession()

	parseCommandLine(c_vars)

	print('Parsing the target file', file=sys.stderr)
	if readTargetFile(c_vars.targetFile,cs) != 0:
		print('Exiting', file=sys.stderr)
		exit()
	print('Done parsing target file. Passwords to crack =', cs.numPasswords, file=sys.stderr)

	print('Processing input',file=sys.stderr)
	testCrackingSession(c_vars,cs)
	print(cs.numGuesses, "\t", cs.numCracked)

	#Final cleanup
	if (c_vars.uncrackedFile != ''):
		try:
			file = open(c_vars.uncrackedFile, 'w')
		except:
			print('Error opening the target file:',targetFile, file=sys.stderr)
			return -1
		for password in cs.passwords:
			result = cs.passwords.get(password)
			if result[1] == False:
				for i in xrange(0,result[0]):
					file.write(password)
	

if __name__ == "__main__":
        main()

