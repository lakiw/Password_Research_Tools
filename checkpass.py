#!/usr/bin/env python3

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


##--Including this to print error message if python < 3.0 is used
from __future__ import print_function
import sys
import argparse

##--Custom imports
from checkpass.file_io import detect_file_encoding
from checkpass.file_io import read_input_passwords
from checkpass.file_io import write_uncracked_to_disk
from checkpass.ret_types import RetType

###--Check for python3 and error out if not--##
if sys.version_info[0] < 3:
    print("This program requires Python 3.x", file=sys.stderr)
    sys.exit(1)


########################################################################################
# Holds the cracking session values
########################################################################################
class CrackingSession:
    def __init__(self):
        
        ##Holds the plaintext passwords
        ## The values of dict are (Password_String: [Number_of_Passwords, isCracked, Number_Of_Guesses_To_Crack])
        self.passwords = dict()

        ##Total number of passwords, (includes duplicates
        self.num_passwords = 0

        ##Total number of passwords cracked
        self.num_cracked = 0

        ##Total number of guesses so far
        self.num_guesses = 0


####################################################
# Parses the command line
####################################################
def parse_command_line(command_line_results = {}):
 
    parser = argparse.ArgumentParser(description='Used to test the effectiveness of a password cracking session against a known set of plaintext passwords')

    #######################################################
    # Declare all the command line variables
    #######################################################

    ##Name of the file containing all the target passwords
    parser.add_argument('--target','-t', help='The set of passwords to use as a target',metavar='TARGET_SET',required=True)

    ##Name of the output file to save the results
    parser.add_argument('--output','-o', help='Filename to save the results to. Default is to output to stdout',metavar='OUTPUTFILE_NAME',required=False,default=None)

    ##Maximum number of guesses to allow. If '-1' then unlimited guesses are allowed
    parser.add_argument('--max_guesses','-m', help='If specified, limits the number of guesses to what is specified',metavar='MAX_GUESSES',type=int,required=False,default=None)
    
    ##Used to "continue" a cracking session from a previous test. Aka it just increments the number of guesses recorded
    parser.add_argument('--start_count','-s', help='Used to continue a previous cracking session. Aka just starts with *count* number of guesses already',metavar='NUM_GUESSS',type=int,required=False,default=0)
    
    ##Used to "continue" a cracking session from a previous test. Aka it just increments the number of cracked passwords recorded
    parser.add_argument('--start_cracked','-c', help='Used to continue a previous cracking session. Aka just starts with *cracked* number of passwords already',metavar='NUM_CRACKED',type=int,required=False,default=0)
    
    ##At the end of a session, save all uncracked passwords to the following file. Used to model multiple cracking sessions
    parser.add_argument('--uncracked_file','-u', help='Save all uncracked passwords at the end of the session to file',metavar='SAVEFILE',required=False,default=None)
    
    ##Allow the user to manually set the encoding type of the training file
    parser.add_argument('--encoding','-e', help='Encoding format of th training file', metavar='ENCODING', required=False, default=None)
    
    ##Prints debugging info
    parser.add_argument('--verbose','-v', help='Prints debugging messages', required=False, action="store_true")

    try:
        for key, value in vars(parser.parse_args()).items():
            command_line_results[key] = value

    except Exception as error:
        print("Error parsing command line: " + str(error), file=sys.stderr)
        return RetType.COMMAND_LINE_ERROR

    return RetType.STATUS_OK


##################################################################
# Checks the input and sees if it would crack passwords in the
# target set
##################################################################
def test_cracking_session(cs, encoding = "UTF-8", start_count = 0, start_cracked = 0, max_guesses = None, output = None, verbose = False):

    ##--Initialize the session--##
    cs.num_guesses = start_count
    cs.num_cracked = start_cracked
    cs.num_passwords = cs.num_passwords + start_cracked

    if output != None:
        try:
            output_file = open(output, 'w')
        except Exception as error:
            print("Error opening file. Error message: " + str(error), file=sys.stderr)
            return RetType.FILE_IO_ERROR
    else:
        output_file = sys.stdout

    ## I only want to print out 1000 items + the last count to make graphing easier
    step_size = cs.num_passwords * 0.001
    step_size = int(step_size)
    if step_size == 0:
        step_size = 1
    cur_step_limit = step_size

    ##--Number of errors occured while parsing input guesses
    num_input_errors = 0

    ##--Print out the inital stats of the crackign session
    print(cs.num_guesses,"\t",cs.num_cracked, file=output_file)

    while True:
        ##--Doing it this way so inputting weird encoding won't crash the program
        try:
            guess = sys.stdin.buffer.readline()
        except Exception as error:
            print ("halting due to :" + str(error), file=sys.stderr)

        cs.num_guesses = cs.num_guesses + 1

        ##--I'm assuming the  
        try:
            guess = guess.decode(encoding).rstrip()

        ##--Handle errors parsing input guesses
        except:
            num_input_errors = num_input_errors + 1
            if verbose:
                print("error decoding input guess. Total number of errors = " + str(num_input_errors), file=sys.stderr)
            else:
                if num_input_errors == 10000:
                    print("***Warning***", file=sys.stderr)
                    print("10,000 errors have occured while processing the input", file=sys.stderr)
                    print("Your results may be unreliable")
            continue

        ## If it is a match
        if guess in cs.passwords and cs.passwords[guess][1] == False:
            cs.passwords[guess][1] = True
            cs.passwords[guess][2] = cs.num_guesses
            cs.num_cracked = cs.num_cracked + cs.passwords[guess][0]
            if cs.num_cracked >= cur_step_limit:
                print(cs.num_guesses, "\t", cs.num_cracked, "\t", file=output_file)
                cur_step_limit = step_size + cur_step_limit
            
            #If all passwords have been cracked, exit
            if cs.num_cracked >= cs.num_passwords:
                break

        ##--If we have made all the maximum number of guesses
        if (max_guesses != None) and (cs.num_guesses >= max_guesses):
            break  

    ##--Do final cleanup and printout for this cracking session
    print(cs.num_guesses, "\t", cs.num_cracked, file=output_file)
    if output != None:
        output_file.close()

    return RetType.STATUS_OK


##################################################################
# Main function, not that exciting
##################################################################
def main():
    command_line_results = {}
    cs = CrackingSession()

    if parse_command_line(command_line_results) != RetType.STATUS_OK:
        print("Exiting", file=sys.stderr)
        return

    ##--Detect the file encoding of th training set
    if command_line_results['encoding'] == None:
        possible_encodings = []
        print('Identifying character encoding of target file', file=sys.stderr)
        if detect_file_encoding(command_line_results['target'], possible_encodings) != RetType.STATUS_OK:
            print("Error detecting file encoding, exiting", file=sys.stderr)
            return

    ##--Use the user specified encoding
    else:
        possible_encodings = [command_line_results['encoding']]

    ##--Now read in the training set
    print('Parsing the target file', file=sys.stderr)
    if read_input_passwords(command_line_results['target'], cs, file_encoding = possible_encodings[0]) != RetType.STATUS_OK:
        print('Error reading in target file. Exiting', file=sys.stderr)
        return

    print('Done parsing target file. Passwords to crack =', cs.num_passwords, file=sys.stderr)
    print('Processing input',file=sys.stderr)

    test_cracking_session(cs, encoding = possible_encodings[0], start_count = command_line_results['start_count'], 
        start_cracked = command_line_results['start_cracked'], max_guesses = command_line_results['max_guesses'], 
        output = command_line_results['output'], verbose = command_line_results['verbose'])

    #Print to uncracked file if that was specified
    if (command_line_results['uncracked_file'] != None):
        write_uncracked_to_disk(cs, command_line_results['uncracked_file'], file_encoding = possible_encodings[0])


if __name__ == "__main__":
    main()