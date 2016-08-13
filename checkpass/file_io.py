#!/usr/bin/env python3

# Used for autodetecting file encoding of the training password set
# Requires the python package chardet to be installed
# pip install chardet
# You can also get it from https://github.com/chardet/chardet
from chardet.universaldetector import UniversalDetector

import sys
import os
import errno
import codecs

##--Custom imports
from checkpass.ret_types import RetType

#################################################################################################
# Used for autodetecting file encoding of the training password set
# Requires the python package chardet to be installed
# pip install chardet
# You can also get it from https://github.com/chardet/chardet
# I'm keeping the declarations for the chardet package local to this file so people can run this
# tool without installing it if they don't want to use this feature
##################################################################################################
def detect_file_encoding(training_file, file_encoding, max_passwords = 10000):
    print()
    print("Attempting to autodetect file encoding of the training passwords", file=sys.stderr)
    print("-----------------------------------------------------------------", file=sys.stderr)
    detector = UniversalDetector()
    try:
        cur_count = 0
        with open(training_file, 'rb') as file:
            for line in file.readlines():
                detector.feed(line)
                if detector.done: 
                    break
                cur_count = cur_count + 1
                if cur_count >= max_passwords:
                    break
            detector.close()
    except IOError as error:
        print ("Error opening file " + training_file, file=sys.stderr)
        print ("Error is " + str(error), file=sys.stderr)
        return RetType.FILE_IO_ERROR
        
    try:
        file_encoding.append(detector.result['encoding'])
        print("File Encoding Detected: " + str(detector.result['encoding']), file=sys.stderr)
        print("Confidence for file encoding: " + str(detector.result['confidence']), file=sys.stderr)
        print("If you think another file encoding might have been used please manually specify the file encoding and run the training program again", file=sys.stderr)
        print()
    except KeyError as error:
        print("Error encountered with file encoding autodetection", file=sys.stderr)
        print("Error : " + str(error), file=sys.stderr)
        return RetType.ENCODING_ERROR

    return RetType.STATUS_OK


#########################################################################################
# Reads in all of the passwords and returns the raw passwords, (minus any POT formatting
# to master_password_list
# Format of the raw passwords is (password,"DATA" or "COMMENT")
# I wanted to pass my comments through to the main program to make displaying results of
# unit tests easier
#########################################################################################
def read_input_passwords(training_file, cs, file_encoding = 'utf-8'):
    ##--keep track of the return value. If there are any Commnents return RetType.DEBUG vs RetType.STATUS_OK
    ret_value = RetType.STATUS_OK
    ##-- First try to open the file--##
    try:
        with codecs.open(training_file, 'r', encoding=file_encoding, errors= 'surrogateescape') as file:
            
            num_encoding_errors = 0  ##The number of encoding errors encountered when parsing the input file
            
            # Read though all the passwords
            for password in file:
                ##--Note, there is a large potential for encoding errors to slip in
                ##--   I don't want to silently ignore these errors, but instead warn the user they are
                ##--   occuring so they can look at what file encoding they are using again
                try:
                    password.encode(file_encoding)
                except UnicodeEncodeError as e:
                    if e.reason == 'surrogates not allowed':
                        num_encoding_errors = num_encoding_errors + 1
                    else:
                        print("Hmm, there was a weird problem reading in a line from the training file", file=sys.stderr)
                        print()
                    continue
      
                ##--Now save the password
                cs.num_passwords = cs.num_passwords + 1
                clean_password = password.rstrip()
                ## If the password has already been read in, (aka multiple people used the same password), increment the count
                if clean_password  in cs.passwords:
                    cs.passwords[clean_password][0] = cs.passwords[clean_password][0] + 1
                ## Otherwise insert the password into the list if it is the first time it has been seen
                else:
                    ## The values of cs.passwords are (Password_String: [Number_of_Passwords, isCracked, Number_Of_Guesses_To_Crack])   
                    cs.passwords[clean_password] = [1,False,-1]

            if num_encoding_errors != 0:
                print()
                print("WARNING: One or more passwords in the training set did not decode properly", file=sys.stderr)
                print("         Number of encoding errors encountered: " + str(num_encoding_errors), file=sys.stderr)
                print("         Ignoring passwords that contained encoding errors so it does not skew the results", file=sys.stderr)
                print("         If you see a lot of these errors then you may want to re-run the training", file=sys.stderr)
                print("         with a different file encoding")
                    
    except IOError as error:
        print (error, file=sys.stderr)
        print ("Error opening file " + training_file, file=sys.stderr)
        return RetType.FILE_IO_ERROR
    
    return ret_value


#######################################################################################
# Writes uncracked passwords from the target set to disk
#######################################################################################
def write_uncracked_to_disk(cs, uncracked_file, file_encoding = "UTF-8"):
    try:
        with codecs.open(uncracked_file, 'w', encoding=file_encoding) as file:
            for password in cs.passwords:
                result = cs.passwords.get(password)
                if result[1] == False:
                    for i in range(0,result[0]):
                        file.write(password + "\n")

    except Exception as error:
        print('Error opening the uncracked file. Error: ', str(error), file=sys.stderr)
        return