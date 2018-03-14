#!/bin/bash


import virustotal
import sys
import os.path
import re


print """                           
                        *
                    _:*///:_                     
                _+*///////////+_                
    ____----*////////////////////**----____    
   *//////////////////////////////////********    
   */////////////////       ////**************    
   *////////////////          /***************    
   *///////////////   /////   ****************    
   *//////////////   /////**   ***************    
   *//////////////   ////***   ***************    
   *//////////////   ///****   ***************    
   *////////////                 *************    
   *////////////    Saleh Bin    *************    
   *////////////     Muhaysin    *************    
   *////////////                 *************    
    *////////********************************     
     */////  github.com/salehmuhaysin  *****      
      *///*********************************             
=========================================================="""



fname = sys.argv[1]
fscanned = fname + ".scanned"


# get all hashes from the input file, and remove dulicated hashes
# return a list of unqie hashes
def GetHashes(fname):
	f = open(fname , 'r')
	hashes = f.readlines()
	f.close()

	h = list(set(hashes)) # remove duplications
	res = [] 
	for i in h:
		res.append(i.strip('\n'))
	return res

# check the hashes against 'fscanned' file and remove already scanned hashes
def RemoveScanned(hashes , scanned):

	if os.path.exists(scanned):
		fs = open(scanned , 'r')
		sc_h = fs.readlines()
		fs.close()
	
		for s in sc_h:
			h = s.split('\t')[0]
			print s,
			hashes.remove(h)
	
	return hashes


# scan the hashes in VirusTotal, and print the result and write it into the 'fscanned' file 
def ScanHashes(hashes , scanned):
	v = virustotal.VirusTotal("<VirusTotal API KEY>")	# API Key

	for h in hashes:
		# check if given hash is md5, skip this if you sure all your input files are MD5 hashes
		validHash = re.finditer(r'(?=(\b[A-Fa-f0-9]{32}\b))', h)
	    	rvalidHash = [match.group(1) for match in validHash]
	    	if not rvalidHash: 
			print h + " Is Not a Valid MD5 Hash"
			continue
		
		# open the scanned file to append the result
		fscanned = open(scanned , 'a')
		pri = ""
		print h,
		report = v.get(h)	# check VirusTotal
		if not report is None:	
			try:		
				# if result found 
				pri = "\t\t " + str(report.positives) + "/" + str(report.total)	
				print pri
				
			except:
				# if there is not score given by VirusTotal
				pri = "\t\t Couldn't parse"		
				print pri

		else:
			# if there is not match
			pri = "\t\t NO DATA"	
			print pri


		fscanned.write(h + pri + '\n')	# write the result into the scanned hashes file
		fscanned.close()






hashes = GetHashes(fname)			# Get the hashes from input file
hashes = RemoveScanned(hashes , fscanned)	# remove scanned hashes 
ScanHashes(hashes , fscanned)			# scan the hashes in VirusTotal



