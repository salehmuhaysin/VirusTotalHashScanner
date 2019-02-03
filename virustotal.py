#!/bin/bash

import argparse

import sys
import os.path
import re
import requests

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




a_parser = argparse.ArgumentParser('Python script tool to check all the given files against VirusTotal')


requiredargs = a_parser.add_argument_group('required arguments')
requiredargs.add_argument('-i', dest='in_file', help='Input hashes file', required=True)

a_parser.add_argument('-o' , dest='out_file' , help='Output file for all the results, if contain previous results it will not check them')
a_parser.add_argument('-w' , dest='white_list' , help='White list database hashes')


args = a_parser.parse_args()
print args

fname = args.in_file
if args.out_file is None:
	foutput = fname + '.scanned'
else:
	foutput = args.out_file


whitelist = args.white_list



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

# check the hashes against 'whitelist' file and remove already scanned hashes
def RemoveScanned(hashes , whitelist , output):

	if os.path.exists(whitelist):
		fs = open(whitelist , 'r')
		sc_h = fs.readlines()
		fs.close()
		foutput = open(output , 'w')
		for s in sc_h:
			h = s.split('\t')[0]
			print s,
			
			if h in hashes:
				hashes.remove(h)

				foutput.write(s)	# write the result into the output hashes file
		
		foutput.close()
	
	return hashes


# scan the hashes in VirusTotal, and print the result and write it into the 'output' file 
def ScanHashes(hashes , output):
	
	params = {'apikey': '<public-key>'}
	headers = {
	  "Accept-Encoding": "gzip, deflate",
	  "User-Agent" : "gzip,  My Python requests library example client or username"
	  }

	for h in hashes:
		# check if given hash is md5, skip this if you sure all your input files are MD5 hashes
		validHash = re.finditer(r'(?=(\b[A-Fa-f0-9]{32}\b))', h)
	    	rvalidHash = [match.group(1) for match in validHash]
	    	if not rvalidHash: 
			print h + " Is Not a Valid MD5 Hash"
			continue
		
		# open the output file to append the result
		foutput = open(output , 'a')
		pri = ""
		print h,
		params['resource'] = h
		response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',  params=params, headers=headers)
		json_response = response.json()

		#report = v.get(h)	# check VirusTotal
		if not json_response is None:	
			try:		
				# if result found 
				pri =  "\t\t " + str(json_response['positives']) + " / " + str(json_response['total']) + "\t\t" + "Scan date: " + json_response['scan_date']

				print pri
			
			except:
				# if there is not score given by VirusTotal
				pri = "\t\t Couldn't parse"		
				print pri
		else:
			# if there is not match
			pri = "\t\t NO DATA"	
			print pri

		foutput.write(h + pri + '\n')	# write the result into the output hashes file
		foutput.close()






hashes = GetHashes(fname)			# Get the hashes from input file
if whitelist is not None:
	hashes = RemoveScanned(hashes , whitelist , foutput)	# remove scanned hashes 
ScanHashes(hashes , foutput)			# scan the hashes in VirusTotal

