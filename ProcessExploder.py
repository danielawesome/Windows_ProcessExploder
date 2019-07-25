################################################
##	
##  Windows Process Exploder     
##
##  Written by: Daniel Cosio
##  Version: 1.0
##  Outputs processes, file path, time and hash
################################################

import wmi, os, sys, subprocess, time
from string import maketrans

wmi = wmi.WMI()	

def kaboom():
	global hash
	global processExploder

	print "****** Process Exploder ******\n"
	print "|-- Start Time --|-- PID --|-- Process Name --|-- Domain\User --|-- Path & Run Command --|-- Handle & Thread Count --|-- SHA1 Hash --|\n"
	
	for  processExploder in wmi.Win32_Process():
		path = processExploder.ExecutablePath # Get the process path. This is used to create a SHA1 hash.
		date = processExploder.CreationDate # Get the timestamp for when a process is created. 
		date = str(date)
		date = date[:14]
		
		try: 
			z = processExploder.GetOwner()  # Get the owner info for a process
            z = "{0}\{1}" .format(z[0], z[2]) # Display only domain and username
			
		except Exception:
			z = " Unknown "  # If a process is closed while running this script, the GetOwner method will throw an exception.
		
		if path == None :
			h = "00/00/0000  00:00 NA"  # Some Kernel level processes will return a path and timestamp as 'None"
			hash =  "Could not create a hash. " # Can't find path so no hash value
        
		else:
			t = time.strptime(date, "%Y%m%d%H%M%S") # Format the time to M$ 12-hour
			h = time.strftime('%m/%d/%Y  %I:%M %p', t)
            
			try:
				proc = subprocess.Popen(['python','hashy.py', '-hash', 'sha1', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				proc.wait()
				hash = proc.stdout.read() # Create a hash of the executable
				if hash == "":
					hash = "Could not create a hash. "
				else: 	
					justHash = maketrans("\n\r", "  ") # Remove newlines to format results
					hash = hash.translate(justHash)				
				
			except IOError as e:
				pass
			

		print "{0} | {1} | {2} | {3} | {4} | {5}/{6} | SHA1: {7}|" .format( h, processExploder.ProcessID, processExploder.Name, z, processExploder.CommandLine, processExploder.HandleCount, processExploder.ThreadCount, hash)

		
		
