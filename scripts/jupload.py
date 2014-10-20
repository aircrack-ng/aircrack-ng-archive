#!/usr/bin/python

# Tested using Python 3.4.2
# Requires requests and path.py modeules
# Requirements 1: python -m pip install requests
# Requirements 2: python -m pip install path.py

# import modules used here -- sys is a very standard one
import sys
import os
import time
import requests
import path

def upload_file(file, upload_url):
	file_tmp = file.abspath()
	print("Uploading", file_tmp, "to", upload_url)
	try:
		r = requests.post(upload_url, files={'file': open(file_tmp, 'rb')})
		if(r.status_code == requests.codes.ok):
			try:
				os.remove(file_tmp)
				print("file", file_tmp, "uploaded and deleted.")
			except:
				print("unable to delete file", file_tmp,"ex:", sys.exc_info()[0])
	except:
		print("problem uploading:", file.name,"ex:",sys.exc_info()[0])
		time.sleep(30)

def clear_directory(dir_name, file_filter):
	try:
		from path import Path
		d = Path(dir_name)
		files = d.walkfiles(file_filter)
		for file in files:
			file_tmp = file.abspath()
			print("deleting file:", file_tmp)
			os.remove(file_tmp)
	except:
		print("problem clearing directory:", dir_name, "ex:", sys.exc_info()[0])

def check_directory(dir_name, file_filter, upload_url):
	try:
		from path import Path
		d = Path(dir_name)
		files = d.walkfiles(file_filter)
		try:
			for file in files:
				upload_file(file, upload_url)
		except:
			print("error in upload_file")
	except FileNotFoundError:
		return False
	except:
		print("problem checking directory:", dir_name,"ex:",sys.exc_info()[0])
		time.sleep(60 * 5)
	return True


# Gather our code in a main() function
def main():

	print("Starting jUpload...")
	print("  DIRECTORY =", sys.argv[1])
	print("  FILE FILTER =", sys.argv[2])
	print("  ULR =", sys.argv[3])
	should_run = True
	while should_run:
		print("Checking directory...")
		should_run = check_directory(sys.argv[1], sys.argv[2], sys.argv[3])
		print("Clearing directory...")
		clear_directory(sys.argv[1], "*.pcap")
		time.sleep(60 * 3)
	print("Stopping jUpload...")

# Standard boilerplate to call the main() function to begin
# the program.
if __name__ == '__main__':
    main()
