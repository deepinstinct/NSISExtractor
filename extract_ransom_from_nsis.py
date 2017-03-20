from os import listdir, remove, makedirs
from os.path import isfile, join, exists
import sys
import subprocess

LOCATION_7ZIP = r"c:\Program Files (x86)\7-Zip\7z.exe"
EXTRACTOR_LOCATION = r"C:\Users\Generic\Desktop\DecryptNSISPayload.exe"

def main():
	if 3 != len(sys.argv):
		print "Usage: " + sys.argv[0] + " NSISFile OutputPath"
		return
		
	archive_name = sys.argv[1]
	out_path = sys.argv[2]
	
	if exists(out_path):
		makedirs(out_path)
		
	# extract the content of NSIS to out_path
	subprocess.call(LOCATION_7ZIP + r' e -y -o' + '\"' + out_path + '\"' + " " + '\"' + archive_name + '\"')
	
	# Execute the extractor for all files and check if the output file were created
	files_list = [f for f in listdir(out_path) if isfile(join(out_path, f))]
	for file_name in files_list:
		subprocess.call(EXTRACTOR_LOCATION + " \"" + join(out_path, file_name) + "\" \"" + file_name + "\" \"" + join(out_path, "out.out") + "\"")
		if exists(join(out_path, "out.out")):
			break

	for file_name in files_list:
		remove(join(out_path, file_name))

if __name__ == "__main__":
	main()