import ctypes
from ctypes import c_char_p
import sys
import os

# .so path
sopath = os.path.join(os.getcwd(),"HMAC_SHA3_256.so")

#load the shared library
lib = ctypes.CDLL(sopath,winmode=ctypes.DEFAULT_MODE)

# Set up the prototype of the function
# All of then are strings (char*)
HMAC_SHA3_256 = lib._Z13HMAC_SHA3_256PKcS0_S0_ 
HMAC_SHA3_256.argtypes = [c_char_p,c_char_p,c_char_p]
HMAC_SHA3_256.restype = None  

GenerateAndSaveKey = lib._Z18GenerateAndSaveKeyPKc 
GenerateAndSaveKey.argtypes = [c_char_p]
GenerateAndSaveKey.restype = None  

# Wrapped functions
def call_HMAC (keyFIle,input_filename,output_filename):
    # convert python strings to bytes, as ctypes works with bytes
    keyFIle = keyFIle.encode('utf-8')
    input_filename = input_filename.encode('utf-8')
    output_filename = output_filename.encode('utf-8')

    # call the c function
    HMAC_SHA3_256(keyFIle,input_filename,output_filename)
    print("HMAC-SHA3-256 calculation completed and written to", output_filename.decode('utf-8'))

def call_GenKey (keyFIle):
    # convert python strings to bytes, as ctypes works with bytes
    keyFIle = keyFIle.encode('utf-8')
    # call the c function
    GenerateAndSaveKey(keyFIle)
    print("Random key generated and saved to", keyFIle.decode('utf-8'))

if len(sys.argv) < 2:
    print("Usage: path/python.exe "+ sys.argv[0]+" HMAC_SHA3_256 <KeyFile> <input_filename> <output_filename>")
    print("Usage: path/python.exe "+ sys.argv[0]+" GenerateAndSaveKey <KeyFile>")
    sys.exit(1)

mode = sys.argv[1]
if mode == "HMAC_SHA3_256":
    if len(sys.argv) != 5:
        print("Usage: "+ sys.argv[0] +" "+sys.argv[1] +" <KeyFile> <input_filename> <output_filename>" )
        sys.exit(1)
    keyPath = sys.argv[2]
    inputPath = sys.argv[3]
    signaturePath = sys.argv[4]
    call_HMAC(keyPath,inputPath,signaturePath)
    sys.exit(0)
elif mode == "GenerateAndSaveKey":
    if len(sys.argv) != 3:
        print("Usage: "+ sys.argv[0] +" "+sys.argv[1] +" <KeyFile>" )
        sys.exit(1)
    keyPath = sys.argv[2]
    call_GenKey(keyPath)
    sys.exit(0)
else:
    print("Invalid option:")
    print("Usage: path/python.exe "+ sys.argv[0]+" HMAC_SHA3_256 <KeyFile> <input_filename> <output_filename>")
    print("Usage: path/python.exe "+ sys.argv[0]+" GenerateAndSaveKey <KeyFile>")
    sys.exit(1)