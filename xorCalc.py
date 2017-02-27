import hashlib
import hmac
import sys
import string
import getopt
import os
import binascii
import zlib

p_reset = "\x08"*8
VERSION = "v0.3"

# XORs a directory containing files using a Seed for HMAC-SHA1 (default: 00)
# Supports Algorithm: HMAC-SHA1, SHA1, SHA224, SHA256, SHA384, and SHA512, MD5 and CRC32
# Created for TattsRNG XORs, can be used for EGMs XORs or others.

class xorCalc:

    def __init__(self):
        filelist = list()
        self.seed = "00"
        self.setseed = False
        self.filedir = ''
        self.alg = "SHA1" # default to SHA1
        self.blocksize = 8192 # try 65536
        prettyoutput = False

        try:
            opts, args = getopt.getopt(sys.argv[1:], "s:d:a:b:hp",["dir=","seed=","alg=","blocksize=", "help","prettyoutput"])
            
            for opt, arg in opts:
                if opt in ("-h", "--help"):
                    print("xorCalc version: " + VERSION)
                    print("\nUsage: xorCalc.py --seed <seed> --directory <input dir>")
                    print("where: ")
                    print("\t--dir\t\t\tdirectory containing all files to be XORed")
                    print("\t--seed or -s\t\tSeed (default '00'), for HMAC hashes")
                    print("\t--alg or -a\t\tHMAC or non-HMAC: SHA1, SHA224, SHA256, SHA384, and SHA512; MD5 and CRC32")
                    print("\t-p\t\t\tformatted output (uppercase, space every 8 characters)")
                    print("\t--blocksize or -b\tBlockSize to read (default=8192), for large files: try: 65536")
                    print("DEFAULT is seed='00', and alg='SHA1'\n\n")
                    
                    sys.exit(0)
                elif opt in ("-d", "--directory"):
                    if os.path.isdir(arg):
                        filelist = os.listdir(arg)
                        self.filedir = arg
                elif opt in ("-s", "--seed"):
                    self.seed = arg
                    self.setseed = True
                elif opt in ("-p", "--prettyoutput"):
                    prettyoutput = True
                elif opt in ("-a", "--alg"):
                    self.alg = arg
                elif opt in ("-b", "--blocksize"):
                    self.blocksize = arg

            # Verify Seed is a number String format, and atleast 2 digits long 
            if (len(self.seed) < 2 or not self.checkhexchars(self.seed)):
                print("Error in Seed Input: Expected atleast two Hexadecimal characters as the Seed input" +
                                 ".\n\nCheck your Seed string again: " + self.seed)
                sys.exit(2)
            else:
                tmpStr = ''
                xorResult = self.XORfile(filelist)
                if (prettyoutput) :
                    tmpStr = str(xorResult).lstrip('0x')        
                    print("XOR result is: " + self.insert_spaces(tmpStr.upper(), 8))
                else:
                    print("XOR result is: " + xorResult)
                
                sys.exit(0)


        except getopt.GetoptError:
            print('try: xorCalc.py -h for more info or')
            print ('xorCalc.py --seed <seed> --file1 <input filename> --file2 <input filename>')
            sys.exit(2)

    # Inserts spaces on [text] for every [s_range]
    def insert_spaces(self, text, s_range):
        return " ".join(text[i:i+s_range] for i in range(0, len(text), s_range))
    
    def checkhexchars(self, text):
        return (all(c in string.hexdigits for c in text))    

    def XORfile(self, flist):
        oh = '0000000000000000000000000000000000000000'
        m = None
        if self.setseed:
            print("\nAlgorithm being used is: HMAC-" + self.alg.upper() + ", Seed: " + self.seed)
        else: 
            print("\nAlgorithm being used is: " + self.alg.upper() + ", Seed: " + self.seed)

        for file in flist: # Generate Hashes
            if self.alg.upper().startswith('SHA'):
                if self.setseed: 
                    # do hmac
                    localhash = self.dohash_sha_seed(os.path.join(self.filedir, file), int(self.blocksize))
                else:
                    # do standard
                    localhash = self.dohash_sha(os.path.join(self.filedir, file), int(self.blocksize))
                    
            elif self.alg.upper() == 'CRC32':
                localhash = self.dohash_crc32(os.path.join(self.filedir, file))
            elif self.alg.upper() == 'MD5':
                localhash = self.domd5(os.path.join(self.filedir, file), int(self.blocksize))
            elif self.alg.upper() == 'PSA32':
                localhash = self.dohash_PSA32(os.path.join(self.filedir, file), int(self.blocksize))
            else:
                print("Unknown hash: " + self.alg)
                sys.exit(2)
                
            oh = hex(int(oh,16) ^ int(str(localhash), 16)) #XOR operator
            print(str(localhash) + "\t" + str(file))

        return oh

    def domd5(self, file, blocksize=2**20):
        m = hashlib.md5()
        done = 0
        size = os.path.getsize(file)
        with open(file, "rb" ) as f:
            while True:
                buf = f.read(blocksize)
                done += blocksize
                sys.stdout.write("%7d"%(done*100/size) + "%" + p_reset)
                if not buf: break
                m.update(buf)
        return m.hexdigest()

    # input: file to be hashed using hmac-sha1
    # output: hexdigest of input file    
    def dohash_sha_seed(self, fname, chunksize=8192):

        # Determine Algorithm
        if self.alg.upper() == 'SHA1':
            dmod = hashlib.sha1
        elif self.alg.upper() == 'SHA224':
            dmod = hashlib.sha224
        elif self.alg.upper() == 'SHA256':
            dmod = hashlib.sha256
        elif self.alg.upper() == 'SHA384':
            dmod = hashlib.sha384
        elif self.alg.upper() == 'SHA512':
            dmod = hashlib.sha512
        else:
            print("Unknown Hash: " + self.alg.upper())
            sys.exit(2)

        key = bytes.fromhex(self.seed)
        m = hmac.new(key, digestmod = dmod) # change this if you want other hashing types for HMAC, e.g. hashlib.md5
        done = 0
        size = os.path.getsize(fname)
        # Read in chunksize blocks at a time
        with open(fname, 'rb') as f:
            while True:
                block = f.read(chunksize)
                done += chunksize
                sys.stdout.write("%7d"%(done*100/size) + "%" + p_reset)
                if not block: break
                m.update(block)      

        return m.hexdigest()

 # input: file to be hashed using sha1()
    # output: hexdigest of input file    
    def dohash_sha(self, fname, chunksize=8192): 
        #m = hashlib.sha1()
        done = 0
        size = os.path.getsize(fname)
        
        if self.alg.upper() == 'SHA1':
            m = hashlib.sha1()
        elif self.alg.upper() == 'SHA224':
            m = hashlib.sha224()
        elif self.alg.upper() == 'SHA256':
            m = hashlib.sha256()
        elif self.alg.upper() == 'SHA384':
            m = hashlib.sha384()
        elif self.alg.upper() == 'SHA512':
            m = hashlib.sha512()
        else:
            print("Unknown Hash: " + self.alg.upper())
            sys.exit(2)

        # Read in chunksize blocks at a time
        with open(fname, 'rb') as f:
            while True:
                block = f.read(chunksize)
                done += chunksize
                sys.stdout.write("%7d"%(done*100/size) + "%" + p_reset)
                if not block: break
                m.update(block)    

        return m.hexdigest()
    
    # input: file to be CRC32 
    def dohash_crc32(self, fname):
        prev = 0
        for eachLine in open(fname,"rb"):
            prev = zlib.crc32(eachLine, prev)

        return "%X" % ( prev & 0xFFFFFFFF)
    
    # Yeah. Need help for this.     
    def dohash_PSA32(self, fname, buff_size=1):
        print("WARNING!! PSA32 doesn't work yet")
        checksum = hex(00000000)
        crc = hex(int(self.seed, 32))
        
        file = open(fname, "rb")
        size = os.path.getsize(fname)
        done = 0
        
        while True:
            checksum += buff_size
            data = file.read(buff_size)
            done += buff_size
            sys.stdout.write("%7d"%(done*100/size) + "%" + p_reset)
            if not data: break
            crc = zlib.crc32(data, int(crc)) ^ checksum      

        return "%X" % ( crc & 0xFFFFFFFF)

def main():
    if (len(sys.argv) < 2):
        print('not enough parameters passed - try -h for more info')
        sys.exit(2)
    else: 
        app = xorCalc()

if __name__ == "__main__": main()
