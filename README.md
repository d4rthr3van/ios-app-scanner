# iOS App Scanner

iOS App Scanner is a simple command-line tool made with Python to help security researchers and developers identify 
potential security flaws in iOS applications.

## Installation

Use the requirements file included in the repo to install iOS App Scanner.

```bash
pip install -r requirements.txt
```

"lbmagic" library is required to run the tool. You can install the tool via pip or Homebrew

```bash
pip install python-magic-bin==0.4.14
```

```bash
brew install libmagic
```

## Usage
To run the tool, once installed the requirements, just execute the main.py file.

```bash
python3 main.py -h    # To display help
python3 main.py -i /path/to/ipa     # To analyse an application
```

## Limitations
For the moment, the tool will only work on MacOS systems, as it uses [otool](https://www.unix.com/man-page/osx/1/otool/)
to explore the binary.

## Functionalities
At the moment, the tool will perform the next checks:
+ Extract .ipa assets
+ Checks in the binary for:
  + PIE Flag: Position Independent Executable (PIE) flag makes the application to load at a random memory address 
  every-time it launches.
  + Stack Canaries: Canary values are placed on the stack to validate its integrity. 
  Everytime a function is called these values are checked.
  + ARC Flag: Automatic Reference Counting: keeps track of class instances on memory, and it decides when it is safe 
  to deallocate the class instances it monitors.
  + Encryption: Checking if the binary is encrypted.
  + Weak Hashing Functions (MD5 and SHA1): Checks if calls to the MD5 and SHA1 hashing functions are present on 
  the binary.
  + Weak PSRNG Functions: Checks if weak psrng function calls are present on the binary.
  + Usage of malloc: Checks if the unsafe malloc function is present on the binary.
+ Analyze .plist file for permissions