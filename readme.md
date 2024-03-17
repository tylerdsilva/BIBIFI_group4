# CMPT785 - Build it Break it Fix it project

## Group Member
- Hugh Song
- Yanfei Wang (apphiaWang)
- Anmol Malhotra
- Rithik Agarwal
- Aastha Jha

## User Manual
TBD

## Requirements
### User Features
* `cd <directory>`   -  The user provides the directory to move to. It accepts `.` and `..` as current and parent directories respectively and support changing multiple directories at once (cd ../../dir1/dir2). cd / takes you to the current user’s root directory. If a directory doesn't exist, the user stays in the current directory.
* `pwd`   - Print the current directory. Each user has /personal and /shared base directories. 
* `ls`   -  Lists the files and directories in the current directory separated by a new line. Shows the directories `.` and `..` as well. To differentiate between a file and a directory, the output look as follows:
  * d -> .
  * d -> ..
  * d -> directory1
  * f -> file1
* `cat <filename>`   - Reads the actual (decrypted) contents of the file. If the file doesn't exist, it prints "<filename> doesn't exist"
* `share <filename> <username>`   -  Shares the file with the target user which appears under the `/shared` directory of the target user. The files are shared only with read permission. The shared directory is read-only. If the file doesn't exist, it prints "File <filename> doesn't exist". If the user doesn't exist, it prints "User <username> doesn't exist".
* `mkdir <directory_name>`   - Creates a new directory. If a directory with this name exists, it prints "Directory already exists"
* `mkfile <filename> <contents>`   - Creates a new file with the contents. The contents are printable ascii characters. If a file with <filename> exists, it replaces the contents. If the file was previously shared, the target user will see the new contents of the file.
* `exit`   - Terminates the program.

### Admin Features
* Admin has access to read the entire file system with all user features
* `adduser <username>`  - This command creates a keyfile called username_keyfile on the host which is used by the user to access the filesystem. If a user with this name already exists, it prints "User <username> already exists"


## System Design
### Start System
Compile the filesystem binary
```sh
g++ -std=c++17 main.cpp -o fileserver -lcrypto
```

Enter the file system
```sh
./filesystem <your_admin_name>
```
(First time execution: this will create folders and keypairs)   
(Normal execution: will do the login verification based on the provide username)

Press ctrl + C or type `exit` command to exit the file system. 

## Auth part
public key location: ./public_keys/adminName_public.pem   
private key location: ./filesystem/.private_keys/adminName_private.pem


Works are tracked at [Trello](https://trello.com/b/GKl7tSmP/cmpt785-bibifi).
