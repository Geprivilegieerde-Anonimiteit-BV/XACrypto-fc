A multi-purpose Cryptography library in Java. Working on it day by day, slowly. Someday this will be complete, today is not that day.
To be clear, this is **NOT** mean't to be a replacement/alternative to BouncyCastle. Instead, it is meant to include what BouncyCastle does not have.

### Current Objective: ZekerRijndael (custom from-scratch AES-128 block cipher)
### Note: i'm creating ZekerRijndael as it can be used for creating the following encryption ciphers: AES-CTR; AES-OFB; AES-CFB. Block modes include AES-CBC; AES-ECB. And of course AES-GCM + ASE-CCM

## View the "zekerRijndael" branch to see inprogress work.

Use `setopt interactivecomments` (zsh only) to allow using `#` for comments if you see errors like `zsh: command not found: #`

Ensure Java + javac are installed, on MacOS it can be installed with Homebrew by running `brew install openjdk`

To compile on MacOS 26 (may work on other OS, idk):

1. git clone https://github.com/Geprivilegieerde-Anonimiteit-BV/XACrypto.git # download the git repository
2. mkdir -p out # create output directory
3. javac -d out $(find src -name "*.java") # converts .java into .class bytecode
4. jar cfe XACrypto.jar de.caydenno1.xacrypto.XACrypto -C out . # package the .class files into a .jar
5. (optional)- jar tf XACrypto.jar # view the contents of the jarfile

To compile on Windows 10 (requires java+javac to already be installed):

1. git clone https://github.com/Geprivilegieerde-Anonimiteit-BV/XACrypto.git && REM download the git repository
2. mkdir out && REM create output directory
3. dir /s /b src\*.java > sources.txt && REM create sources
4. javac -d out @sources.txt && REM form sources into java bytecode
5. jar cfe XACrypto.jar de.caydenno1.xacrypto.XACrypto -C out . && REM form java bytecode into jar
6. (optional)- jar tf XACrypto.jar && view jarfile contents

XACrypto.jar is now in the project root (if u did everything correctly).
