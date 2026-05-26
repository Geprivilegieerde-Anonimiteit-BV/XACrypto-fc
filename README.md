A multi-purpose Cryptography library in Java. Working on it day by day, slowly. Someday this will become used, today is not that day.


Use `setopt interactivecomments` (zsh only) to disable errors like `zsh: command not found: #`

Ensure Java + javac are installed, on MacOS it can be installed with Homebrew by running `brew install openjdk`

To compile on MacOS 26 (may work on other OS, idk):

1. git clone https://github.com/Geprivilegieerde-Anonimiteit-BV/XACrypto.git # download the git repository
2. mkdir -p out # create output directory
3. javac -d out $(find src -name "*.java") # converts .java into .class bytecode
4. jar cfe XACrypto.jar de.caydenno1.xacrypto.XACrypto -C out . # package the .class files into a .jar
5. (optional)- jar tf XACrypto.jar # view the contents of the jarfile

XACrypto.jar is now in the project root (if u did everything correctly).

-- A new release will **NOT** be published until SHA256Advanced is complete. --