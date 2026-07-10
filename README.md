A multi-purpose Cryptography library in Java. Working on it day by day, slowly. Someday this will be complete, today is not that day.
To be clear, this is **NOT** mean't to be a replacement/alternative to BouncyCastle. Instead, it is meant to include what BouncyCastle does not have. No code was taken from OpenSSL or BouncyCastle for that reason.

Yes. We will advertise Microsoft products for free via variable names.

Use `setopt interactivecomments` (zsh only) to allow using `#` for comments if you see errors like `zsh: command not found: #`

Ensure Java + javac are installed, on MacOS it can be installed with Homebrew by running `brew install openjdk`

You will also need maven installed. With Homebrew, this can be installed with `brew install maven`.

To compile (these commands should work universally):

1. git clone https://github.com/Geprivilegieerde-Anonimiteit-BV/XACrypto.git # download the git repository
2. cd XACrypto # enter the directory
3. mvn clean package # first clean the directory, then package it into a jar

You should find the built jar at target/xacrypto-\<version\>.jar
