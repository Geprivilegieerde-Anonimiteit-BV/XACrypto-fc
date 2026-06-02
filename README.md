A multi-purpose Cryptography library in Java. Working on it day by day, slowly. Someday this will be complete, today is not that day.
To be clear, this is **NOT** mean't to be a replacement/alternative to BouncyCastle. Instead, it is meant to include what BouncyCastle does not have. I do not take any code whatsoever from OpenSSL or BouncyCastle for that reason.

### Current Objective: ZekerRijndael (custom from-scratch AES-128 block cipher)
### Note: i'm creating ZekerRijndael as it can be used for creating the following encryption ciphers: AES-CTR; AES-OFB; AES-CFB. Block modes include AES-CBC; AES-ECB. And of course AES-GCM + ASE-CCM
### if i ever say 196-bit, i mean 192-bit my brain is just bugged lol
## View the "zekerRijndael" branch to see inprogress work.

(i keep confusing myself so here's a todo) TODO:
### BLOWFISH-ECB
### BLOWFISH-CBC
### ARIA-ECB
### ARIA-CBC
### ARIA-CFB
### ARIA-OFB

### Current Objective: ZekerRijndael (custom from-scratch AES-128 block cipher)

## View the "zekerRijndael" branch to see inprogress work.

Use `setopt interactivecomments` (zsh only) to allow using `#` for comments if you see errors like `zsh: command not found: #`

Ensure Java + javac are installed, on MacOS it can be installed with Homebrew by running `brew install openjdk`

You will also need maven installed. With Homebrew, this can be installed with `brew install maven`.

To compile:

1. git clone https://github.com/Geprivilegieerde-Anonimiteit-BV/XACrypto.git # download the git repository
2. cd XACrypto
3. mvn clean package

You should find the built jar at target/XACrypto-1.0-SNAPSHOT.jar
