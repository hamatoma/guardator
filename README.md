# guardator

A GUI tool for secure start of a configured program and some command line tools for maintenance.

## The Program Guardator
The program asks for a password. If correct the configured external program is started.

There is a possability to change the password.

## The Commandline Tool scrambler
Some services to maintain the project:
* Can build encrypted text used in the source text: sub command codepoints
* Can shuffle program code to make it difficult to reengineer customized source code.
* Can encrypt/decrypt data.

### Usage
Call scrambler without arguments to see the following usage message:
```Usage: scrambler <command> <args_and_opts>'
  Modifies source code.

-v, --[no-]verbose    shows more information
scrambler codepoints <text1> [<text2> ...]
  Shows the codepoints of  <textN>.
-m, --masks    A comma separated list of values that will be xor-ed to the codepoints.
scrambler create-safe <output> <offset1> <string1> [<offset2> <string2>...]
  Creates a file <output> with random binary data 
    and embedded ciphered <stringN> at <offsetN>
-f, --file          the file of the data safe.
                    (defaults to "/etc/guardator/datasafe.data")
-s, --secret        The secret ("passphrase") for encryption.
-z, --size          The size of the output file.
                    (defaults to "65536")
-S, --secret2       The password for execution.
-F, --[no-]force    forces overwriting the existing file.
scrambler initialize [<opts>]
  Creates a new standard customized data safe file (with two secrets).
-2, --secret2       the password used for execution of critical commands.
-f, --file          the file of the data safe.
                    (defaults to "/etc/guardator/datasafe.data")
-z, --size          the size of the data safe file.
                    (defaults to "4092")
-s, --secret        the secret used for en/decrypting storage data.
-F, --[no-]force    forces overwriting the existing file.
scrambler patch-safe [<opts>] <file> [[<offset1> <secret1> [<offset2> <secret2> ...]
  Modifies an existing data safe named <file> with <secretN> at offset <offsetN>.
-S, --secret    The secret ("passphrase") for encryption.
scrambler random <count>
  Creates and shows <count> random numbers.
-M, --max-value    the maximum (including) value of the created numbers.
                   (defaults to "4294967295")
-m, --min-value    the minimum value of the created numbers.
                   (defaults to "0")
-s, --separator    the separator between the created number.
                   (defaults to ",")
scrambler shuffle <input> <output>
  Reorders source code from file <input> into file <output>.
-h, --[no-]reverse    Sorts ranges in reverse order (for testing).
scrambler store-int16 <file> <offset> <value>
  Stores a 16 bit [value] at [offset] into file <file>.
-m, --masks    A comma separated list of values that will be xor-ed to the stored data.
```
## The Commandline Tool guardator_cli
Maintainance of the configuration file used for guardator.

# Customizing
The programs need secrets. 

Therefore there is a possability to customize the sourcecode to use your own secrets.

Copy the file lib/app/helper/data_safe_custom_template.dart into the file
lib/app/helper/data_safe_custom.dart and change the constants described in the sourcecode comments.

Than compile the programs into the programs.
