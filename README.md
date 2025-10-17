### Use the identify_hash.py with the outputs of this extension
The extension will create known.txt and hashes.txt in your users directory called burp_outputs.

https://github.com/awillard1/id_hash/tree/main

##### Example Usage of id_hash with the outputs of the extensions
```
python3 /mnt/c/PenTesting/id_hash/identify_hash.py --value-file /mnt/c/users/adamw/burp-outputs/inputs.txt --hash-file /mnt/c/users/adamw/burp-outputs/hashes.txt --try-external --external-verbose --john-fork 28
```
