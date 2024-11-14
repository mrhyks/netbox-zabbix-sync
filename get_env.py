import sys
import os
for arguments in sys.argv:
    print(arguments)
print(os.environ['VAULT'])
print(os.environ['VAULT_PASSWORD'])