import subprocess
import os

VAULT_FILE = 'vault.py'
DECRYPTED_FILE = 'decrypted_vault.py'
VAULT_PASSWORD_FILE = 'vault_password.txt'  # Update this path
VAULT_PASSWORD = 'X5evHMGtCU4B58cgiQMh'

def decrypt_vault():
    with open(VAULT_PASSWORD_FILE, 'w') as file:
        file.write(VAULT_PASSWORD)
    subprocess.run(['ansible-vault', 'decrypt', VAULT_FILE, '--output', DECRYPTED_FILE, '--vault-password-file', VAULT_PASSWORD_FILE], check=True)

def encrypt_vault():
    subprocess.run(['ansible-vault', 'encrypt', DECRYPTED_FILE, '--output', VAULT_FILE, '--vault-password-file', VAULT_PASSWORD_FILE], check=True)
    os.remove(VAULT_PASSWORD_FILE)
    os.remove(DECRYPTED_FILE)

def load_vault_content():
    import decrypted_vault
    print(decrypted_vault.ZABBIX_TOKEN)
    
    with open(DECRYPTED_FILE, 'r') as file:
        content = file.read()
    return content

def main():
    decrypt_vault()
    content = load_vault_content()
    # print(content)  # Process the content as needed
    encrypt_vault()

if __name__ == '__main__':
    main()