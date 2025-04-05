# Damian Mitros index: 292586
# Kryptografia - Błędne powtórzenie klucza jednorazowego
import os, argparse, base64

def prepare_file():
  if not os.path.exists("orig.txt"):
    print("Orig.txt was not found.")
    return
  
  with open("orig.txt", "r", encoding="utf-8") as file:
    text = file.read()

  line_length = 32
  text = ' '.join(text.splitlines())
  filtered_text = ''.join(char for char in text if char.isalpha() or char.isspace()).lower()

  lines=[]
  for i in range(0, len(filtered_text), line_length):
    if i + line_length <= len(filtered_text):
      lines.append(filtered_text[i:i + line_length])
    else:
      last_line = filtered_text[i:]
      padded_line = last_line + ' ' * (line_length - len(last_line))
      lines.append(padded_line)

  try:
    with open("plain.txt", "w", encoding="utf-8") as file:
      file.write('\n'.join(lines))
  except Exception as e:
    print(f"Error writing to plain.txt: {e}")
    return
  
def encrypt_file():
  if not os.path.exists("plain.txt"):
    print("Plain.txt was not found.")
    return

  if not os.path.exists("key.txt"):
    print("Key.txt was not found.")
    return

  with open("plain.txt", "r", encoding="utf-8") as file:
    plaintext = file.read()

  with open("key.txt", "r", encoding="utf-8") as file:
    key = file.read()

  encrypted_lines = []
  for line in plaintext.splitlines():
    if len(line) > 32:
      print("Line exceeds 32 characters. Please check your input.")
      return
    
    encrypted_line = []
    for i in range(len(line)):
      key_temp = key[i % len(key)]
      encrypted_char = chr(ord(line[i]) ^ ord(key_temp))
      encrypted_line.append(encrypted_char)
    
    encrypted_lines.append(encrypted_line)

  try:
    with open("crypto.txt", "w", encoding="utf-8") as file:  
      for line in encrypted_lines:
        raw_bytes = ''.join(line).encode('utf-8')
        b64_encoded = base64.b64encode(raw_bytes).decode('utf-8')
        file.write(b64_encoded + '\n')
  except Exception as e:
    print(f"Error writing to crypto.txt: {e}")
    return

def cryptoanalysis():
  if not os.path.exists("crypto.txt"):
    print("crypto.txt was not found.")
    return

  with open("crypto.txt", "r", encoding="utf-8") as file:
    encrypted_lines = file.readlines()
    
  key_length = 32  
  possible_key = bytearray([0] * key_length)
  decoded_lines = [base64.b64decode(line.strip()) for line in encrypted_lines]

  for pos in range(key_length):
    bytes_at_pos = [line[pos] for line in decoded_lines if pos < len(line)]

    best_key_byte = 0
    best_score = -1
        
    for key_byte in range(256):
      score = 0
      for b in bytes_at_pos:
        decrypted = b ^ key_byte
        if decrypted == 32: 
          score += 3
        elif 97 <= decrypted <= 122: 
          score += 2
        elif (65 <= decrypted <= 90) or (48 <= decrypted <= 57):
          score += 1
        elif 33 <= decrypted <= 126:  
          score += 0.5
        else:  
          score -= 1
            
      if score > best_score:
        best_score = score
        best_key_byte = key_byte
        
    possible_key[pos] = best_key_byte
    
  decrypted_lines = []
  for line in decoded_lines:
    decrypted = []
    for i, byte in enumerate(line):
      if i < key_length:
        dec_char = byte ^ possible_key[i]
        if 97 <= dec_char <= 122 or dec_char == 32: 
          decrypted.append(chr(dec_char))
        else:
          decrypted.append('_')
      else:
        decrypted.append('_')
        
    decrypted_lines.append(''.join(decrypted))
    
  # Print the discovered key (for debugging)
  # key_text = ''.join(chr(b) if 97 <= b <= 122 or b == 32 else '_' for b in possible_key)
  # print(f"Discovered key: {key_text}")

  try:
    with open("decrypt.txt", "w", encoding="utf-8") as file:
      file.write('\n'.join(decrypted_lines))
  except Exception as e:
    print(f"Error writing to decrypt.txt: {e}")
    return
    
def main():
  parser = argparse.ArgumentParser(description="Encrypt a file using XOR cipher.")
  parser.add_argument("-p", "--prepare", action="store_true", help="Prepare the orig.txt file.")
  parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the plain.txt file with key.txt.")
  parser.add_argument("-k", "--cryptoanalysis", action="store_true", help="Perform cryptoanalysis on the encrypted file.")
  args = parser.parse_args()

  if args.prepare:
    prepare_file()
  elif args.encrypt:
    encrypt_file()
  elif args.cryptoanalysis:
    cryptoanalysis()
  else:
    print("Please specify --prepare or --encrypt.")

main()