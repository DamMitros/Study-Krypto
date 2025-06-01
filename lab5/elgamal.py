# Damian Mitros index: 292586
# Kryptografia - System ElGamala
import random, math, sys

def extended_gcd(a, b):
  if a == 0:
    return b, 0, 1
  gcd, x1, y1 = extended_gcd(b % a, a)
  x = y1 - (b // a) * x1
  y = x1
  return gcd, x, y

def mod_inverse(a, m):
  gcd, x, _ = extended_gcd(a, m)
  if gcd != 1:
    raise ValueError("Odwrotność modularna nie istnieje")
  return (x % m + m) % m

def pow_mod(base, exp, mod):
  return pow(base, exp, mod)

def read_elgamal_params():
  try:
    with open('elgamal.txt', 'r') as f:
      lines = f.read().strip().split('\n')
      p = int(lines[0].strip())
      g = int(lines[1].strip())
      return p, g
  except FileNotFoundError:
    print("Błąd: Nie można znaleźć pliku elgamal.txt")
    sys.exit(1)
  except (ValueError, IndexError):
    print("Błąd: Nieprawidłowy format pliku elgamal.txt")
    sys.exit(1)

def generate_keys():
  p, g = read_elgamal_params()

  b = random.randint(2, p - 2)
  beta = pow_mod(g, b, p)
    
  with open('private.txt', 'w') as f:
    f.write(f"{p}\n{g}\n{b}\n")
    
  with open('public.txt', 'w') as f:
    f.write(f"{p}\n{g}\n{beta}\n")

def read_private_key():
  try:
    with open('private.txt', 'r') as f:
      lines = f.read().strip().split('\n')
      p = int(lines[0].strip())
      g = int(lines[1].strip())
      b = int(lines[2].strip())
      return p, g, b
  except FileNotFoundError:
    print("Błąd: Nie można znaleźć pliku private.txt")
    sys.exit(1)
  except (ValueError, IndexError):
    print("Błąd: Nieprawidłowy format pliku private.txt")
    sys.exit(1)

def read_public_key():
  try:
    with open('public.txt', 'r') as f:
      lines = f.read().strip().split('\n')
      p = int(lines[0].strip())
      g = int(lines[1].strip())
      beta = int(lines[2].strip())
      return p, g, beta
  except FileNotFoundError:
    print("Błąd: Nie można znaleźć pliku public.txt")
    sys.exit(1)
  except (ValueError, IndexError):
    print("Błąd: Nieprawidłowy format pliku public.txt")
    sys.exit(1)

def encrypt():
  p, g, beta = read_public_key()

  try:
    with open('plain.txt', 'r') as f:
      m = int(f.read().strip())
  except FileNotFoundError:
    print("Błąd: Nie można znaleźć pliku plain.txt")
    sys.exit(1)
  except ValueError:
    print("Błąd: Wiadomość musi być liczbą")
    sys.exit(1)
    
  if m >= p:
    print("Błąd: Wiadomość musi być mniejsza od p")
    sys.exit(1)
    
  k = random.randint(2, p - 2)
  c1 = pow_mod(g, k, p)
  c2 = (m * pow_mod(beta, k, p)) % p
    
  with open('crypto.txt', 'w') as f:
    f.write(f"{c1}\n{c2}\n")

def decrypt():
  p, g, b = read_private_key()

  try:
    with open('crypto.txt', 'r') as f:
      lines = f.read().strip().split('\n')
      c1 = int(lines[0].strip())
      c2 = int(lines[1].strip())
  except FileNotFoundError:
    print("Błąd: Nie można znaleźć pliku crypto.txt")
    sys.exit(1)
  except (ValueError, IndexError):
    print("Błąd: Nieprawidłowy format pliku crypto.txt")
    sys.exit(1)
    
  beta_k = pow_mod(c1, b, p)
  beta_k_inv = mod_inverse(beta_k, p)
  m = (c2 * beta_k_inv) % p

  with open('decrypt.txt', 'w') as f:
    f.write(f"{m}\n")

def sign():
  p, g, b = read_private_key()

  try:
    with open('message.txt', 'r') as f:
      m = int(f.read().strip())
  except FileNotFoundError:
    print("Błąd: Nie można znaleźć pliku message.txt")
    sys.exit(1)
  except ValueError:
    print("Błąd: Wiadomość musi być liczbą")
    sys.exit(1)

  if m >= p:
    print("Błąd: Wiadomość musi być mniejsza od p")
    sys.exit(1)
    
  while True:
    k = random.randint(2, p - 2)
    if math.gcd(k, p - 1) == 1:
      break
    
  r = pow_mod(g, k, p)
  k_inv = mod_inverse(k, p - 1)
  x = ((m - b * r) * k_inv) % (p - 1)

  with open('signature.txt', 'w') as f:
    f.write(f"{r}\n{x}\n")

def verify():
  p, g, beta = read_public_key()
    
  try:
    with open('message.txt', 'r') as f:
      m = int(f.read().strip())
  except FileNotFoundError:
    print("Błąd: Nie można znaleźć pliku message.txt")
    sys.exit(1)
  except ValueError:
    print("Błąd: Wiadomość musi być liczbą")
    sys.exit(1)

  if m >= p:
    print("Błąd: Wiadomość musi być mniejsza od p")
    sys.exit(1)

  try:
    with open('signature.txt', 'r') as f:
      lines = f.read().strip().split('\n')
      r = int(lines[0].strip())
      x = int(lines[1].strip())
  except FileNotFoundError:
    print("Błąd: Nie można znaleźć pliku signature.txt")
    sys.exit(1)
  except (ValueError, IndexError):
    print("Błąd: Nieprawidłowy format pliku signature.txt")
    sys.exit(1)

  if not (1 <= r <= p-1) or not (0 <= x <= p-2):
    result = "N"
    print("N")
    with open('verify.txt', 'w') as f:
      f.write(f"{result}\n")
    return

  left = pow_mod(g, m, p)
  right = (pow_mod(r, x, p) * pow_mod(beta, r, p)) % p
    
  if left == right:
    result = "T"
    print("T")
  else:
    result = "N"
    print("N")

  with open('verify.txt', 'w') as f:
    f.write(f"{result}\n")

def main():
  if len(sys.argv) != 2:
    print("Użycie: python elgamal.py [-k|-e|-d|-s|-v]")
    sys.exit(1)
    
  option = sys.argv[1]
    
  if option == "-k":
    generate_keys()
  elif option == "-e":
    encrypt()
  elif option == "-d":
    decrypt()
  elif option == "-s":
    sign()
  elif option == "-v":
    verify()
  else:
    print("Nieprawidłowa opcja. Użyj: -k, -e, -d, -s, lub -v")
    sys.exit(1)

if __name__ == "__main__":
  main()