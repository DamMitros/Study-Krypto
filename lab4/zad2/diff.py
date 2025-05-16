# Damian Mitros index: 292586
# Kryptografia - Funkcje skrótu 2
import hashlib

with open("hash-.pdf", "rb") as f:
  lecture = f.read()

with open("personal.txt", "rb") as f:
  personal = f.read()

with open("personal_.txt", "rb") as f:
  personal_ = f.read()

hash_algos = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b"]

def compute_hash(algorithm, data):
  h = hashlib.new(algorithm)
  h.update(data)
  return h.hexdigest()

def bit_diff(hash1, hash2):
  b1 = bin(int(hash1, 16))[2:].zfill(len(hash1) * 4)
  b2 = bin(int(hash2, 16))[2:].zfill(len(hash2) * 4)
  diff = sum(c1 != c2 for c1, c2 in zip(b1, b2))
  return diff, len(b1)

with open("diff.txt", "w") as out:
  for algo in hash_algos:
    h1 = compute_hash(algo, lecture + personal)
    h2 = compute_hash(algo, lecture + personal_)
    diff, total = bit_diff(h1, h2)

    out.write(f"cat hash-.pdf personal.txt | {algo}sum\n")
    out.write(f"cat hash-.pdf personal_.txt | {algo}sum\n")
    out.write(f"{h1}\n")
    out.write(f"{h2}\n")
    out.write(f"Liczba różniących się bitów: {diff} z {total}, procentowo: {round(100 * diff / total)}%.\n\n")