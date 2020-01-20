import sys
import re

def find_repeat(string):
  match= re.match(r'(.*?)(?:\1)*$', string)
  word= match.group(1)
  return word

def breaker(password, key):
  index = 0
  decrypted = ""
  for char in password:
    decrypted += chr((ord(key[index]) - ord(char)) % 255)
    index += 1

  print(find_repeat(decrypted))

with open("check.txt", "r") as c:
  with open("out.txt", "r") as o:
    breaker(c.read(), o.read())