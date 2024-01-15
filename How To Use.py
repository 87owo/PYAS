import subprocess

file_path = input("input scan file: ")
result = subprocess.check_output(["PYAS_Engine.exe", file_path], text=True, stderr=subprocess.STDOUT)
print(result.strip())
