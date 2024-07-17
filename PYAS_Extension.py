from subprocess import Popen, PIPE
import os, re, sys

class ExtenRules:
    def __init__(self):
        self.pyas = sys.argv[0].replace("\\", "/")
        self.dir = os.path.dirname(self.pyas)
        self.exten = os.path.join(self.dir, "Exten")

    def bdc_scan(self, file):
        try:
            check_file = file.replace("\\", "/")
            if ":/Windows" not in check_file and ":/Program" not in check_file:
                cmd = f'"{self.exten}\\bitdefender\\bdc.exe" "{file}"'
                p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True).wait()
                for match in re.finditer(r'(?P<filename>[^\s]+)\s+infected:\s+(?P<virusname>.+)', p.communicate()[0]):
                    return match.groupdict()
            return False
        except:
            return False

    def hollows_hunter(self, p):
        try:
            check_file = p.exe().replace("\\", "/")
            if ":/Windows" not in check_file and ":/Program" not in check_file:
                cmd = f'"{self.exten}\\hollows_hunter\\hollows_hunter.exe" /ofilter 2 /pid "{p.pid}"'
                p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True).wait()
                return 'Detected' in p.communicate()[0]
            return False
        except:
            return False

    def pe_sieve(self, p):
        try:
            check_file = p.exe().replace("\\", "/")
            if ":/Windows" not in check_file and ":/Program" not in check_file:
                cmd = f'"{self.exten}\\pe_sieve\\pe_sieve.exe" /ofilter 2 /pid "{p.pid}"'
                p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True).wait()
                output = p.communicate()[0]
                for match in re.finditer(r'(\d+)', output):
                    line = output[:match.start()].split('\n')[-1].strip().replace(':', '')
                    if line in ["Implanted shc", "Replaced", "IAT Hooks"] and int(match.group(1)) > 0:
                        return line
            return False
        except:
            return False
