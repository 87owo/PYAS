import requests

def scan(types,text):
    response = requests.get("http://27.147.30.238:5001/pyas", params={types: text})
    if response.status_code == 200:
        if response.text == "True":
            return "Virus found"
        else:
            return "Virus not found"
    else:
        return response.status_code

print(scan("md5","<md5 hashes>"))

# http://27.147.30.238:5001/pyas?md5=<md5 hashes>
# return string True, False
