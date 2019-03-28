
import json
import re

def str2bool(v):
  return v.lower() in ("True", "true", "1")

def check_password(password):
    with open('policy.json') as json_file:
        data = json.load(json_file)

    length = int(data["length"])
    numbers = str2bool(data["numbers"])
    uppercase = str2bool(data["uppercase letters"])
    lowercase = str2bool(data["lowercase letters"])
    special = str2bool(data["special symbols"])

    if len(password) < length:
        return False

    numbers_check = bool(re.search('\d+', password))
    # print("numbers check", numbers_check)
    uppercase_check = bool(re.search('[A-Z]', password))
    # print("uppercase check", uppercase_check)
    lowercase_check = bool(re.search('[a-z]', password))
    # print("lowercase check", lowercase_check)
    special_check = bool(re.search('[^a-zA-Z0-9_]', password))
    # print("special symbols check", special_check)

    if numbers_check != numbers:
        return False
    if uppercase_check != uppercase:
        return False
    if lowercase_check != lowercase:
        return False
    if special_check != special:
        return False
    return True

# print("Status:", check_password("xxx4x@C_xxxxxx"))
