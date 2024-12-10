import re, random, string

with open('../Implant/daemon/daemon-implant.go', 'r') as file:
    content = file.read()

# Replace function names (this assumes no anonymous functions)
content = re.sub(r'def (\w+)\(', lambda m: f'def {random.choice(string.ascii_uppercase)}{random.randint(1000,9999)}(', content)

with open('../Implant/main_obfuscated.go', 'w') as file:
    file.write(content)