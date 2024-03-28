import re
import zlib
import base64

class detector:
    def detect_layer(content):
        try:
            content = first_layer.deobfuscate_first_layer(content)
            try:
                content = second_layer.deobfuscate_second_layer(content)
                content = third_layer.deobfuscate_third_layer(content)
            except:
                content = third_layer.deobfuscate_third_layer(content)
                content = second_layer.deobfuscate_second_layer(content)
        except:
            try:
                content = second_layer.deobfuscate_second_layer(content)
                try:
                    content = third_layer.deobfuscate_third_layer(content)
                    content = first_layer.deobfuscate_first_layer(content)
                except:
                    content = first_layer.deobfuscate_first_layer(content)
                    content = third_layer.deobfuscate_third_layer(content)
            except:
                content = third_layer.deobfuscate_third_layer(content)
                try:
                    content = second_layer.deobfuscate_second_layer(content)
                    content = first_layer.deobfuscate_first_layer(content)
                except:
                    content = first_layer.deobfuscate_first_layer(content)
                    content = second_layer.deobfuscate_second_layer(content)
        with open("output.py", "w") as f:
            f.write(content)

class first_layer:
    def get_variables_name_and_values(content):
        # fire = bytes([78, 97, 70, 117, 109, 67, 108, 121, ...])
        # water = bytes([117, 86, 77, 118, 103, 103, 78, 102, ...])
        # earth = bytes([111, 69, 119, 109, 79, 103, 114, 81, ...])
        # wind =  bytes([116, 89, 81, 87, 102, 89, 99, 117, 65, ...])
        base64_values = []
        matches = re.findall(r'\b([a-zA-Z_]\w*)\s*=\s*(.+?)\s*(?:$|(?=\n))', content, re.MULTILINE)
        for match in matches:
            value = match[1]
            base64_values.append(eval(value))
        return base64_values
    
    def remove_second_layer(base64_values):
        # first_layer = exec(__import__("zlib").decompress(__import__("base64").b64decode(fire + water + earth + wind)))
        base64_string = ""
        for value in base64_values:
            base64_string+=value
        removed_first_layer = zlib.decompress(base64.b64decode(base64_string)).decode()
        return removed_first_layer
    
    def deobfuscate_first_layer(content):
        base64_values = first_layer.get_variables_name_and_values(content)
        content = first_layer.remove_second_layer(base64_values)
        return content

class second_layer:
    def get_variable_name_and_value(content):
        # name = "".join(random.choices(dir(builtins), k=random.randint(10, 25)))
        # value = [73, 173, 212, 107, 106, 94, 34, 120, 43, 76, 214, 102, 133, ...]
        match = re.search(r'\b([a-zA-Z_]\w*)\s*=\s*(.+?)\s*(?:$|(?=\n))', content, re.MULTILINE)
        name_encrypted = match.group(1)
        value = eval(match.group(2))
        return name_encrypted, value

    def get_in_loc(name_encrypted, content):
        # in_loc = random.randint(0, int(len(encrypted)/2))
        pattern = r'if\s+' + re.escape(name_encrypted) + r'\s*\[(.*?)\]'
        match = re.search(pattern, content)
        in_loc = match.group(1)
        return eval(in_loc)

    def get_re_loc(name_encrypted, content):
        # re_loc = random.randint(in_loc, len(encrypted) - 1)
        pattern = r'\b' + re.escape(name_encrypted) + r'\s*\[(.*?)\]'
        matches = re.findall(pattern, content, re.MULTILINE)
        re_loc = eval(matches[1])
        return re_loc
    
    def get_i_value(value, re_loc, in_loc):
        # i = for i in rannge(1,100)
        i_value = value[re_loc] ^ value[in_loc]
        return i_value
    
    def remove_second_layer(i_value, value, in_loc, re_loc):
        # second_layer = exec(__import__("zlib").decompress(bytes(map(lambda x: x^i, encrypted[0:in_loc] + encrypted[in_loc + 1: re_loc] + encrypted[re_loc + 1:]))))
        removed_second_layer = zlib.decompress(bytes(map(lambda x: x^i_value, value[0: in_loc] + value[in_loc + 1: re_loc] + value[re_loc + 1:]))).decode()
        return removed_second_layer
    
    def deobfuscate_second_layer(content):
        name_encrypted, value = second_layer.get_variable_name_and_value(content)
        in_loc = second_layer.get_in_loc(name_encrypted, content)
        re_loc = second_layer.get_re_loc(name_encrypted, content)
        i_value = second_layer.get_i_value(value, re_loc, in_loc)

        content = second_layer.remove_second_layer(i_value, value, in_loc, re_loc)

        return content
    
class third_layer:
    def get_ip_table(content):
        # ip_table = ['101.74.119.100', '121.75.69.79', '103.122.65.81', ...]
        match = re.search(r'\b([a-zA-Z_]\w*)\s*=\s*(.+?)\s*(?:$|(?=\n))', content, re.MULTILINE)
        ip_table = eval(match.group(2))
        return ip_table
    
    def get_data(ip_table):
        data = list([int(x) for item in [value.split(".") for value in ip_table] for x in item])
        return data
    
    def remove_third_layer(data):
        # third_layer = exec(compile(__import__("zlib").decompress(__import__("base64").b64decode(bytes(data))), "<(*3*)>", "exec"))
        third_layer_removed = zlib.decompress(base64.b64decode(bytes(data))).decode()
        return third_layer_removed
    
    def deobfuscate_third_layer(content):
        ip_table = third_layer.get_ip_table(content)
        data = third_layer.get_data(ip_table)
        content = third_layer.remove_third_layer(data)
        return content
    
def main():

    file = input("insert the file path:")

    with open(file,"r") as f:
        content = f.read()

    detector.detect_layer(content)

if __name__ == "__main__":
    main()