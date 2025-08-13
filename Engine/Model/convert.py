from PIL import Image
import numpy, pefile, os

def file_to_images(file_data, output_dir, file_name, target_size=(224, 224)):#
    wah = int(numpy.ceil(numpy.sqrt(len(file_data))))
    file_data = numpy.frombuffer(file_data, dtype=numpy.uint8)
    image_array = numpy.zeros((wah * wah,), dtype=numpy.uint8)
    image_array[:len(file_data)] = file_data
    image = Image.fromarray(image_array.reshape((wah, wah)), 'L')
    image = image.resize(target_size, Image.Resampling.NEAREST)
    image.save(os.path.join(output_dir, f"{file_name}.png"))

def check_file_type(file_path):
    try:
        shell_section = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", 
        "cry", "tvm", "dec", "enc", "vmp", "upx", "aes", "lzma", "press", 
        "pack", "enigma", "protect", "secur"]

        unknown_section = ["asmstub", "base", "bss", "clr_uef", "cursors", 
        "engine", "fio", "fothk", "h~;", "icapsec", "malloc_h", "miniex", 
        "mssmixer", "ndr64", "nsys_wr", "obr", "wow", "wow64svc", "wpp_sf",
        "pad", "pgae", "poolmi", "proxy", "qihoo", "res", "retpol", "uedbg",
        "rwexec", "rygs", "s:@", "sanontcp", "segm", "test", "tracesup",
        "transit", "trs_age", "wisevec"]

        unimportant_section = ["viahwaes", "orpc", "nep", "ace", "extjmp", 
        "no_bbt", "data", "page", "hexpthk"]

        shells = shell_section + unimportant_section + unknown_section
        
        ftype = str(f".{file_path.split('.')[-1]}").lower()

        if ftype in [".bat", ".cmd", ".ps1", ".vbs", ".wsf", ".js", ".html"]:
            with open(file_path, 'rb') as f:
                return [f.read()]

        match_data = []
        if ftype in [".com", ".exe", ".dll", ".sys", ".scr"]:
            with pefile.PE(file_path, fast_load=True) as pe:
                for section in pe.sections:
                    section_name = section.Name.rstrip(b'\x00').decode('latin1')
                    #if (section.Characteristics & 0x00000020 and not
                    #any(shell in section_name.lower() for shell in shells)):
                    if section.Characteristics & 0x00000020:
                        match_data.append(section.get_data())
                return match_data
        return False
    except Exception as e:
        print(e)
        return False

def batch_file_to_images(input_dir, output_dir):
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                file_data = check_file_type(file_path)
                if file_data:
                    for i, data in enumerate(file_data, 1):
                        print(i, file_path)
                        relative_path = os.path.relpath(root, input_dir)
                        output_path_dir = os.path.join(output_dir, relative_path)
                        if not os.path.exists(output_path_dir):
                            os.makedirs(output_path_dir)
                        file_to_images(data, output_path_dir, f"{i}_{file}")
            except Exception as e:
                print(e)
                pass

input_directory = input('Enter the folder path: ')
output_directory = "./Image_File"
batch_file_to_images(input_directory, output_directory)
input('Conversion Complete')
