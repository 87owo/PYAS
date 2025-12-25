from PIL import Image
import numpy, pefile, os

####################################################################################################

def preprocess_image(file_data, size, channels=1):
    width, height = size
    wah = int(numpy.ceil(numpy.sqrt(len(file_data) / channels)))
    arr = numpy.frombuffer(file_data, dtype=numpy.uint8)
    img = numpy.zeros(wah*wah*channels, dtype=numpy.uint8)
    img[:len(file_data)] = arr
    image = Image.fromarray(img.reshape((wah, wah)), 'L')
    return image.resize((width, height), Image.Resampling.NEAREST)

####################################################################################################

def is_text_file(content, sample_size=1024):
    raw = content[:sample_size]
    if not raw:
        return False
    text_char = set(range(32, 127)) | {9, 10, 13}
    nontext = sum(b not in text_char for b in raw)
    return nontext / len(raw) < 0.15

def get_type(file_path):
    suffix = {".com", ".dll", ".drv", ".exe", ".ocx", ".scr", ".sys", ".mui", ".cpl"}

    match_data = {}
    if not os.path.splitext(file_path)[-1].lower() in suffix:
        return match_data
    try:
        with pefile.PE(file_path, fast_load=True) as pe:
            for section in pe.sections:
                name = section.Name.rstrip(b'\x00').decode('latin1').lower()
                data = section.get_data()
                if data:
                    match_data[name] = section.get_data()
    except pefile.PEFormatError:
        with open(file_path, 'rb') as f:
            file_content = f.read()
        if is_text_file(file_content):
            match_data[os.path.splitext(file_path)[-1].lower()] = file_content
    return match_data

####################################################################################################

def file_to_images(input_dir, output_dir):
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                for name, data in get_type(file_path).items():
                    print(name, file_path)
                    relative_path = os.path.relpath(root, input_dir)
                    output_path_dir = os.path.join(output_dir, relative_path)
                    if not os.path.exists(output_path_dir):
                        os.makedirs(output_path_dir)
                    image = preprocess_image(data, (224, 224))
                    image.save(os.path.join(output_path_dir, f"{name}_{file}.png"))
            except Exception as e:
                print(e)

####################################################################################################

input_directory = input('Enter the folder path: ')
output_directory = "./Image_Output"
file_to_images(input_directory, output_directory)
input('Conversion Complete')
