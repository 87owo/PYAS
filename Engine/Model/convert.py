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

def get_type(file_path):
    suffix = {".com", ".dll", ".drv", ".exe", ".ocx", ".scr", ".sys", ".mui", ".cpl"}
    try:
        file_content = None
        if not os.path.splitext(file_path)[-1].lower() in suffix:
            return file_content
        with open(file_path, 'rb') as f:
            file_content = f.read()
    except:
        pass
    return file_content

####################################################################################################

def file_to_images(input_dir, output_dir):
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                file_content = get_type(file_path)
                if file_content:
                    print(file_path)
                    relative_path = os.path.relpath(root, input_dir)
                    output_path_dir = os.path.join(output_dir, relative_path)

                    if not os.path.exists(output_path_dir):
                        os.makedirs(output_path_dir)
                    image = preprocess_image(file_content, (224, 224))
                    safe_name = os.path.basename(file_path).replace('/', '_').replace('\\', '_')
                    image.save(os.path.join(output_path_dir, f"{safe_name}.png"))
            except Exception as e:
                print(e)

####################################################################################################

input_directory = input('Enter the folder path: ')
output_directory = "./Image_Output"
file_to_images(input_directory, output_directory)
input('Conversion Complete')
