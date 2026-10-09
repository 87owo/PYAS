VERSION = "3.7.1"
FILE_VERSION = VERSION + ".0"


def create_version_file(output_file="versionfile.txt"):
    import pyinstaller_versionfile

    pyinstaller_versionfile.create_versionfile(
        output_file=output_file,
        version=FILE_VERSION,
        company_name="PYAS Security",
        file_description="PYAS Security Antivirus",
        internal_name="PYAS",
        legal_copyright="PYAS Security",
        original_filename="PYAS.exe",
        product_name="PYAS",
    )


if __name__ == "__main__":
    create_version_file()
