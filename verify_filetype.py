import os, StringIO, zipfile

def is_distutils_file(content, filename, filetype):
    '''Perform some basic checks to see whether the indicated file could be
    a valid distutils file.
    '''

    if filename.endswith('.exe'):
        # check for valid exe
        if filetype != 'bdist_wininst':
            return False

        try:
            t = StringIO.StringIO(content)
            t.filename = filename
            z = zipfile.ZipFile(t)
            l = z.namelist()
        except zipfile.error:
            return False

        for zipname in l:
            if not safe_zipnames.match(zipname):
                return False

    elif filename.endswith('.zip'):
        # check for valid zip
        try:
            t = StringIO.StringIO(content)
            t.filename = filename
            z = zipfile.ZipFile(t)
            l = z.namelist()
        except zipfile.error:
            return False
        for entry in l:
            parts = os.path.split(entry)
            if len(parts) == 2 and parts[1] == 'PKG-INFO':
                # eg. "roundup-0.8.2/PKG-INFO"
                break
        else:
            return False

    return True


if __name__ == '__main__':
    import sys
    filename, filetype = sys.argv[1:]
    print is_distutils_file(open(filename, 'rb').read(), filename, filetype)

