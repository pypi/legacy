import os, re, StringIO, zipfile

safe_zipnames = re.compile(r'(purelib|platlib|headers|scripts|data).+', re.I)

def extract_zip( content, filename):
    try:
        t = StringIO.StringIO(content)
        t.filename = filename
        z = zipfile.ZipFile(t)
        return z.namelist()
    except zipfile.error:
        return None


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

    elif filename.endswith('.msi'):
        if filetype != 'bdist_msi':
            return False

        if not content.startswith('\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'): # from magic file
            return False

    elif filename.endswith('.zip') or filename.endswith('.egg'):
        # check for valid zip
        l = extract_zip(content, filename)
        if l is None:
            return False
        for entry in l:
            parts = os.path.split(entry)
            if len(parts) == 2 and parts[1] == 'PKG-INFO':
                # eg. "roundup-0.8.2/PKG-INFO" or "EGG-INFO/PKG-INFO"
                break
        else:
            return False

    elif filename.endswith('.whl'):
        l = extract_zip(content, filename)
        if l is None:
            return False
        for entry in l:
            parts = os.path.split(entry)
            if len(parts) == 2 and parts[1] == 'WHEEL':
                # eg. "wheel-0.7.dist-info/WHEEL"
                break
    return True


if __name__ == '__main__':
    import sys
    filename, filetype = sys.argv[1:]
    print is_distutils_file(open(filename, 'rb').read(), filename, filetype)

