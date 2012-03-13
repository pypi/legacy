import sys
import zipfile
import tarfile
import gzip
import bz2
import StringIO
import cgi

from docutils.core import publish_parts


def trim_docstring(text):
    """
    Trim indentation and blank lines from docstring text & return it.

    See PEP 257.
    """
    if not text:
        return text
    # Convert tabs to spaces (following the normal Python rules)
    # and split into a list of lines:
    lines = text.expandtabs().splitlines()
    # Determine minimum indentation (first line doesn't count):
    indent = sys.maxint
    for line in lines[1:]:
        stripped = line.lstrip()
        if stripped:
            indent = min(indent, len(line) - len(stripped))
    # Remove indentation (first line is special):
    trimmed = [lines[0].strip()]
    if indent < sys.maxint:
        for line in lines[1:]:
            trimmed.append(line[indent:].rstrip())
    # Strip off trailing and leading blank lines:
    while trimmed and not trimmed[-1]:
        trimmed.pop()
    while trimmed and not trimmed[0]:
        trimmed.pop(0)
    # Return a single string:
    return '\n'.join(trimmed)


def processDescription(source, output_encoding='unicode'):
    """Given an source string, returns an HTML fragment as a string.

    The return value is the contents of the <body> tag.

    Parameters:

    - `source`: A multi-line text string; required.
    - `output_encoding`: The desired encoding of the output.  If a Unicode
      string is desired, use the default value of "unicode" .
    """
    # Dedent all lines of `source`.
    source = trim_docstring(source)

    settings_overrides={
        'raw_enabled': 0,  # no raw HTML code
        'file_insertion_enabled': 0,  # no file/URL access
        'halt_level': 2,  # at warnings or errors, raise an exception
        'report_level': 5,  # never report problems with the reST code
        }

    # capture publishing errors, they go to stderr
    old_stderr = sys.stderr
    sys.stderr = s = StringIO.StringIO()
    parts = None
    try:
        # Convert reStructuredText to HTML using Docutils.
        parts = publish_parts(source=source, writer_name='html',
                              settings_overrides=settings_overrides)
    except:
        pass

    sys.stderr = old_stderr

    # original text if publishing errors occur
    if parts is None or len(s.getvalue()) > 0:
        output = "".join('<PRE>\n' + cgi.escape(source) + '</PRE>')
    else:
        output = parts['body']

    if output_encoding != 'unicode':
        output = output.encode(output_encoding)

    return output

def extractPackageReadme(content, filename, filetype):
    '''Extract the README from a file and attempt to turn it into HTML.

    Return the source text and html version or emty strings in either case if
    extraction fails.
    '''
    text = html = ''
    if filename.endswith('.zip') or filename.endswith('.egg'):
        try:
            t = StringIO.StringIO(content)
            t.filename = filename
            zip = zipfile.ZipFile(t)
            l = zip.namelist()
        except zipfile.error:
            return '', ''
        for entry in l:
            parts = entry.split('/')
            if len(parts) != 2:
                continue
            filename = parts[-1]
            if filename.count('.') > 1:
                continue
            if filename.count('.') == 1:
                name, ext = filename.split('.')
            else:
                # just use the filename and assume a readme is plain text
                name = filename
                ext = 'txt'
            if name.upper() != 'README':
                continue
            # grab the content and parse if it's something we might understand,
            # based on the file extension
            text = zip.open(entry).read()
            if ext in ('txt', 'rst', 'md'):
                html = processDescription(text)
            return text, html

    elif (filename.endswith('.tar.gz') or filename.endswith('.tgz') or
            filename.endswith('.tar.bz2') or filename.endswith('.tbz2')):
        # open the tar file with the appropriate compression
        ext = filename.split('.')[-1]
        if ext[-2:] == 'gz':
            file = StringIO.StringIO(content)
            file = gzip.GzipFile(filename, fileobj=file)
        else:
            file = StringIO.StringIO(bz2.decompress(content))
        try:
            tar = tarfile.TarFile(filename, 'r', file)
            l = tar.getmembers()
        except tarfile.TarError:
            return '', ''
        for entry in l:
            parts = entry.name.split('/')
            if len(parts) != 2:
                continue
            filename = parts[-1]
            if filename.count('.') > 1:
                continue
            if filename.count('.') == 1:
                name, ext = filename.split('.')
            else:
                # just use the filename and assume a readme is plain text
                name = filename
                ext = 'txt'
            if name.upper() != 'README':
                continue
            print 'FOUND', filename
            # grab the content and parse if it's something we might understand,
            # based on the file extension
            text = tar.extractfile(entry).read()
            if ext in ('txt', 'rst', 'md'):
                html = processDescription(text)
            return text, html

    return text, html

if __name__ == '__main__':
    fname ='../parse/dist/parse-1.4.1.tar.gz'
    fname ='../parse/dist/parse-1.4.1.zip'
    fname ='../parse/dist/parse-1.4.1.tar.bz2'
    text, html = extractPackageReadme(open(fname).read(), fname, 'sdist')

