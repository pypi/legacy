##########################################################################
#
# Copyright (c) 2005 Imaginary Landscape LLC and Contributors.
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
##########################################################################
## This file is from ZPTKit
"""
templatetools.py

Tools for using ZopePageTemplates, primarily intended for use with
Webware.

Typically you will use TemplatePool, storing an instance of the pool.
To get a template, use aPool.getTemplate(filename) -- this reuse a
template if possible (but no two threads will use the same template).
When you are finished with the template you should call
aPool.returnTemplate(templateObject).  In Webware this is typically
done as part of SitePage, with templates returned in .sleep().

The other interesting tool is ContextWrapper.  This is a thin wrapper
that give you access to the template's namespace.  Any object can
define the method ``__render_with_namespace__`` and if the object is
rendered in a template then that method will be called with a single
argument -- a dictionary-like object containing the namespace.

This is awkward when you have a method (rather than a full blown
object) that you want to render using the namespace.  ContextWrapper
takes a function argument, and when it is render, it in turn calls the
function it was given with the namespace argument.  A small example is
in that class.
"""

import os
from zope.pagetemplate.pagetemplate import PageTemplate
from zope.pagetemplate.pagetemplate import PTRuntimeError
import types

class TemplatePool:

    """

    A manager class to pool templates.  Templates are created on
    demand (using getTemplate), and can be returned -- if a template
    from the same filename has been already been created and returned,
    then it can be reused.

    To ensure threadsafety, two threads will not have access to the
    same template.
    """

    def __init__(self, ptClass=None, classArgs=(), classKW=None):
        self._pool = {}
        if not ptClass:
            ptClass = FilePageTemplate
        self.ptClass = ptClass
        self.classArgs = classArgs
        self.classKW = classKW or {}

    def getTemplate(self, filename):
        try:
            inst = self._pool[filename].pop()
        except (KeyError, IndexError):
            kw = self.classKW.copy()
            kw['factory'] = self
            inst = self.ptClass(filename, *self.classArgs, **kw)
        if inst._v_errors:
            raise PTRuntimeError(
                'Template %s has errors:\n%s\n%s'
                % (filename, inst._v_errors[0], inst._v_errors[1]))
        return inst

    def __call__(self, filename):
        return self.getTemplate(filename)

    def returnTemplate(self, template):
        self._pool.setdefault(template.filename, []).append(template)

    def __repr__(self):
        start = '<TemplatePool %s factory=%s(' % (
            hex(id(self)), self.ptClass)
        if self.classArgs:
            start += ', '.join(map(repr, self.classArgs))
        if self.classKW:
            if self.classArgs:
                start += ' '
            start += ', '.join(['%s=%r' % (n, v)
                                for n, v in self.classKW.items()
                                if v is not self])
        return start + ')>'

class FilenameSpace:

    """
    This implements 'here' for page templates, where 'here' is a space
    that supports fetching other templates.  I.e., when you do::

        <metal:use-macro="here/standard_template.pt/macros/page">

    this is the 'here' that finds 'standard_template.pt'.

    You must also provide it with a subclass of PageTemplate that can
    accept a filename as its only constructor argument.  (Or
    potentially it can be some other factory function that creates
    PageTemplate instances)
    """

    def __init__(self, dirs, ptClass):
        if isinstance(dirs, (str, unicode)):
            dirs = [dirs]
        self.dirs = dirs
        self.ptClass = ptClass

    def __getitem__(self, key):
        assert '/' not in key, "Keys cannot have '/'s: %r" % key
        for dir in self.dirs:
            filename = os.path.join(dir, key)
            if os.path.exists(filename):
                break
        else:
            raise KeyError(
                "The filename %s could not be found (in %s)" %
                (key, ', '.join(self.dirs)))
        if os.path.isdir(filename):
            return self.__class__(filename, self.ptClass)
        else:
            return self.ptClass(filename)

    def __repr__(self):
        return ('<%s %s dirs=(%s) ptClass=%s>'
                % (self.__class__.__name__,
                   hex(id(self)), ', '.join(self.dirs),
                   self.ptClass))


class FilePageTemplate(PageTemplate):

    """
    This is a page template that is based on a file.  Each template is
    passed a filename argument, and the template is read from that
    file.  The template may be reread (if it has changed) anytime you
    call .refresh().  You may wish to do this at the beginning of a
    request.

    It adds 'here' to the context, which is a namespace for the
    directory in which it is contained (using FileNamespace).
    Specifically this makes this work::

        <html metal:use-macro="here/standard_template.pt/macros/page">

    You can pass in here_dir if you want to use a separate directory.
    Sometimes this will be a fixed directory, since there is currently
    no way to traverse from 'here' to a parent directory.
    """

    def __init__(self, filename, here_dirs=None, factory=None):
        self.filename = filename
        self.mtime = 0
        if factory is None:
            self.factory = self.__class__
        else:
            self.factory = factory
        self.refresh()
        if here_dirs is None:
            here_dirs = [os.path.dirname(os.path.abspath(filename))]
        self.here_dirs = here_dirs
        self.here = FilenameSpace(
            here_dirs,
            self.factory)

    def refresh(self):
        mtime = os.stat(self.filename).st_mtime
        if mtime > self.mtime:
            self.mtime = mtime
            self.read_file(self.filename)

    def read_file(self, filename):
        f = open(self.filename, 'rb')
        self.write(f.read())
        f.close()

    def __call__(self, context=None, *args, **kw):
        if context is None:
            context = {}
        if not kw.has_key('args'):
            kw['args'] = args
        elif args:
            assert 0, "You cannot both pass in a keyword argument 'args', and positional arguments"
        extra_context = {'options': kw, 'here': self.here,
                         'test': test}
        context.update(extra_context)
        return self.pt_render(extra_context=context)

    def __repr__(self):
        return ('<%s %s %s>'
                % (self.__class__, hex(id(self)), self.filename))


class ContextWrapper:

    """
    This is used when you don't want to create a new object just to
    render a small bit of content in a way that is aware of the
    PageTemplate context.  You use it like::

        class MyClass:
            def getLink(self, ns):
                do stuff with ns...
            link = ContextWrapper(getLink)

    Then when someone does <span tal:replace="aMyClass/link"> they
    will be calling the getLink function.
    """

    def __init__(self, callback, *args, **kw):
        self.callback = callback
        self.args = args
        self.kw = kw

    def __render_with_namespace__(self, ns):
        return self.callback(ns, *self.args, **self.kw)

def test(conditional, trueValue, falseValue=None):
    if conditional:
        return trueValue
    else:
        return falseValue

__all__ = ['TemplatePool', 'FilePageTemplate', 'StandardContext']
