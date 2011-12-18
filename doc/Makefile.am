
AUTOMAKE_OPTIONS = 1.10

DOC_MODULE = ell

DOC_MODULE_VERSION = 2

DOC_MAIN_SGML_FILE = $(DOC_MODULE)-docs.xml

DOC_SOURCE_DIR = ../ell

SCAN_OPTIONS = --rebuild-sections

MKDB_OPTIONS = --xml-mode --output-format=xml --name-space ell --tmpl-dir=.

MKTMPL_OPTIONS = --output-dir=.

MKHTML_OPTIONS = --path=$(abs_srcdir)/doc --path=$(abs_builddir)/doc

HFILE_GLOB = $(top_srcdir)/ell/*.h
CFILE_GLOB = $(top_srcdir)/ell/*.c

IGNORE_HFILES = private.h

content_files = version.xml

if ENABLE_GTK_DOC
include $(top_srcdir)/doc/gtk-doc.make
endif

DISTCLEANFILES = $(DOC_MODULE)-docs.xml \
			$(DOC_MODULE).types $(DOC_MODULE)-*.txt *.sgml *.bak

MAINTAINERCLEANFILES = Makefile.in gtk-doc.make
