# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2010-2025 Intel Corporation.

from sphinx.highlighting import PygmentsBridge
from pygments.formatters.latex import LatexFormatter


project = 'TXGen'
copyright = '2010-2025'

version = '3.2.4'
release = version

source_suffix = '.rst'
main_doc = 'index'
pygments_style = 'sphinx'
html_theme = 'default'
html_add_permalinks = ''
htmlhelp_basename = 'Pktgendoc'

latex_documents = [
    ('index',
     'txgen.tex',
     'TXGen Documentation',
     'Intel Corp', 'manual'),
]

latex_preamble = """
\\usepackage{upquote}
\\usepackage[utf8]{inputenc}
\\usepackage{DejaVuSansMono}
\\usepackage[T1]{fontenc}
\\usepackage{helvet}
\\renewcommand{\\familydefault}{\\sfdefault}

\\RecustomVerbatimEnvironment{Verbatim}{Verbatim}{xleftmargin=5mm}
"""

latex_elements = {
    'papersize': 'a4paper',
    'pointsize': '11pt',
    'preamble': latex_preamble,
}


man_pages = [
    ('index',
     'txgen',
     'TXGen Documentation',
     ['Intel Corp'],
     1)
]

texinfo_documents = [
    ('index', 'TXGen',
     'TXGen Documentation',
     'Intel Corp',
     'TXGen',
     'One line description of project.',
     'Miscellaneous'),
]


class CustomLatexFormatter(LatexFormatter):
    def __init__(self, **options):
        super(CustomLatexFormatter, self).__init__(**options)
        self.verboptions = r"formatcom=\footnotesize"

PygmentsBridge.latex_formatter = CustomLatexFormatter
