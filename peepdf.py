'''
PeePDF is not an actual package or anything. So, this module intends
to simulate it by adding the peepdf subdirectory from cwd to the module
search path...
'''
import sys, os.path
cwd = os.path.dirname(__file__)
sys.path.append(os.path.join(cwd, 'peepdf'))

import PDFCore
