###############################################################################
# msdnGrab
#
# Allows a user to grab documentation from online MSDN for a given function
# name in IDA, and import the documentation as a repeatable comment for that
# function.
#
# The script assumes that the function name is valid, and queries Google for
# the MSDN page. It then pulls the short description of the function, and
# the function definition into the comment. It also allows you to open the
# MSDN page to view the rest of the information.
#
# Usage:
#
#   Hotkey to grab as comment (Win32 API):  F3
#   Hotkey to grab as comment (C/C++):      Ctrl-F3
#   Hotkey to open query in browser:        Ctrl-Shift-F3
#
#   Just highlight a function (e.g. CreateFileA) in IDA, and hit the
#   corresponding hotkey what you want.
#
# Copyright (c) 2012 - * | Eugene Ching <eugene@enegue.com>
#
# All rights reserved.
#
###############################################################################

import idautils
import idc
import idaapi

import bs4
import HTMLParser
import urllib
import urllib2
import webbrowser


###############################################################################
# Globals
###############################################################################

_MSDN_HOTKEY_WIN32API   = 'F3'
_MSDN_HOTKEY_C          = 'Ctrl-F3'
_MSDN_HOTKEY_BROWSER    = 'Ctrl-Shift-F3'

COMMENT_NOT_REPEATABLE  = 0
COMMENT_REPEATABLE      = 1
MAX_COMMENT_WIDTH       = 50

_SEARCHTYPE_WIN32API    = 0
_SEARCHTYPE_C           = 1

_MSDN_DEBUG             = False


###############################################################################
# Helper functions
###############################################################################

def dbgPrint(sMessage):
  if (_MSDN_DEBUG == True):
    print sMessage

class TagStripper(HTMLParser.HTMLParser):
  def __init__(self):
    self.reset()
    self.fed = []
  def handle_data(self, d):
    self.fed.append(d)
  def get_data(self):
    return ''.join(self.fed)

def stripTags(text):
  s = TagStripper()
  s.feed(str(text))
  return s.get_data()

def stripBlankLines(text):
  return os.linesep.join([s for s in text.splitlines() if s])

def multiLineString(text):
  multiLine = ''
  lengthFromPreviousNewLine = 0
  words = text.split()
  for word in words:
    multiLine = multiLine + word + ' '
    if (len(multiLine)-lengthFromPreviousNewLine > MAX_COMMENT_WIDTH):
      multiLine = multiLine + '\n'
      lengthFromPreviousNewLine = len(multiLine)
  return multiLine.rstrip('\n')



###############################################################################
# Search Google for MSDN page
###############################################################################

def grabMsdnPageFromGoogle(searchTerm, searchType):
  # Get the Google URL
  if (searchType == _SEARCHTYPE_WIN32API):
    '''
    Queries for WIN32 API.

    Such queries are fairly easy, Google returns the right hit
    as the first entry almost all the time, without much ado.
    We simply query it.

    '''
    googleUrl='http://www.google.com/search?hl=en&q=%s+function+msdn+desktop+apps&sa=N&safe=off&filter=0' % searchTerm
    print '(msdnGrab) [Querying against Win32API] %s' % googleUrl

  elif (searchType == _SEARCHTYPE_C):
    '''
    Queries for C/C++.

    These queries are harder to get right, and if possible we
    want the right hit at the top of Google's results. We use
    Google's intitle and inurl to ensure that we get the right
    page, and an English one, in that order.

    '''
    googleUrl='http://www.google.com/search?hl=en&q=intitle:%s+msdn+crt+inurl:msdn*en-us&sa=N&safe=off&filter=0' % searchTerm
    print '(msdnGrab) [Querying against C/C++] %s' % googleUrl

  else:
    googleUrl = None

  # Check failure
  if (googleUrl is None):
    print '(msdnGrab) Error: Could not build a suitable Google search query.'
    return None

  # Read the page
  opener = urllib2.build_opener()
  opener.addheaders = [('User-agent', 'Mozilla/5.0')]
  page = opener.open(googleUrl).read()
  soup = bs4.BeautifulSoup(page)

  # Extract the first MSDN link
  links = soup.findAll('a')
  msdnLinks = [re.search('http://msdn.microsoft.com/(.*?)&', str(link)) for link in soup.find_all('a') if ('msdn.microsoft.com/en-us' in str(link))]
  try:
    msdnUrl = 'http://msdn.microsoft.com/en-us/' + msdnLinks[0].group(1)
  except:
    msdnUrl = None

  # Return the first link
  return msdnUrl


###############################################################################
# Launch browser with search term
###############################################################################

class QuietChooser(Choose):
  def enter(self, n):
    pass

def openMsdnPageInBrowser():
  # Get the highlighted identifier
  searchTerm = idaapi.get_highlighted_identifier()

  # Get the address
  ea = ScreenEA()

  # Make sure we have something highlighted
  if not searchTerm:
    print "(msdnGrab) Error: No identifier to use as search term was highlighted."
    return None

  # Select "language"
  languages = ['Win32 API', 'C/C++']
  chooser = QuietChooser([], "(Open in browser) Language to query", 1)  # Get a modal Choose instance
  chooser.list = languages                      # List to choose from
  chooser.width = 40                            # Set the width
  ch = chooser.choose()                         # Run the chooser

  # Decode the selection
  if (chooser.list[ch-1] == 'Win32 API'):
    searchType = _SEARCHTYPE_WIN32API
  elif (chooser.list[ch-1] == 'C/C++'):
    searchType = _SEARCHTYPE_C
  else:
    print '(msdnGrab) Error: Invalid language type selection made.'
    return None

  # Handle IDA's naming conventions for the identifier
  searchTerm = searchTerm.replace('__imp_', '')
  print '(msdnGrab) Using search term: %s' % searchTerm

  # Get the MSDN page URL
  msdnUrl = grabMsdnPageFromGoogle(searchTerm, searchType)
  if (msdnUrl is None):
    print '(msdnGrab) Error: Could not find a suitable MSDN page.'
    return None

  # Launch the browser
  webbrowser.open(msdnUrl)


###############################################################################
# Search MSDN page for definition
###############################################################################

def grabDefinitionFromMsdn(searchType):
  # Get the highlighted identifier
  searchTerm = idaapi.get_highlighted_identifier()

  # Get the address
  ea = ScreenEA()

  # Make sure we have something highlighted
  if not searchTerm:
    print "(msdnGrab) Error: No identifier to use as search term was highlighted."
    return None

  # Handle IDA's naming conventions for the identifier
  searchTerm = searchTerm.replace('__imp_', '')
  print '(msdnGrab) Using search term: %s' % searchTerm

  # Get the MSDN page URL
  msdnUrl = grabMsdnPageFromGoogle(searchTerm, searchType)

  while (msdnUrl is None):
    # Try again, in case underscores are causing trouble
    if (searchTerm.startswith('_')):
      searchTerm = searchTerm[1:]
      print '(msdnGrab) Using search term: %s' % searchTerm
      msdnUrl = grabMsdnPageFromGoogle(searchTerm, searchType)
    else:
      print '(msdnGrab) Error: Could not find a suitable MSDN page.'
      return None

  # Read the page
  opener = urllib2.build_opener()
  opener.addheaders = [('User-agent', 'Mozilla/5.0')]
  page = opener.open(msdnUrl).read()
  page = page.replace('\xc2\xa0', ' ')
  soup = bs4.BeautifulSoup(page)

  # Find the first (code) definition
  dbgPrint('Searching for code...')
  code = 'No code found.'
  for code in soup.findAll('pre'):
    code = stripBlankLines(stripTags(code))
    dbgPrint('Code found: \n%s' % code)
    if (code != ''):
      break
  code = code.replace('\r', '')

  # Find the description
  dbgPrint('Searching for description...')
  desc = 'No description found.'
  for desc in soup.findAll('p'):
    desc = stripBlankLines(stripTags(desc)).strip()
    dbgPrint('Description found: \n%s' % desc)
    if (desc != '' and 
        'updated' not in desc.lower() and 
        'applies to' not in desc.lower() and
        'rated this helpful' not in desc.lower() and
        not desc.startswith('[') and not desc.endswith(']')
       ):
      break

  # Pretty format the description
  desc = stripBlankLines(stripTags(desc))

  # Find the actual library call
  codeReferences = list(XrefsFrom(ea, 1))
  if (codeReferences == []):
    nextEa = ea
  else:
    nextEa = codeReferences[0].to

  # Put it as a repeatable comment (don't clobber existing comment)
  print '(msdnGrab) Setting repeatable comment at 0x%s:' % str(hex(nextEa))
  print desc
  print code
  print ''

  if ('data' in idc.SegName(nextEa)):
    '''
    Assume we're in an external library.

    The behavior of GetFunctionCmt() and RptCmt() is different.
    The check for None and '' is for robustness, although it looks
    quirky. Handles both cases. Nothing will fail otherwise,
    just that the output will have a double line space when
    it's not needed.
    '''
    existingComment = idc.RptCmt(nextEa)
    if (existingComment is None or existingComment == ''):
      existingComment = ''
    else:
      existingComment = existingComment + '\n\n'

    idc.MakeRptCmt(nextEa, existingComment + multiLineString(desc) + '\n\n' + code)

  else:
    '''
    Assume we're in code.

    The behavior of GetFunctionCmt() and RptCmt() is different.
    The check for None and '' is for robustness, although it looks
    quirky. Handles both cases. Nothing will fail otherwise,
    just that the output will have a double line space when
    it's not needed.

    '''
    existingComment = idc.GetFunctionCmt(nextEa, COMMENT_REPEATABLE)
    if (existingComment is None or existingComment == ''):
      existingComment = ''
    else:
      existingComment = existingComment + '\n\n'

    idc.SetFunctionCmt(nextEa, existingComment + multiLineString(desc) + '\n\n' + code, COMMENT_REPEATABLE)

  # Refresh the screen
  idc.Refresh()


###############################################################################
# Register hotkey
###############################################################################

if __name__ == "__main__":
  # Register the hotkeys
  print '(msdnGrab) Press "%s" grab definition from MSDN (for win32 API).' % _MSDN_HOTKEY_WIN32API
  print '(msdnGrab) Press "%s" grab definition from MSDN (for C/C++).' % _MSDN_HOTKEY_C
  print '(msdnGrab) Press "%s" to open MSDN page in browser.' % _MSDN_HOTKEY_BROWSER

  # Add the hotkeys
  idaapi.CompileLine('static __grabDefinitionFromMsdn_win32api() { RunPythonStatement("grabDefinitionFromMsdn(_SEARCHTYPE_WIN32API)"); }')
  idc.AddHotkey(_MSDN_HOTKEY_WIN32API, '__grabDefinitionFromMsdn_win32api')

  idaapi.CompileLine('static __grabDefinitionFromMsdn_c() { RunPythonStatement("grabDefinitionFromMsdn(_SEARCHTYPE_C)"); }')
  idc.AddHotkey(_MSDN_HOTKEY_C, '__grabDefinitionFromMsdn_c')

  idaapi.CompileLine('static __openMsdnPageInBrowser() { RunPythonStatement("openMsdnPageInBrowser()"); }')
  idc.AddHotkey(_MSDN_HOTKEY_BROWSER, '__openMsdnPageInBrowser')

