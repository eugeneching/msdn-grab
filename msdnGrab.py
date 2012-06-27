###############################################################################
# MSDN Grab
#
# Allows a user to grab documentation from online MSDN for a given function
# name in IDA, and import the documentation as a repeatable comment for that
# function.
#
# The script assumes that the function name is valid, and queries Google for
# the MSDN page. It then pulls the short description of the function, and
# the function definition into the comment.
#
# Usage:
#
#   Hotkey for MSDN grab: F3
#   Highlight a function (e.g. CreateFileA) in IDA, and hit F3.
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


###############################################################################
# Globals
###############################################################################

_MSDN_HOTKEY        = 'F3'
COMMENT_REPEATABLE  = 1
MAX_COMMENT_WIDTH   = 50


###############################################################################
# Helper functions
###############################################################################

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

def grabMsdnPageFromGoogle(searchTerm):
  # Get the Google URL
  googleUrl='http://www.google.com/search?hl=en&q=%s+function+msdn+desktop+apps&sa=N&safe=off&filter=0' % searchTerm

  # Read the page
  opener = urllib2.build_opener()
  opener.addheaders = [('User-agent', 'Mozilla/5.0')]
  page = opener.open(googleUrl).read()
  soup = bs4.BeautifulSoup(page)

  # Extract the first MSDN link
  links = soup.findAll('a')
  msdnLinks = [re.search('http://msdn.microsoft.com/(.*?)&', str(link)) for link in soup.find_all('a') if ('msdn.microsoft.com' in str(link))]
  try:
    msdnUrl = 'http://msdn.microsoft.com/' + msdnLinks[0].group(1)
  except:
    msdnUrl = None

  # Return the first link
  return msdnUrl


###############################################################################
# Search MSDN page for definition
###############################################################################

def grabDefinitionFromMsdn():
  # Get the highlighted identifier
  searchTerm = idaapi.get_highlighted_identifier()

  # Get the address
  ea = ScreenEA()

  # Make sure we have something highlighted
  if not searchTerm:
    print "(msdn_grab) No identifier to use as search term was highlighted."
    return None

  # Handle IDA's naming conventions for the identifier
  searchTerm = searchTerm.replace('__imp_', '')

  # Get the MSDN page URL
  msdnUrl = grabMsdnPageFromGoogle(searchTerm)

  # Read the page
  opener = urllib2.build_opener()
  opener.addheaders = [('User-agent', 'Mozilla/5.0')]
  page = opener.open(msdnUrl).read()
  page = page.replace('\xc2\xa0', ' ')
  soup = bs4.BeautifulSoup(page)

  # Find the first definition
  code = soup.findAll('pre')[0]
  code = stripBlankLines(stripTags(code))

  # Find the description
  desc = soup.findAll('p')[1]
  desc = stripBlankLines(stripTags(desc))

  # Find the actual library call
  nextEa = ea
  codeReferences = list(CodeRefsFrom(nextEa, 0))
  while not (codeReferences == []):
    nextEa = codeReferences[0]
    codeReferences = list(CodeRefsFrom(nextEa, 0))

  # Put it as a repeatable comment (don't clobber existing comment)
  print '(msdn_grab) Setting function command at 0x%s:' % str(hex(nextEa))
  print code

  existingComment = GetCommentEx(nextEa, COMMENT_REPEATABLE)
  if (existingComment is None):
    existingComment = ''
  else:
    existingComment = existingComment + '\n\n'

  idc.MakeRptCmt(nextEa, existingComment + multiLineString(desc) + '\n\n' + code)
  idc.Refresh()


###############################################################################
# Register hotkey
###############################################################################

if __name__ == "__main__":
  # Register the hotkeys
  print '(msdn_grab) Press "%s" grab definition from MSDN.' % _MSDN_HOTKEY

  # Add the hotkeys
  idaapi.CompileLine('static __grabDefinitionFromMsdn() { RunPythonStatement("grabDefinitionFromMsdn()"); }')
  idc.AddHotkey(_MSDN_HOTKEY, '__grabDefinitionFromMsdn')


