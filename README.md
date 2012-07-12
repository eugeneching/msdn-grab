msdnGrab
========

Allows a user to grab documentation from online MSDN for a given function name in IDA, and import the documentation as a repeatable comment for that function. Handles queries for the Win32 API and C/C++.

___

### Usage:
  1 Highlight a given term that you want to query documentation for (e.g. you may highlight "fopen", "HeapAlloc").
  2 Decide whether that is a Win32 API function, or a C/C++ function (i.e. CRT).
  3 If it's a Win32 API function, hit F3, and if it's a C/C+ function, hit Ctrl-F3.
  4 The results should populate as a repeating comment.

### Notes about comments

  1 If it's an external library call (i.e. function is an extern in the data segment), a (code) repeating comment is used.
  2 If it's a direct call (i.e. function is in the code segment), a (function) repeating comment is used.

  P/S: I am using the words external and direct calls very loosely.

