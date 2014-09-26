OS/2 32bit EXE fixer for Watcom C/C++ v11.0x
--------------------------------------------

Things to keep in mind:
-----------------------

You will use this product at your own risk, author of this
program is not responsible for possible damage what was caused
by use of this program. Orginally this package was intented to
be given of developers of Watcom C/C++, but their support was
death and I didn't get reply form them. So now I announced this
product to public (let's hope developers of Watcom C/C++ will
found this package now and fix problem with linker)



So what's in this package:
--------------------------

Files that I have included:

common.h            common definations 
defines.h           defines for this app
make.cmd            makefile launcher batch
makefile            makefile
maketest.cmd        batch which makes example program
readme              this readme
test.c              example program
test.exe            pre compiled example program
watfix.c            source code of fixer
watfix.exe          fixer
watfix.lnk          linking information

As you see there is test.exe which demonstrates problem with
Watcom C/C++ & 16-bit DLL's. First check test.c what example
program is suppose to do and then just run it and check results.
If there was problem with it then run: watfix.exe test.exe
And then check results again, problem should be fixed now.



Source code:
------------

To compile whole source code you will need Watcom C/C++ v11.0x and
linker from Watcom C/C++ v10.6. Sorry about not well documented source
but I created this app in hurry.



Contacting to author:
---------------------

Please tell me about your succes with this application. If you have
some questions about my source code or something please contact me
with email:

vesa.jaaskelainen@kouvola.ksaok.fi
