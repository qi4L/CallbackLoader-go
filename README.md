According to Microsoft, a callback function is code in a managed application that helps unmanaged DLL functions complete tasks. The call to a callback function is passed indirectly from the managed application through the DLL function back to the managed implementation. This repository contains a list of callback functions that can be used to execute position-independent shellcode, making CreateThread a thing of the past.

There are more callback functions that can act as loaders, such as HTTP callback functions, but where specifically to place the shellcode and what the calling process entails is something to be explored on one's own.

