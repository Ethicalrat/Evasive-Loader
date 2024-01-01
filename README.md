# Evasive-Loader
Evasive loader to bypass AVs/EDR detection

## Features

- <u>RC4 encryption of shellcode</u>
    - The shellcode loader has used Rc4 encryption/decryption with Windows inbuilt Systemfunction032/033
    - Decryption code is included in the project
    - Encryption code is given seperately. Feel free to use your own code to encrypt
      
- <u>Local mapping injection with callback function code execution</u>
    - Local map injection technique used with NtCreateSection + NtMapviewOfSection
      
- <u>Hell's gate implementation with added capability of indirect syscall</u>
    - Original Hell's gate Technique is used to fetch Nt functions - [Hell's Gate Original implementation](https://github.com/am0nsec/HellsGate/tree/master)
    - Indirect syscall cabability added to increase stealth
      
- <u>Custom GetNtdllbase function with API hashing to avoid using GetModuleHandle</u>
    - A custom GetNtdllBase function using PEB walk technique.
    - "Ntdll" is hashed and compared to avoid static detection

## ToDo
- Add ETW bypass code using HW breakpoint

## Usage
- Open the sln file in visual studios
- Edit payload and decryption key and compile the binary
- Requires Visual Studio 2019 and above.

## Credits
- Hell's Gate by @am0nsec and @RtlMateusz
- @mr.d0x @NUL0x4C and @5pider for the awesome [Maldev academy] (https://maldevacademy.com/)
  
###!!! For Educational Purpose Only !!!
