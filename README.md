# Analysis_scripts
Collection of my scripts and IDA scripts to boost my malware analysis productivity.

## funccall_highlighter.py
An IDA Pro plugin that highlights function calls within the Graph/Linear view and Hex-Rays pseudocode view, enabling better readability for function pointer and function call identification which assist you to focus only on the function call while analyze the code.

### Prerequisites
- IDA Pro 7.x or later with the Hex-Rays decompiler plugin installed (for the pseudocode highlighter).
- Python 3.x compatible with IDA Pro.

### Installation
- Copy `funccall_highlighter.py` into `C:\path\to\IDA Pro\plugins\`. For example `C:\Program Files\IDA Pro 8.3\plugins\`
- Restart IDA Pro if needed

### Usage
Via right-click menu:

![image](https://github.com/user-attachments/assets/6443cb02-d958-47b7-bfbb-8f7c18094f3c)

Via hotkey:
- `Ctrl + Alt + H`: Enable function call highlighting in the pseudocode view.
- `Ctrl + Alt + D`: Disable function call highlighting in the pseudocode view.
- `Ctrl + Alt + G`: Enable function call highlighting in the Graph/Linear views.
- `Ctrl + Alt + L`: Disable function call highlighting in the Graph/Linear views.

Before and after:

![ida64_FxpNTB6JYF](https://github.com/user-attachments/assets/d5456fe2-4b24-4834-9e93-ee470e1e5043)

![ida64_a98qM7lfUH](https://github.com/user-attachments/assets/f13c2511-c698-4fed-8fcc-6e4d86f0100a)
