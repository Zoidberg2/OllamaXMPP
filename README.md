# OllamaXMPP

## Description
This Python script enables communication between any compatible Ollama model and an XMPP server. To use it:
1. Start by running `ollama serve` to activate your Ollama model.
2. Launch the script separately.
3. Begin chatting with your bot, which will act as a bridge between you and the Ollama model.

The script supports multiple communication methods:
- **Plaintext**: Likely works with all XMPP servers and clients.
- **OMEMO** (Tested with Conversations and Gajim).
- **OpenPGP** (XEP-0027, tested with Conversations).

---

## Usage
Edit the botconfig.ini with the parameters<br>
1.Credentials for the XMPP server(JID and Password),<br>
2.allowed_users = The code will only allow those on this list to interact with the Ollama model.<br>
3.keys_directory = Any path that is writable for the user running the script. The code is supposed to generate a new openPGP key and place the public key here.<br> 
4.contacts_keys_directory = Any path that is writable for the user running the script. The code will automatically store the public keys of the contacts here.<br>
To run the script, simply execute:<br>

```bash
python3 ollamaxmpp.py
```

For OpenPGP setup(Client side):
1. Copy your public key as plaintext.(the bot will not deal with files).
2. Send it to the bot in a chat window.(Also as a plaintext).
3. The bot will respond with its own keys.

---
                
## Installation
It is advisable to install the dependencies and run the code in a Python virtual environment for isolation. 
### Prerequisites
Ensure Python is installed on your system. You can download it from [Python.org](https://www.python.org/).

### Dependencies
Install the required libraries using pip:

```bash
pip install langchain_ollama slixmpp-omemo python-gnupg
```
```bash
pip install slixmpp==1.8.6
```
### Known issues
This code is only tested with slixmpp 1.8.6.<br>
As of yet you gonna need to manually create the directories for keys and contact keys.

### Special Thanks to
Mr Dele Olajide https://github.com/deleolajide, who inspired me the idea of a LLM XMPP connection with his Openfire Llama plugin.<br>      
Slixmpp team https://codeberg.org/poezio/slixmpp, for creating and maintaining the slixmpp project. <br>
Syndace https://github.com/Syndace, for the slixmpp-omemo plugin. <br>
Holger Weiss https://github.com/weiss, for helping me understand better XMPP specs. <br>

