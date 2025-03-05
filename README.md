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
Edit the botconfig.ini with the parameters
Credentials for the XMPP server(JID and Password),
allowed_users = The code will only allow those on this list to interact with the Ollama model.
keys_directory = Any path that is writable for the user running the script. The code is supposed to generate a new key and place the public key here. 
contacts_keys_directory = Any path that is writable for the user running the script. The code will automatically store the public keys of the contacts here.
To run the script, simply execute:

```bash
python3 ollamaxmpp.py
```

For OpenPGP setup(Client side):
1. Copy your public key as plaintext.
2. Send it to the bot in a chat window.
3. The bot will respond with its own keys.

---

## Installation

### Prerequisites
Ensure Python is installed on your system. You can download it from [Python.org](https://www.python.org/).

### Dependencies
Install the required libraries using pip:

```bash
pip install langchain_ollama slixmpp slixmpp-omemo python-gnupg
```
