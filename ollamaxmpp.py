from argparse import ArgumentParser
from getpass import getpass
import json
import logging
import sys
from typing import Any, Dict, FrozenSet, Literal, Optional, Union
from langchain_ollama import OllamaLLM
from omemo.storage import Just, Maybe, Nothing, Storage
from omemo.types import DeviceInformation, JSONType
from slixmpp import JID
from slixmpp.clientxmpp import ClientXMPP
from slixmpp.plugins import register_plugin
from slixmpp.stanza import Message
from slixmpp.xmlstream.handler import CoroutineCallback
from slixmpp.xmlstream.matcher import MatchXPath
import traceback
from slixmpp_omemo import TrustLevel, XEP_0384
from xml.etree import ElementTree as ET
import asyncio
from slixmpp.xmlstream.stanzabase import StanzaBase
from slixmpp.xmlstream import register_stanza_plugin
import slixmpp
from slixmpp.plugins.xep_0027 import Encrypted
from slixmpp.exceptions import IqError, IqTimeout
import gnupg
import subprocess
import os
from configparser import ConfigParser
import re
# Set up logging
logging.basicConfig(level=logging.INFO)
RED = '\033[91m'
RESET = '\033[0m'

def create_dummy_config():
    config = ConfigParser()
    config['credentials'] = {
        'jid': 'bot@example.com',
        'password': 'Password'
    }
    config['users'] = {
        'allowed_users': 'user1@example.com/resource,user2@example.com/resource,user3@example.com/resource'
    }
    config['server'] = {
        'llama_server_url': 'http://localhost:11434'
    }
    config['muc'] = {
        'room': 'roomid@conference.example.com',
        'nick': 'bot'
    }
    config['keys'] = {
        'keypasswd': 'none',
        'keys_directory': '/path/to/keys',
        'contacts_keys_directory': '/path/to/contact_keys',
        'public_key_file': 'public_key.asc'
    }
    config['llm'] = {
        'model': 'deepseek-r1:7b',
        'prompt': 'You are a very helpful assistant, you are a conversational AI model. You will be having a conversation with an user.',
        'device': 'gpu',
        'num_gpu': '1',
        'num_thread': '8',
        'batch_size': '32',
        'quantization_mode': 'int8',
        'cache_type': 'redis',
        'cache_capacity': '10gb',
        'compute_type': 'float16',
        'tensor_parallel': 'True'
    }

    with open('botconfig.ini', 'w') as configfile:
        config.write(configfile)
        configfile.write("""
    # [OMEMOStorage]
    # json_file = /path/to/omemo-echo-client.json
    """)

    print(f"{RED}Created dummy 'botconfig.ini' file with example values.{RESET}")
    print(f"{RED}Config file did not exist, we just created one. Please fill in the botconfig.ini file with the necessary parameters.{RESET}")
    sys.exit(0)

def generate_keys(keys_directory, public_key_file, nick, jid):
    """Generate a new OpenPGP key pair and save the public key to the specified directory"""
    gpg = gnupg.GPG()

    # Define the key parameters
    key_params = gpg.gen_key_input(
        key_type="RSA",
        key_length=4096,
        name_real=nick,
        name_email=jid,
        name_comment="OpenPGP Key",
        passphrase=keypasswd
    )

    # Generate the key
    key = gpg.gen_key(key_params)

    if not key:
        raise ValueError("Failed to generate key")

    # Export the public key
    public_key = gpg.export_keys(key.fingerprint)
    public_key_path = os.path.join(keys_directory, public_key_file)

    os.makedirs(keys_directory, exist_ok=True)

    with open(public_key_path, "w") as f:
        f.write(public_key)

    logging.debug(f"Keys generated and saved to the directory: {public_key_path}")
    return public_key_path, key.fingerprint

class EncryptionInfo(StanzaBase):
    name = 'encryption'
    namespace = 'urn:xmpp:eme:0'
    plugin_attrib = 'encryption'
    interfaces = {'namespace'}

    def setup(self, xml):
        super(EncryptionInfo, self).setup(xml)
        self.xml.tag = self.tag_name()

class StorageImpl(Storage):

    def __init__(self) -> None:
        super().__init__()

        # Get the directory of the script file
        script_dir = os.path.dirname(os.path.abspath(__file__))
        default_path = os.path.join(script_dir, 'omemo-echo-client.json')

        # Read the configuration file
        config = ConfigParser()
        config.read('botconfig.ini')

        # Get the JSON file path from the configuration or use the default path
        self.JSON_FILE = config.get('Storage', 'json_file', fallback=default_path)

        self.__data: Dict[str, JSONType] = {}
        try:
            with open(self.JSON_FILE, encoding="utf8") as f:
                self.__data = json.load(f)
        except Exception:
            pass

    async def _load(self, key: str) -> Maybe[JSONType]:
        if key in self.__data:
            return Just(self.__data[key])

        return Nothing()

    async def _store(self, key: str, value: JSONType) -> None:
        self.__data[key] = value
        with open(self.JSON_FILE, "w", encoding="utf8") as f:
            json.dump(self.__data, f)

    async def _delete(self, key: str) -> None:
        self.__data.pop(key, None)
        with open(self.JSON_FILE, "w", encoding="utf8") as f:
            json.dump(self.__data, f)

class XEP_0384Impl(XEP_0384):
    """
    Example implementation of the OMEMO plugin for Slixmpp.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # Just the type definition here
        self.__storage: Storage

    def plugin_init(self) -> None:
        self.__storage = StorageImpl()

        super().plugin_init()

    @property
    def storage(self) -> Storage:
        return self.__storage

    @property
    def _btbv_enabled(self) -> bool:
        return True

    async def _devices_blindly_trusted(
        self,
        blindly_trusted: FrozenSet[DeviceInformation],
        identifier: Optional[str]
    ) -> None:
        logging.info(f"[{identifier}] Devices trusted blindly: {blindly_trusted}")

    async def _prompt_manual_trust(
        self,
        manually_trusted: FrozenSet[DeviceInformation],
        identifier: Optional[str]
    ) -> None:
        # Since BTBV is enabled and we don't do any manual trust adjustments in the example, this method
        # should never be called. All devices should be automatically trusted blindly by BTBV.

        # To show how a full implementation could look like, the following code will prompt for a trust
        # decision using `input`:
        session_mananger = await self.get_session_manager()

        for device in manually_trusted:
            while True:
                answer = input(f"[{identifier}] Trust the following device? (yes/no) {device}")
                if answer in { "yes", "no" }:
                    await session_mananger.set_trust(
                        device.bare_jid,
                        device.identity_key,
                        TrustLevel.TRUSTED.value if answer == "yes" else TrustLevel.DISTRUSTED.value
                    )
                    break
                print("Please answer yes or no.")

register_plugin(XEP_0384Impl)

class OllamaEncrypted(ClientXMPP):

    def __init__(self, jid, password, room, nick, allowed_users, openpgp_key, fingerprint) -> None:
        super().__init__(jid, password)
        self.allowed_users = []
        for user in allowed_users:
            try:
                jid_obj = JID(user)
                self.allowed_users.append(jid_obj)
            except ValueError as e:
                logging.error(f"Invalid JID: {user} - {e}")
        self.llama_server_url = llama_server_url
        self.llm = OllamaLLM(model=config.get('llm', 'model'))
        self.prompt = config.get('llm', 'prompt')
        self.room = room
        self.nick = nick
        self.jid = jid
        self.fingerprint = fingerprint
        self.add_event_handler("session_start", self.start)
        self.register_handler(CoroutineCallback(
            "Messages",
            MatchXPath(f"{{{self.default_ns}}}message"),
            self.message_handler  # type: ignore[arg-type]
        ))
        self.sent_stanza_id = None
        self.sent_message_ids = set()
        self.public_key_path = public_key_path
        self.gpg = gnupg.GPG()
        self.contacts_keys_directory = contacts_keys_directory
        self.keypasswd = keypasswd
        register_stanza_plugin(slixmpp.Message, Encrypted)
        register_stanza_plugin(slixmpp.Message, EncryptionInfo)
        self.register_plugin('xep_0172')
    async def start(self, _event: Any) -> None:
        self.send_signed_presence()
        muc_jid = self.room
        self.add_event_handler("disconnected", self.on_disconnect)
        self.affiliations = await self.get_muc_affiliations(muc_jid)
        logging.info(f"Affiliations in {muc_jid}: {self.affiliations}")

        logging.info("Session started")
        try:
            await self.get_roster()
            logging.info("Roster retrieved")
        except Exception as e:
            logging.error(f"Error retrieving roster: {e}")

        try:
            self.send_presence()
            logging.info("Presence sent")
        except Exception as e:
            logging.error(f"Error sending presence: {e}")

        try:
            logging.info(f"Joining MUC room: {self.room} with nickname: {self.nick}")
            self.plugin['xep_0045'].join_muc(self.room,
                                             self.nick,
                                             # If a room password is needed, use:
                                             # password=the_room_password,
                                             )
            logging.info("MUC room join request sent")
        except Exception as e:
            logging.error(f"Error joining MUC room: {e}")
            if isinstance(e, PresenceError):
                logging.error("Presence error")
            elif isinstance(e, TimeoutError):
                logging.error("Timeout error")
            else:
                logging.error(f"Unknown error: {e}")

        except Exception as e:
            logging.error(f"Error joining MUC room: {e}")

    async def on_disconnect(self, event):
        print("Bot disconnected, retrying in 10 seconds...")
        await asyncio.sleep(10)
        await self.connect()
     
    async def get_muc_affiliations(self, muc_jid):
        """Retrieve the affiliations from a MUC room."""
        owner_list = []
        admin_list = []
        member_list = []
        moderator_list = []

        events = [asyncio.Event() for _ in range(4)]

        def iq_callback(iq, affiliation_list, event):
            nonlocal owner_list, admin_list, member_list, moderator_list
            for item in iq.xml.find('.//{http://jabber.org/protocol/muc#admin}query'):
                jid = item.get('jid')
                if jid != self.boundjid.bare:  # exclude the bot itself
                    affiliation_list.append(jid)
            event.set()

        owner_iq = self.Iq()
        owner_iq['type'] = 'get'
        owner_iq['to'] = muc_jid
        owner_query = ET.Element('{http://jabber.org/protocol/muc#admin}query')
        owner_item = ET.SubElement(owner_query, 'item')
        owner_item.set('affiliation', 'owner')
        owner_iq.append(owner_query)
        owner_iq.send(callback=lambda iq: iq_callback(iq, owner_list, events[0]))

        admin_iq = self.Iq()
        admin_iq['type'] = 'get'
        admin_iq['to'] = muc_jid
        admin_query = ET.Element('{http://jabber.org/protocol/muc#admin}query')
        admin_item = ET.SubElement(admin_query, 'item')
        admin_item.set('affiliation', 'admin')
        admin_iq.append(admin_query)
        admin_iq.send(callback=lambda iq: iq_callback(iq, admin_list, events[1]))

        member_iq = self.Iq()
        member_iq['type'] = 'get'
        member_iq['to'] = muc_jid
        member_query = ET.Element('{http://jabber.org/protocol/muc#admin}query')
        member_item = ET.SubElement(member_query, 'item')
        member_item.set('affiliation', 'member')
        member_iq.append(member_query)
        member_iq.send(callback=lambda iq: iq_callback(iq, member_list, events[2]))

        moderator_iq = self.Iq()
        moderator_iq['type'] = 'get'
        moderator_iq['to'] = muc_jid
        moderator_query = ET.Element('{http://jabber.org/protocol/muc#admin}query')
        moderator_item = ET.SubElement(moderator_query, 'item')
        moderator_item.set('role', 'moderator')
        moderator_iq.append(moderator_query)
        moderator_iq.send(callback=lambda iq: iq_callback(iq, moderator_list, events[3]))

        await asyncio.gather(*[event.wait() for event in events])

        affiliations = owner_list + admin_list + member_list + moderator_list
        return affiliations

    async def message_handler(self, stanza: Message) -> None:
        config = ConfigParser()
        config.read('botconfig.ini')
        config = {
            "model": config.get('llm', 'model'),
            "prompt": config.get('llm', 'prompt'),
            "device": {
            "device": config.get('llm', 'device'),
                "num_gpu": config.getint('llm', 'num_gpu'),
                "num_thread": config.getint('llm', 'num_thread')
                },
            "batch": {
                "batch_size": config.getint('llm', 'batch_size')
                },
            "quantization": {
                "mode": config.get('llm', 'quantization_mode')
                },
            "cache": {
                "type": config.get('llm', 'cache_type'),
                "capacity": config.get('llm', 'cache_capacity')
                },
            "runtime": {
                "compute_type": config.get('llm', 'compute_type'),
                "tensor_parallel": config.getboolean('llm', 'tensor_parallel')
                }
            }        
        
        if stanza["id"] in self.sent_message_ids:
            return

        if not stanza["body"]:
            return
        if stanza["from"] == self.jid:
            return
        if stanza["from"] not in self.allowed_users:
            logging.info(f"Received message from unauthorized user {stanza['from']}")
            return
        xep_0384: XEP_0384 = self["xep_0384"]
        prompt = self.prompt
        mfrom = stanza["from"].bare
        mto = stanza["from"]
        mtype = stanza["type"]
        msg = stanza
        logging.debug(f"mtype: {mtype} (type: {type(mtype)})")
        if mtype not in {"groupchat", "chat", "normal"}:
            logging.debug("Filtering out message")
            return
        logging.info(f"Allowing message with type: {mtype},Waiting for Ollama response.")

        namespace = xep_0384.is_encrypted(stanza)

        if namespace == 'eu.siacs.conversations.axolotl':
            logging.debug("OMEMO Encrypted message detected")
            try:
                decrypted_message, sender_jid = await xep_0384.decrypt_message(stanza)
                logging.debug(f"Decrypted message type: {type(decrypted_message)}")
                logging.debug(f"Decrypted message: {decrypted_message}")
                if isinstance(decrypted_message, dict):
                    user_input = decrypted_message.get("body", "")
                    logging.debug(f"User input (dict): {user_input}")
                elif isinstance(decrypted_message, Message):
                    user_input = decrypted_message["body"]
                    logging.debug(f"User input (Message): {user_input}")
                else:
                    user_input = str(decrypted_message)
                    logging.debug(f"User input (other): {user_input}")

                if mtype == "groupchat":
                    # Get the MUC room and sender's nick
                    muc_room = stanza["from"]
                    logging.debug(f"MUC room: {muc_room}")
                    room_jid = stanza["from"].bare
                    prompt += f"\nUser: {user_input}"
                    logging.debug(f"{user_input}: {prompt}")
                    try:
                        # Generate response using the AI model
                        response = self.llm.invoke(prompt, config=config)
                        logging.debug(f"Response generated for {mfrom}: {response}")
                    except Exception as e:
                        logging.error(f"Ollama did not respond: {e}")
                        response = "Ollama did not respond. Please try again later."                    
                    logging.debug("Encrypting response...")
                    muc_room_jid = stanza["from"].bare  # Get the room JID from the 'from' attribute
                    logging.debug("MUC room JID: %s", muc_room_jid)

                    if self.boundjid.bare + "/" + self.boundjid.resource in self.affiliations:
                        device_list.remove(self.boundjid.bare + "/" + self.boundjid.resource)

                    message = self.make_message(mto=muc_room_jid, mtype="groupchat")
                    message["body"] = response
                    message.set_to(muc_room_jid)
                    message.set_from(self.boundjid)

                    try:
                        logging.debug("Encrypting message with xep_0384...")
                        messages, encryption_errors = await xep_0384.encrypt_message(message, [JID(jid) for jid in self.affiliations])
                        if len(encryption_errors) > 0:
                            logging.warning(f"There were non-critical errors during encryption: {encryption_errors}")

                        for namespace, encrypted_message in messages.items():
                            encrypted_message["eme"]["namespace"] = namespace
                            encrypted_message["eme"]["name"] = self["xep_0380"].mechanisms[namespace]
                            encrypted_message.send()

                            # Keep track of the stanza_id of the sent message
                            self.sent_message_ids.add(message["id"])
                    except Exception as e:
                        logging.error(f"Error encrypting or sending message: {e}")
                        logging.error(f"Exception traceback: {traceback.format_exc()}")

                elif mtype == "chat":
                    user_input = decrypted_message.get("body", "")
                    prompt += f"\nUser: {user_input}"
                    mfrom = stanza["from"]
                    logging.debug(f"Conversation history for user {mfrom}: {prompt}")
                    try:
                        # Generate response using the AI model
                        response = self.llm.invoke(prompt, config=config)
                        logging.debug(f"Response generated for {mfrom}: {response}")
                    except Exception as e:
                        logging.error(f"Ollama did not respond: {e}")
                        response = "Ollama did not respond. Please try again later."
                    logging.debug(f"Sending prompt to LLaMA: {prompt}")
                    logging.debug(f"Received response from LLaMA: {response}")
                    await self.encrypted_reply(mto, mtype, response)

            except Exception as e:
                logging.error(f"Error: {e}")
                return

        #Here we deal with PGP encrypted(XEP-0027)messages.
        x_element = msg.xml.find('{jabber:x:encrypted}x')

        if x_element is not None:

            logging.debug("Encrypted message detected")
            encrypted_data = x_element.text
            logging.debug(f"Encrypted data: {encrypted_data}")

            # Add the necessary headers to the encrypted data
            encrypted_data_with_headers = f"-----BEGIN PGP MESSAGE-----\n{encrypted_data}\n-----END PGP MESSAGE-----"
            logging.debug(f"Encrypted data with headers: {encrypted_data_with_headers}")

            decrypted_data = await self.decrypt_message(encrypted_data_with_headers)

            user_input = decrypted_data
            logging.debug(f"user_input")

            mtype = stanza['type']
            mto = stanza['to']

            if mtype == "chat":
                # Create prompt that teaches the AI to recognize its name and answer the last question
                prompt += f"\nUser: {user_input}"
                logging.debug(f"Sending prompt to LLaMA: {prompt}")
                try:
                    # Generate response using the AI model
                    response = self.llm.invoke(prompt, config=config)
                    logging.debug(f"Response generated for {mfrom}: {response}")
                except Exception as e:
                    logging.error(f"Ollama did not respond: {e}")
                    response = "Ollama did not respond. Please try again later."
                logging.debug(f"Response generated for {mfrom}: {response}")

                # Get the recipient's public key file
                recipient_bare_jid = mfrom
                recipient_key_file = f'{self.contacts_keys_directory}/{recipient_bare_jid}.asc'

                # Ensure the key file exists
                if not os.path.exists(recipient_key_file):
                    logging.error(f"Public key file not found for {recipient_bare_jid}: {recipient_key_file}")
                    return

                try:
                    # Encrypt the message using the recipient's public key file
                    encrypted_message = self.encrypt_message(response, [recipient_key_file])

                    # Strip PGP headers and footers
                    encrypted_message = self.strip_pgp_headers(encrypted_message)

                    # Use the full JID for sending the message
                    recipient_full_jid = mfrom.full

                    msg = self.make_message(mto=recipient_full_jid, mtype=mtype)

                    # Add the encrypted data directly to the <x> element
                    encrypted = ET.Element('x', {'xmlns': 'jabber:x:encrypted'})
                    encrypted.text = encrypted_message
                    msg.append(encrypted)

                    # Add the <body> element for fallback
                    fallback_message = "I sent you a PGP encrypted message but your client doesn’t seem to support that."
                    msg['body'] = fallback_message

                    # Send the encrypted message
                    msg.send()
                    self.sent_message_ids.add(msg["id"])
                    logging.debug(f"message id: {stanza['id']}")
                    logging.info(f"Encrypted message sent successfully to {recipient_full_jid}")
                    print(f"Encrypted message sent to {recipient_full_jid}.")
                    print(f"Encrypted message: {encrypted_message}")
                except Exception as e:
                    logging.error(f"Failed to send encrypted message to {recipient_full_jid}: {e}")

            elif mtype == "groupchat":
                muc_jid = stanza["from"].bare
                muc_room = stanza["from"].resource

                # Get the JIDs of all participants in the MUC
                participants = await self.get_muc_affiliations(muc_jid)

                # Ensure there are participants to send the message to
                if not participants:
                    logging.warning(f"No participants found in the MUC room {muc_jid}key_directory")
                    return

                # Generate the response using the AI model
                prompt += f"\nUser: {user_input}"
                logging.debug(f"Sending prompt to LLaMA: {prompt}")
                try:
                    # Generate response using the AI model
                    response = self.llm.invoke(prompt, config=config)
                    logging.debug(f"Response generated for {mfrom}: {response}")
                except Exception as e:
                    logging.error(f"Ollama did not respond: {e}")
                    response = "Ollama did not respond. Please try again later."
                logging.debug(f"Response generated for MUC {muc_jid}: {response}")

                # Collect the public key files for all participants
                recipient_key_files = []
                for participant_jid in participants:
                    if participant_jid is None:
                        logging.warning(f"Skipping participant with None JID")
                        continue

                    recipient_key_file = f'{self.contacts_keys_directory}/{participant_jid}.asc'
                    recipient_key_files.append(recipient_key_file)

                # Encrypt the message for all participants at once
                try:
                    encrypted_message = self.encrypt_message(response, recipient_key_files)
                    encrypted_message = self.strip_pgp_headers(encrypted_message)
                except Exception as e:
                    logging.error(f"Failed to encrypt message for MUC {muc_jid}: {e}")
                    return

                try:
                    # Create the message stanza with the combined encrypted payload
                    msg = self.Message()
                    msg['to'] = muc_jid
                    msg['type'] = 'groupchat'

                    # Add the encrypted data directly to the <x> element
                    encrypted = ET.Element('x', {'xmlns': 'jabber:x:encrypted'})
                    encrypted.text = encrypted_message
                    msg.append(encrypted)

                    # Add the <body> element for fallback
                    msg['body'] = "I sent you a PGP encrypted message but your client doesn’t seem to support that."

                    # Send the combined encrypted message to the MUC
                    msg.send()
                    self.sent_message_ids.add(msg["id"])
                    logging.debug(f"message id: {stanza['id']}")
                    logging.info(f"Combined encrypted message sent successfully to MUC {muc_jid}")
                    print(f"Combined encrypted message sent to MUC {muc_jid}.")
                    print(f"Combined encrypted message: {encrypted_message}")
                except Exception as e:
                    logging.error(f"Failed to send combined encrypted message to MUC {muc_jid}: {e}")

        #Here we deal with PlainText
        else:
            logging.debug("Plain message detected")
            if stanza["type"] in {"groupchat", "chat", "normal"}:

                # Check for PGP public key messages
                if re.search(r"-----BEGIN PGP PUBLIC KEY BLOCK-----", stanza["body"]) and re.search(r"-----END PGP PUBLIC KEY BLOCK-----", stanza["body"]):
                    self.handle_pgp_public_key(stanza)
                    return

                if stanza["body"] == "You received a message encrypted with OMEMO but your client doesn't support OMEMO.":
                    return

                if "I sent you an OMEMO encrypted message" in stanza["body"]:
                    return

                user_input = stanza["body"]
                logging.debug(f"User input (unencrypted): {user_input}")
                # Get the MUC room and sender's nick
                muc_room = stanza["from"]
                room_jid = stanza["from"].bare
                logging.debug(f"MUC room: {muc_room}")
                if stanza["from"] not in self.allowed_users:
                    logging.warning(f"Received message from unauthorized user {stanza['from']}")
                    return

                if mtype == "groupchat":
                    # Create prompt that teaches the AI to recognize its name and answer the last question
                    prompt += f"\nUser: {user_input}"
                    logging.debug(f"Sending prompt to LLaMA: {prompt}")
                    try:
                        # Generate response using the AI model
                        response = self.llm.invoke(prompt, config=config)
                        logging.debug(f"Response generated for {mfrom}: {response}")
                    except Exception as e:
                        logging.error(f"Ollama did not respond: {e}")
                        response = "Ollama did not respond. Please try again later."                    
                    logging.debug("Sending response unencrypted")
                    muc_room_jid = room
                    message = self.make_message(mto=muc_room_jid, mtype="groupchat")
                    message["body"] = response
                    message.set_to(muc_room_jid)
                    message.set_from(self.boundjid)
                    message.send()
                    self.sent_message_ids.add(message["id"])
                    logging.debug(f"message id: {message["id"]}")

                if mtype == "chat":
                    user_input = stanza['body']
                    prompt += f"\nUser: {user_input}"
                    logging.debug(f"Sending prompt to LLaMA: {prompt}")
                    try:
                        # Generate response using the AI model
                        response = self.llm.invoke(prompt, config=config)
                        logging.debug(f"Response generated for {mfrom}: {response}")
                    except Exception as e:
                        logging.error(f"Ollama did not respond: {e}")
                        response = "Ollama did not respond. Please try again later."
                    # Send the response back to the user
                    self.plain_reply(mfrom, "chat", response)

    async def encrypted_reply(
        self,
        mto: JID,
        mtype: Literal["chat", "normal"],
        reply: Union[Message, str]
    ) -> None:
        """
        Helper to reply with encrypted messages.

        Args:
            mto: The recipient JID.
            mtype: The message type.
            reply: Either the message stanza to encrypt and reply with, or the text content of the reply.
        """

        xep_0384: XEP_0384 = self["xep_0384"]

        message = self.make_message(mto=mto, mtype=mtype)
        if isinstance(reply, str):
            message["body"] = reply
        else:
            message["body"] = reply["body"]

        message.set_to(mto)
        message.set_from(self.boundjid)

        # It might be a good idea to strip everything but the body from the stanza, since some things might
        # break when echoed.
        messages, encryption_errors = await xep_0384.encrypt_message(message, mto)

        if len(encryption_errors) > 0:
            log.info(f"There were non-critical errors during encryption: {encryption_errors}")

        for namespace, message in messages.items():
            message["eme"]["namespace"] = namespace
            message["eme"]["name"] = self["xep_0380"].mechanisms[namespace]

            # Store the message ID

            message.send()
            self.sent_message_ids.add(message["id"])
            logging.debug(f"Message ID :{message["id"]}")
    def plain_reply(self, mto: JID, mtype: Literal["chat", "normal"], reply: str) -> None:
        """
        Helper to reply with plain messages.

        Args:
            mto: The recipient JID.
            mtype: The message type.
            reply: The text content of the reply.
        """

        stanza = self.make_message(mto=mto, mtype=mtype)
        stanza["body"] = reply

        # Store the message ID

        stanza.send()
        self.sent_message_ids.add(stanza["id"])
        logging.debug(f"Message id: {stanza["id"]}")
    #Encrypting PGP messages
    def encrypt_message(self, message, recipient_key_files):
        try:
            # Run the gpg command to encrypt the message to multiple recipients
            command = ['gpg', '--encrypt', '--armor']
            for key_file in recipient_key_files:
                command.extend(['--recipient-file', key_file])

            # Log the command being executed for debugging
            logging.debug(f"Executing gpg command: {command}")

            result = subprocess.run(
                command,
                input=message.encode('utf-8'),  # Encode the message to bytes
                capture_output=True,
                text=False  # Capture output as bytes
            )

            if result.returncode != 0:
                raise ValueError(f"Encryption failed: {result.stderr.decode('utf-8')}")

            return result.stdout.decode('utf-8')  # Decode the output to a string
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            raise

    def strip_pgp_headers(self, encrypted_message):
        # Remove PGP headers and footers
        lines = encrypted_message.split('\n')
        lines = [line for line in lines if not line.startswith('-----BEGIN PGP MESSAGE-----') and not line.startswith('-----END PGP MESSAGE-----')]
        return '\n'.join(lines).strip()

    async def decrypt_message(self, encrypted_data):
        logging.debug("Attempting to decrypt message")
        # Decrypt the message using GPG
        decrypted = self.gpg.decrypt(encrypted_data, passphrase=self.keypasswd)
        if decrypted.ok:
            logging.debug("Decryption successful")
            logging.debug(f"payload={decrypted}")
            return str(decrypted)
        else:
            logging.error(f"Decryption failed: {decrypted.status}")
            return None


    def send_signed_presence(self):
        # Create a presence stanza
        presence = self.Presence()
        presence['from'] = self.boundjid.bare
        presence['to'] = self.boundjid.bare

        # Add status
        status = "Online"
        presence['status'] = status

        # Log the original presence stanza
        logging.debug(f"Original presence stanza: {ET.tostring(presence.xml)}")

        # Sign the status content
        signed_status = self.sign_status(status)

        # Create the x element with the correct namespace
        x_element = ET.Element('{jabber:x:signed}x')
        x_element.text = signed_status

        # Add the x element to the presence stanza
        presence.xml.append(x_element)

        # Log the signed presence stanza
        logging.debug(f"Signed presence stanza: {ET.tostring(presence.xml)}")

        # Send the signed presence
        presence.send()
        logging.debug(f"Sent signed presence: {ET.tostring(presence.xml)}")

    def sign_status(self, status):
        # Sign the status content
        signed_data = self.gpg.sign(status, keyid=self.fingerprint, passphrase=self.keypasswd, detach=True)
        signed_data_str = str(signed_data)

        # Strip out the PGP signature headers
        signed_data_str = signed_data_str.replace("-----BEGIN PGP SIGNATURE-----", "")
        signed_data_str = signed_data_str.replace("-----END PGP SIGNATURE-----", "")
        signed_data_str = signed_data_str.strip()  # Remove any leading/trailing whitespace

        return signed_data_str
    #this will grab the users public key, and save it at the contacts_keys_directory
    def handle_pgp_public_key(self, stanza):
        user_input = stanza["body"]
        user_jid = stanza["from"].bare
        logging.debug(f"PGP public key detected from {user_jid}: {user_input}")

        # Extract the PGP public key block
        key_data = re.search(r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----", user_input, re.DOTALL)
        if key_data:
            key_data = key_data.group(0)
            key_file_path = os.path.join(contacts_keys_directory, f"{user_jid}.asc")
            logging.debug(f"Extracted PGP public key: {key_data}")

            # Ensure the directory exists
            os.makedirs(os.path.dirname(key_file_path), exist_ok=True)

            # Check if the file already exists
            if os.path.exists(key_file_path):
                logging.debug(f"File {key_file_path} already exists. Overwriting...")

            with open(key_file_path, 'w') as key_file:
                key_file.write(key_data)
                logging.debug(f"PGP public key saved to {key_file_path}")
                
            # Read the bot's public key
            bot_public_key = self.read_bot_public_key()
            if bot_public_key:
                self.plain_reply(user_jid, "chat", f"Your PGP public key has been successfully saved.\n\n I will send you my public key, After receiving it, just copy the text, then on OpenKeychain click on the [+] then [Import from file] then on the [3 dots on the vertical] then [Read from clipboard] Here is my public key:\n{bot_public_key}")
            else:
                self.plain_reply(user_jid, "chat", "Your PGP public key has been successfully saved. However, I encountered an issue reading my own public key.")
        else:
            logging.warning(f"Failed to extract PGP public key from message from {user_jid}")
            self.plain_reply(user_jid, "chat", "Failed to extract PGP public key. Please ensure the key is correctly formatted.")

    #this will help the bot return its own public key to users who sent their pub key first.
    def read_bot_public_key(self):
        try:
            with open(self.public_key_path, 'r') as f:
                bot_public_key = f.read()
                logging.debug(f"Bot's public key: {bot_public_key}")
                self.send_signed_presence()
                return bot_public_key
        except Exception as e:
            logging.error(f"Error reading bot's public key: {e}")
            return None

if __name__ == "__main__":

    # Check if the configuration file exists
    if not os.path.exists('botconfig.ini'):
        create_dummy_config()

    # Read the configuration file
    config = ConfigParser()
    config.read('botconfig.ini')

    # Extract the necessary configuration values
    jid = config.get('credentials', 'jid')
    password = config.get('credentials', 'password')
    allowed_users = config.get('users', 'allowed_users').split(',')
    llama_server_url = config.get('server', 'llama_server_url')
    room = config.get('muc', 'room')
    nick = config.get('muc', 'nick')
    keypasswd = config.get('keys', 'keypasswd')
    keys_directory = config.get('keys', 'keys_directory')
    contacts_keys_directory = config.get('keys', 'contacts_keys_directory')
    public_key_file = config.get('keys', 'public_key_file')
    # Placeholder paths
    PLACEHOLDER_PATHS = ['/path/to/keys', '/path/to/contact_keys']

    # Define default paths
    DEFAULT_KEYS_DIRECTORY = os.path.join(os.getcwd(), 'keys')
    DEFAULT_CONTACTS_KEYS_DIRECTORY = os.path.join(os.getcwd(), 'contact_keys')

    # Get the configuration paths, using defaults if placeholders are found
    keys_directory = config.get('keys', 'keys_directory', fallback=DEFAULT_KEYS_DIRECTORY)
    contacts_keys_directory = config.get('keys', 'contacts_keys_directory', fallback=DEFAULT_CONTACTS_KEYS_DIRECTORY)

    # Check if the paths are placeholders and use defaults if necessary
    if keys_directory in PLACEHOLDER_PATHS:
        keys_directory = DEFAULT_KEYS_DIRECTORY

    if contacts_keys_directory in PLACEHOLDER_PATHS:
        contacts_keys_directory = DEFAULT_CONTACTS_KEYS_DIRECTORY
    public_key_path = os.path.join(keys_directory, public_key_file)
    
    if jid == 'bot@example.com':
        print(f"{RED}Please adjust your 'botconfig.ini' file with your credentials.{RESET}")
        sys.exit(0)
    # Check if the public key file exists and is valid
    if os.path.exists(public_key_path):
        logging.info("Keys already exist, checking validity")
        with open(public_key_path, 'r') as f:
            public_key_data = f.read()
            logging.debug(f"Public key data: {public_key_data}")

            import_result = gnupg.GPG().import_keys(public_key_data)
            logging.debug(f"GPG import result: {import_result}")

            if not import_result.results or not import_result.fingerprints:
                logging.warning("Existing public key is invalid, regenerating keys")
                os.remove(public_key_path)
                public_key_path, fingerprint = generate_keys(keys_directory, public_key_file, nick, jid)
            else:
                fingerprint = import_result.fingerprints[0]
    else:
        logging.info("Keys do not exist, generating new keys")
        public_key_path, fingerprint = generate_keys(keys_directory, public_key_file, nick, jid)

    try:
        with open(public_key_path, 'r') as f:
            openpgp_key = f.read()
    except Exception as e:
        logging.error(f"Error reading public key: {e}")
        exit(1)

    xmpp = OllamaEncrypted(jid, password, room, nick, allowed_users, openpgp_key, fingerprint)
    xmpp.register_plugin("xep_0199")  # XMPP Ping
    xmpp.register_plugin("xep_0380")  # Explicit Message Encryption
    xmpp.register_plugin("xep_0384", module=sys.modules[__name__])  # OMEMO
    xmpp.register_plugin('xep_0045') # Multi-User Chat
    # Connect to the XMPP server and start processing XMPP stanzas.
    xmpp.connect()
    asyncio.get_event_loop().run_forever()
