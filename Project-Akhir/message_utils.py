import json

def load_messages():
    try:
        with open("messages.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def save_message(sender, recipient, message):
    messages = load_messages()
    messages.append({"sender": sender, "recipient": recipient, "message": message})
    with open("messages.json", "w") as f:
        json.dump(messages, f, indent=4)