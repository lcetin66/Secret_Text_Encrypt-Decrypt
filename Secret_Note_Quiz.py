from tkinter import *
from tkinter import filedialog, PhotoImage, Label
from cryptography.fernet import Fernet
import base64
import os

window = Tk()
window.title("Secret Note Quiz")
window.minsize(width=400, height=750)

var_Title = StringVar()
var_MasterKey = StringVar()
file_path = None

def generate_key_from_password(password):
    # Generating a 32-byte base64 key for Fernet
    clean = ''.join(e for e in password if e.isalnum())
    if not clean:
        raise ValueError("The master key cannot be empty.")
    padded = clean.ljust(32, 's')[:32]
    return base64.urlsafe_b64encode(padded.encode())

def save_and_encrypt():
    global file_path

    # get the master title
    title = var_Title.get().strip()
    if not title:
        display.config(text="No title entered!")
        return

    # get the secret text
    text_content = TextSecret.get("1.0", END).strip().encode()
    if not text_content:
        display.config(text="No text content has been entered.")
        return

    # get the master key
    password = var_MasterKey.get().strip()
    if not password:
        display.config(text="Master key not entered!")
        return

    # file save path
    file_path = filedialog.asksaveasfilename(
        initialfile=f"{title}.txt",
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if not file_path:
        return

    try:
        key = generate_key_from_password(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(text_content)
        with open(file_path, "wb") as file:
            file.write(encrypted)
        display.config(text="The file has been saved and encrypted.")
    except Exception as error:
        display.config(text=str(error))

    # Empty Entry
    title_Entry.delete(0, END)
    TextSecret.delete("1.0", END)
    MasterKeyEntry.delete(0, END)


def decrypt_file():
    global file_path

    password = var_MasterKey.get().strip()
    if not password:
        display.config(text="Master key not entered!")
        return

    file_path = filedialog.askopenfilename(
        initialdir="/",
        title="Select an Encrypted File",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if not file_path:
        return

    # Fill in the file name
    title_Entry.delete(0, END)
    title_Entry.insert(0, os.path.splitext(os.path.basename(file_path))[0])

    try:
        key = generate_key_from_password(password)
        fernet = Fernet(key)
        with open(file_path, "rb") as file:
            encrypted = file.read()
        decrypted = fernet.decrypt(encrypted).decode()
        TextSecret.delete("1.0", END)
        TextSecret.insert("1.0", decrypted)
        display.config(text="The file has been decrypted.")
    except Exception as e:
        display.config(text="The file password could not be decrypted.: " + str(e))

# --- GUI ---
try:
    image = PhotoImage(file="images/secret.png")
    label = Label(window, image=image)
    label.place(x=125, y=30)
    #canvas = Canvas(height=300,width=300)
    #canvas.create_image(200,100,image=image)
    #canvas.place(x=0, y=10)
except TclError:
    display = Label(window, text="Image not found!")
    display.place(x=125, y=100)

Label(window, text="Enter your title").place(x=35, y=200)
title_Entry= Entry(window, textvariable=var_Title, border=0.5, width=35)
title_Entry.place(x=35, y=220)

Label(window, text="Enter your secret").place(x=35, y=250)
TextSecret = Text(window, borderwidth=0.5, width=44, height=15)
TextSecret.place(x=38, y=280)

Label(window, text="Enter master key").place(x=35, y=490)
MasterKeyEntry = Entry(window, textvariable=var_MasterKey, border=0.5, width=35)
MasterKeyEntry.place(x=35, y=515)

Button(text='Save & Encrypt', command=save_and_encrypt, width=32).place(x=35, y=550)
Button(text='Decrypt', command=decrypt_file, width=32).place(x=35, y=580)

display = Label(window, text="", width=35, justify="center", wraplength=250)
display.place(x=39, y=620)

window.mainloop()
