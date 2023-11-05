import sys
import customtkinter 
import tkinter as tk
import sys
import re
import hashlib
import json
import rdatasets
import pandas as pd
import matplotlib.pyplot as plt
import os
entry1 = None
entry2 = None
root = None
root2=None
NewUserentry = None
Passwordentry = None
ConfiemePasswordentry = None
texte_chiffre = "" 
texte_chiffre2 = ""
columns=''
filename="10-million-password.txt"
def main():
    customtkinter.set_appearance_mode("dark")
    customtkinter.set_default_color_theme("dark-blue")
    global root
    root = customtkinter.CTk()
    root.geometry("800x600")
    root.title("My Application ")
    main_page(root)

    root.mainloop()

def enregistrement(root, username, password, confirm_password):
    frame = customtkinter.CTkFrame(master=root)
    frame.pack(pady=20, padx=60, fill="both", expand=True)
    if not passwords_match(password, confirm_password):
        label1 = customtkinter.CTkLabel(master=frame, text="Password is not a match", font=("Roboto", 24))
        label1.pack(pady=0, padx=0, expand=True)
    elif not is_valid_email(username):
        label1 = customtkinter.CTkLabel(master=frame, text="Invalid email", font=("Roboto", 24))
        label1.pack(pady=0, padx=0, expand=True)
    
    elif not is_valid_password(password):
        label1 = customtkinter.CTkLabel(master=frame, text="Invalid password", font=("Roboto", 24))
        label1.pack(pady=0, padx=0, expand=True)
    
    else:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        label1 = customtkinter.CTkLabel(master=frame, text="GOOD", font=("Roboto", 24))
        label1.pack(pady=0, padx=0, expand=True)

        with open("text.txt", "a") as file:
            file.write(f"Username: {username}, Password: {hashed_password}\n")
def signin(root): 
    for widget in root.winfo_children():
        widget.destroy()
    global NewUserentry, Passwordentry, ConfiemePasswordentry 
    frame = customtkinter.CTkFrame(master=root)
    frame.pack(pady=20, padx=60, fill="both", expand=True)
    label = customtkinter.CTkLabel(master=frame, text="Sign In", font=("Roboto", 24))
    label.pack(pady=12, padx=10, expand=True)
    
    NewUserentry = customtkinter.CTkEntry(master=frame, placeholder_text=" New User Name")
    NewUserentry.pack(pady=12, padx=10, expand=True)
    
    Passwordentry = customtkinter.CTkEntry(master=frame, placeholder_text="Password")
    Passwordentry.pack(pady=12, padx=10, expand=True)
    ConfiemePasswordentry = customtkinter.CTkEntry(master=frame, placeholder_text=" Confieme Password")
    ConfiemePasswordentry.pack(pady=12, padx=10, expand=True)
    button = customtkinter.CTkButton(master=frame, text="Save", command=lambda: enregistrement(root, NewUserentry.get(), Passwordentry.get(), ConfiemePasswordentry.get()))
    button.pack(pady=12, padx=10, expand=True)
    button = customtkinter.CTkButton(master=frame, text="Back", command=lambda: main_page(root))
    button.pack(pady=6, padx=5, expand=True)
    back_button = customtkinter.CTkButton(master=frame, text="Back to Login", command=lambda: main_page(root))
    back_button.pack(pady=12, padx=10, expand=True)

def exite(root):
    for widget in root.winfo_children():
        widget.destroy()
    sys.exit()
 
def login_page(root):
    global entry1, entry2
    for widget in root.winfo_children():
        widget.destroy()
    frame = customtkinter.CTkFrame(master=root)
    frame.pack(pady=20, padx=60, fill="both", expand=True)

    label = customtkinter.CTkLabel(master=frame, text="Login", font=("Roboto", 24))
    label.pack(pady=12, padx=10, expand=True)
    
    entry1 = customtkinter.CTkEntry(master=frame, placeholder_text="User Name")
    entry1.pack(pady=12, padx=10, expand=True)
    
    entry2 = customtkinter.CTkEntry(master=frame, placeholder_text="Password", show="*")
    entry2.pack(pady=12, padx=10, expand=True)

    button = customtkinter.CTkButton(master=frame, text="Login", command=lambda:Verification(root))
    button.pack(pady=12, padx=10, expand=True)
    button = customtkinter.CTkButton(master=frame, text="Back",command=lambda:main_page(root))
    button.pack(pady=6, padx=5, expand=True)

    checkbox = customtkinter.CTkCheckBox(master=frame, text="Remember Me")
    checkbox.pack(pady=12, padx=10, expand=True)



def CESAR(root):
    for widget in root.winfo_children():
        widget.destroy()
    label = None 
    def on_button_click(event):
        
        decalage_value = int(decalage.get()) 
        texte_chiffre = chiffre_cesar_ascii(Texte.get(), decalage_value)
        label.configure(text=texte_chiffre)
    def on_button_click2(event):
        
        decalage_value = int(decalage.get()) 
        texte_chiffre = chiffre_cesar_lettres(Texte.get(), decalage_value)
        label.configure(text=texte_chiffre)
    frame = customtkinter.CTkFrame(master=root)
    frame.pack(pady=20, padx=60, fill="both", expand=True)
    Texte = customtkinter.CTkEntry(master=frame, placeholder_text="Word To Cypher")
    Texte.pack(pady=12, padx=10, expand=True, fill="both")
    decalage = customtkinter.CTkEntry(master=frame, placeholder_text="decalage")
    decalage.pack(pady=12, padx=10, expand=True)
    frame_buttons = customtkinter.CTkFrame(master=frame)
    frame_buttons.pack(pady=12, expand=True, fill="both")
    button1 = customtkinter.CTkButton(master=frame_buttons, text="Cypher with ASCII")
    button1.pack(side="left", padx=3, expand=True)
    button1.bind("<Button-1>", on_button_click)
    button2 = customtkinter.CTkButton(master=frame_buttons, text="Cypher with 26 ALPH")
    button2.pack(side="left", padx=3, expand=True)
    button2.bind("<Button-1>", on_button_click2)
    label = customtkinter.CTkLabel(master=frame, text=texte_chiffre2, font=("Roboto", 20))
    label.pack(pady=12, padx=10, expand=True)
    back_button = customtkinter.CTkButton(master=frame, text="Back ", command=lambda: Application_page(root))
    back_button.pack(pady=12, padx=10, expand=True)



def HASH(root):
    label = None
    global texte_chiffre
    def on_button_click(event):
        global texte_chiffre
        texte_chiffre = sha256_hash(word_hash.get())
        label.configure(text=texte_chiffre)
    def on_button_click1(event):
        global texte_chiffre
        texte_chiffre = word_exists_in_file(word_hash.get(),filename)
        label.configure(text=texte_chiffre)


    for widget in root.winfo_children():
        widget.destroy()
    frame = customtkinter.CTkFrame(master=root)
    frame.pack(pady=20, padx=60, fill="both", expand=True)
    word_hash = customtkinter.CTkEntry(master=frame, placeholder_text=" Word to Hash")
    word_hash.pack(pady=12, padx=10, expand=True, fill="both")
    frame_buttons = customtkinter.CTkFrame(master=frame)
    frame_buttons.pack(pady=12, expand=True, fill="both")
    button1 = customtkinter.CTkButton(master=frame_buttons, text="Hash the word with sh256")
    button1.pack(side="left", padx=3, expand=True)
    button1.bind("<Button-1>", on_button_click)
    button2 = customtkinter.CTkButton(master=frame_buttons, text="Cheak Dictionaire")
    button2.pack(side="left", padx=3, expand=True)
    button2.bind("<Button-1>", on_button_click1)
    label = customtkinter.CTkLabel(master=frame, text=texte_chiffre, font=("Roboto", 20))
    label.pack(pady=12, padx=20, expand=True)
    back_button = customtkinter.CTkButton(master=frame, text="Back ", command=lambda: Application_page(root))
    back_button.pack(pady=12, padx=10, expand=True)

def dataset(root):
    selected_column = None  
    global values 
    def on_button_click(event):
        global available_columns, available_columns3,selected_value
        selected_value = checkBox1.get()
        available_columns = get_dataset_columns(selected_value)
        available_columns3 = available_columns.copy()
        checkBox2.configure(values=available_columns)
        checkBox2.set('')
        checkBox3.configure(values=available_columns)
        checkBox3.set('') 
    def on_checkBox2_select(event):
        nonlocal selected_column
        selected_column = checkBox2.get()
        confirmation_button2.configure(state="normal")
        checkBox3_values = available_columns3
        checkBox3.configure(values=checkBox3_values)
        checkBox3.set('')

    def on_checkBox3_select(event):
        confirmation_button3.configure(state="normal")  

    def confirm_selection_2():
        global selected_value1
        selected_value1 = checkBox2.get()

    def confirm_selection_3():
        global selected_value2
        selected_value2 = checkBox3.get()

    for widget in root.winfo_children():
        widget.destroy()

    frame = customtkinter.CTkFrame(master=root)
    frame.pack(pady=20, padx=60, fill="both", expand=True)
    label = customtkinter.CTkLabel(master=frame, text="Select Your Dataset ", font=("Roboto", 20))
    label.pack(pady=12, padx=10, expand=True)

    values = ['ability', 'airmiles', 'AirPassengers', 'airquality', 'anscombe', 'attenu', 'attitude', 'austres', 'BJsales', 'BOD', 'cars', 'ChickWeight', 'chickwts', 'co2', 'crimtab', 'discoveries', 'DNase', 'esoph', 'euro', 'EuStockMarkets', 'faithful', 'Formaldehyde', 'freeny', 'HairEyeColor', 'Harman23', 'Harman74', 'Indometh', 'infert', 'InsectSprays', 'iris', 'iris3', 'islands', 'JohnsonJohnson', 'LakeHuron', 'lh', 'LifeCycleSavings', 'Loblolly', 'longley', 'lynx', 'morley', 'mtcars', 'nhtemp', 'Nile', 'nottem', 'npk', 'occupationalStatus', 'Orange', 'OrchardSprays', 'PlantGrowth', 'precip', 'presidents', 'pressure', 'Puromycin', 'quakes', 'randu', 'rivers', 'rock', 'Seatbelts', 'sleep', 'stackloss', 'sunspot', 'sunspots', 'swiss', 'Theoph', 'Titanic', 'ToothGrowth', 'treering', 'trees', 'UCBAdmissions', 'UKDriverDeaths', 'UKgas', 'USAccDeaths', 'USArrests', 'USJudgeRatings', 'USPersonalExpenditure', 'uspop', 'VADeaths', 'volcano', 'warpbreaks', 'women', 'WorldPhones', 'WWWusage']
    checkBox1 = customtkinter.CTkComboBox(master=frame, values=values)
    checkBox1.pack(side="top", expand=True)
    button1 = customtkinter.CTkButton(master=frame, text="confirm")
    button1.pack(side="top" ,padx=3, expand=True)
    button1.bind("<Button-1>", on_button_click)
    checkBox2 = customtkinter.CTkComboBox(master=frame, values=[])
    checkBox2.pack(side="left", padx=3, expand=True)
    checkBox2.bind("<<ComboboxSelected>>", on_checkBox2_select)
    confirmation_button2 = customtkinter.CTkButton(master=frame, text="Confirm Selection 2")
    confirmation_button2.pack(side="left", padx=3, expand=True)
    confirmation_button2.configure(command=confirm_selection_2)
    checkBox3 = customtkinter.CTkComboBox(master=frame, values=[])
    checkBox3.pack(side="left", padx=6, expand=True)
    checkBox3.bind("<<ComboboxSelected>>", on_checkBox3_select)
    confirmation_button3 = customtkinter.CTkButton(master=frame, text="Confirm Selection 3")
    confirmation_button3.pack(side="left", padx=6, expand=True)
    confirmation_button3.configure(command=confirm_selection_3)
    frame2 = customtkinter.CTkFrame(master=root)
    frame2.pack(pady=20, padx=60, fill="both", expand=True)
    button4 = customtkinter.CTkButton(master=frame2, text="Show Dataset as dictionary")
    button4.pack(side="top", expand=True)
    button4.configure(command=lambda: another_function(selected_value))
    button5 = customtkinter.CTkButton(master=frame2, text="Show Dataset as Plot ")
    button5.pack(side="top", expand=True)
    button5.configure(command=lambda: plot_scatter(selected_value, selected_value1, selected_value2))
    button6 = customtkinter.CTkButton(master=frame2, text="Back")
    button6.pack(side="top", expand=True)
    button6.configure(command=lambda: Application_page(root))
def Application_page(root):
    for widget in root.winfo_children():
        widget.destroy()
    
    frame = customtkinter.CTkFrame(master=root)
    frame.pack(pady=20, padx=60, fill="both", expand=True)

    button1 = customtkinter.CTkButton(master=frame, text="Provide a word to hash (in invisible mode)",command=lambda:HASH(root))
    button1.pack(pady=12, padx=3, expand=True, fill="both", side="top", anchor="w")

    button2 = customtkinter.CTkButton(master=frame, text="Caesar Shift", command=lambda:CESAR(root))
    button2.pack(pady=12, padx=3, expand=True, fill="both", side="top", anchor="w")

    button3 = customtkinter.CTkButton(master=frame, text="Collect a dataset of your choice",command=lambda:dataset(root))
    button3.pack(pady=12, padx=3, expand=True, fill="both", side="top", anchor="w")

    button4 = customtkinter.CTkButton(master=frame, text="Back", command=lambda: main_page(root))
    button4.pack(pady=6, padx=3, expand=True, fill="both", side="top", anchor="w")
def main_page(root):
    for widget in root.winfo_children():
        widget.destroy()
    
    frame = customtkinter.CTkFrame(master=root)
    frame.pack(pady=20, padx=60, fill="both", expand=True)
    
    button1 = customtkinter.CTkButton(master=frame, text="Login", command=lambda:login_page(root))
    button1.pack(pady=12, padx=10, expand=True)
    
    button2 = customtkinter.CTkButton(master=frame, text="Sign In", command=lambda:signin(root))
    button2.pack(pady=12, padx=10, expand=True)
    
    button3 = customtkinter.CTkButton(master=frame, text="Exit", command=lambda:exite(root))
    button3.pack(pady=12, padx=10, expand=True)

def passwords_match(password, confirm_password):
    return password == confirm_password
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None
def is_valid_password(password):
    password_regex = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@#$%^&+=!])(?!.*\s).{8,}$'
    return re.match(password_regex, password) is not None
def chiffre_cesar_ascii(texte, decalage):
    texte_chiffre = ""
    for caractere in texte:
        code_ascii = ord(caractere)
        code_ascii_decale = code_ascii + decalage
        caractere_chiffre = chr(code_ascii_decale)
        texte_chiffre += caractere_chiffre
    return texte_chiffre
def chiffre_cesar_lettres(texte, decalage):
    texte_chiffre = ""
    for caractere in texte:
        if caractere.isalpha():
            majuscule = caractere.isupper()
            caractere = caractere.lower()
            code_ascii = ord(caractere)
            code_ascii_decale = (code_ascii - ord('a') + decalage) % 26
            caractere_chiffre = chr(code_ascii_decale + ord('a'))
            if majuscule:
                caractere_chiffre = caractere_chiffre.upper()
        else:
            caractere_chiffre = caractere
        texte_chiffre += caractere_chiffre
    return texte_chiffre
def sha256_hash(word):
    sha256 = hashlib.sha256()
    sha256.update(word.encode('utf-8'))
    hash_hex = sha256.hexdigest()
    return hash_hex
def word_exists_in_file(word, filename):
    try:
        with open(filename, "r") as file:
            text = file.read()
            if word in text:
                return f"The word {word} was found in the file {filename}."
            else:
                return f"The word {word} was not found in the file {filename}."
    except FileNotFoundError:
        return f"Error: The file {filename} was not found."
def get_dataset_columns(dataset_name, json_file_path='dataset_columns.json'):
    # Check if the JSON file exists
    if not os.path.isfile(json_file_path):
        # Create the JSON file
        all_dataset_columns = {}
        dataset_names =values
        for name in dataset_names:
            data = rdatasets.data(name)
            df = pd.DataFrame(data)
            columns = df.columns.tolist()
            all_dataset_columns[name] = columns

        # Save the dataset columns to the JSON file
        with open(json_file_path, 'w') as json_file:
            json.dump(all_dataset_columns, json_file, indent=4)

    # Load dataset columns from the JSON file
    with open(json_file_path, 'r') as json_file:
        dataset_columns = json.load(json_file)

    if dataset_name in dataset_columns:
        columns = dataset_columns[dataset_name]
        return columns if columns else []
    else:
        return []
def dataset_to_dict(dataset_name):
    data = rdatasets.data(dataset_name)
    df = pd.DataFrame(data)
    data_dict = df.to_dict("list")
    return data_dict
def plot_scatter(dataset_name, x_column, y_column):
    data = rdatasets.data(dataset_name)
    df = pd.DataFrame(data)
    plt.figure(figsize=(10, 6))
    plt.scatter(df[x_column], df[y_column], label=f'{x_column} vs. {y_column}')
    plt.xlabel(x_column)
    plt.ylabel(y_column)
    plt.title(f'Relation between {x_column} and {y_column}')
    plt.legend()
    plt.show()
def display_dict_in_window(data_dict, window_title):
    new_window = customtkinter.CTk()
    new_window.geometry("500x350")
    new_window.title(window_title)
    new_window.iconbitmap("images/images.ico")

    frame = customtkinter.CTkFrame(master=new_window)
    frame.pack(pady=20, padx=60, fill="both", expand=True)

    label =customtkinter.CTkLabel(master=frame, text=data_dict)
    label.pack(pady=0, padx=60,expand=True)
    new_window.mainloop()
def another_function(data_dict):
    data=dataset_to_dict(data_dict)
    display_dict_in_window(data, "Window Title for Another Function")
def Verification(root):
    global entry1, entry2

    entered_username = entry1.get()
    entered_password = entry2.get()
    with open("text.txt", "r") as file:
        credentials = file.readlines()
    for line in credentials:
        parts = line.strip().split(", ")
        username, stored_hashed_password = None, None
        for part in parts:
            if part.startswith("Username: "):
                username = part.split(": ")[1]
            elif part.startswith("Password: "):
                stored_hashed_password = part.split(": ")[1]

        if username is not None and stored_hashed_password is not None:
            entered_hashed_password = hashlib.sha256(entered_password.encode()).hexdigest()
            if entered_username == username and entered_hashed_password == stored_hashed_password:
                Application_page(root)
                return

if __name__ == "__main__":
    main()
