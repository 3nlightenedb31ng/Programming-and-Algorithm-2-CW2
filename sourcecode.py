import re
import bcrypt
from tkinter import *
from tkinter import messagebox
from tkinter import simpledialog

def main():
    root = Tk()
    root.title("Password Generator and Strength Estimator")

    label = Label(root, text="Welcome to the Password Generator and Strength Estimator!")
    label.pack(pady=10)

    button_generate_password = Button(root, text="Generate Password", command=generate_password)
    button_generate_password.pack(pady=10)

    button_close = Button(root, text="Close", command=root.destroy)
    button_close.pack(pady=10)

    root.mainloop()

def generate_password():
    password = get_password()
    strength, score = password_strength(password)
    messagebox.showinfo("Password Generator", f"Generated password: {password}\nStrength: {strength}\nScore: {score}")
    hashed_password = hash_password(password)
    if verify_password(password, hashed_password):
        messagebox.showinfo("Password Generator", "Password verification successful!")
    else:
        messagebox.showerror("Password Generator", "Password verification failed.")
    save_password_strength(hashed_password, strength, score)

def get_password():
    while True:
        password = simpledialog.askstring("Password Generator", "Enter a password: ", show="*")
        if len(password) < 8:
            messagebox.showerror("Password Generator", "Password must be at least 8 characters long. Please try again.")
        else:
            return password

def password_strength(password):
  
    uppercase_regex = re.compile(r'[A-Z]')
    lowercase_regex = re.compile(r'[a-z]')
    digit_regex = re.compile(r'\d')
    symbol_regex = re.compile(r'[\W_]+')

    
    weights = {
        'length': 1,
        'uppercase': 1,
        'lowercase': 1,
        'digit': 1,
        'symbol': 2
    }

   
    score = 0
    if len(password) >= 8:
        score += weights['length']
    if uppercase_regex.search(password):
        score += weights['uppercase']
    if lowercase_regex.search(password):
        score += weights['lowercase']
    if digit_regex.search(password):
        score += weights['digit']
    if symbol_regex.search(password):
        score += weights['symbol']

    
    if score >= 8:
        strength = 'Strong'
    elif score >= 5:
        strength = 'Moderate'
    else:
        strength = 'Weak'

    return strength, score

def hash_password(password):
    
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password)

def save_password_strength(hashed_password, strength, score):
    with open('passwords.txt', 'a') as file:
        file.write(f"{hashed_password} {strength} {score}\n")
    messagebox.showinfo("Password Generator", "Password strength saved to passwords.txt")

if __name__ == '__main__':
    main()
