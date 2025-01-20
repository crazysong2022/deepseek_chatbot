import os
import smtplib
import bcrypt
from email.mime.text import MIMEText
from openai import OpenAI
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk


# Load API key and initialize OpenAI client
def load_api_key(file_path: str) -> str:
    """Load the OpenAI API key from a configuration file."""
    try:
        with open(file_path, "r") as file:
            for line in file:
                if line.startswith("OPENAI_API_KEY="):
                    return line.strip().split("=", 1)[1]
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file '{file_path}' not found.")
    except Exception as e:
        raise Exception(f"An error occurred while reading the API key: {e}")
    raise ValueError("API key not found in the configuration file.")


def load_role_description(file_path: str) -> str:
    """Load the role description from a file."""
    try:
        with open(file_path, "r") as file:
            role_description = file.read().strip()
            if not role_description:
                raise ValueError("Role description file is empty.")
            return role_description
    except FileNotFoundError:
        raise FileNotFoundError(f"Role description file '{file_path}' not found.")
    except Exception as e:
        raise Exception(f"An error occurred while reading the role description: {e}")


# Load the API key from the file
API_KEY = load_api_key("config.txt")
client = OpenAI(api_key=API_KEY, base_url="https://api.deepseek.com")


def hash_password(password):
    """Hash the password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def check_password(stored_hash, password):
    """Check if the provided password matches the stored hash."""
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)


def check_username_unique(username, users_file="users.txt"):
    """Check if the username is unique."""
    try:
        with open(users_file, "r") as file:
            for line in file:
                existing_username = line.split(":")[0]
                if existing_username == username:
                    return False  # Username already exists
    except FileNotFoundError:
        pass  # If file doesn't exist, it's okay to create it
    return True


def send_email(recipient_email, subject, body):
    """Send an email using the Outlook SMTP server."""
    try:
        smtp_server = "smtp.office365.com"
        smtp_port = 587
        sender_email = "smartwayimport@outlook.com"
        sender_password = "your_password_or_app_password"

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = recipient_email

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")


# Main Application Class
class ChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AI Chat Assistant")
        self.geometry("800x600")
        self.configure(bg="#f0f0f0")

        # Custom fonts
        self.heading_font = ("Arial", 24, "bold")
        self.body_font = ("Helvetica", 12)
        self.button_font = ("Helvetica", 12, "bold")

        # Initialize API client
        self.API_KEY = load_api_key("config.txt")
        self.client = OpenAI(api_key=self.API_KEY, base_url="https://api.deepseek.com")

        # Initialize user and conversation state
        self.current_user = None
        self.conversation_history = []

        # Load the last signed-in user
        self.load_current_user()

        # Show the main menu
        self.show_main_menu()

    def show_main_menu(self):
        """Display the main menu with options."""
        self.clear_window()
        self.configure(bg="#f0f0f0")

        # Heading
        tk.Label(self, text="Welcome to the AI Chat Assistant!", font=self.heading_font, bg="#f0f0f0").pack(pady=20)

        # Logged-in user display
        if self.current_user:
            tk.Label(self, text=f"Logged in as: {self.current_user}", font=self.body_font, bg="#f0f0f0").pack(pady=10)

        # Buttons
        button_frame = tk.Frame(self, bg="#f0f0f0")
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Sign Up", command=self.show_signup_screen, font=self.button_font, bg="#0078d7", fg="white", width=20).grid(row=0, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Sign In", command=self.show_signin_screen, font=self.button_font, bg="#0078d7", fg="white", width=20).grid(row=1, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Forgot Password", command=self.show_forgot_password_screen, font=self.button_font, bg="#0078d7", fg="white", width=20).grid(row=2, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Log Out", command=self.logout, font=self.button_font, bg="#d83b01", fg="white", width=20).grid(row=3, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Exit", command=self.quit, font=self.button_font, bg="#d83b01", fg="white", width=20).grid(row=4, column=0, padx=10, pady=10)

    def show_signup_screen(self):
        """Display the sign-up screen."""
        self.clear_window()
        self.configure(bg="#f0f0f0")

        # Heading
        tk.Label(self, text="Sign Up", font=self.heading_font, bg="#f0f0f0").pack(pady=20)

        # Form frame
        form_frame = tk.Frame(self, bg="#f0f0f0")
        form_frame.pack(pady=20)

        # Username
        tk.Label(form_frame, text="Username:", font=self.body_font, bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.username_entry = tk.Entry(form_frame, font=self.body_font, width=30)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        # Email
        tk.Label(form_frame, text="Email:", font=self.body_font, bg="#f0f0f0").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.email_entry = tk.Entry(form_frame, font=self.body_font, width=30)
        self.email_entry.grid(row=1, column=1, padx=10, pady=10)

        # Password
        tk.Label(form_frame, text="Password:", font=self.body_font, bg="#f0f0f0").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.password_entry = tk.Entry(form_frame, font=self.body_font, width=30, show="*")
        self.password_entry.grid(row=2, column=1, padx=10, pady=10)

        # Buttons
        button_frame = tk.Frame(self, bg="#f0f0f0")
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Submit", command=self.handle_signup, font=self.button_font, bg="#0078d7", fg="white", width=20).grid(row=0, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Back", command=self.show_main_menu, font=self.button_font, bg="#d83b01", fg="white", width=20).grid(row=0, column=1, padx=10, pady=10)

    def handle_signup(self):
        """Handle the sign-up process."""
        username = self.username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not email or not password:
            messagebox.showerror("Error", "All fields are required!")
            return

        if not check_username_unique(username):
            messagebox.showerror("Error", "Username already exists!")
            return

        password_hash = hash_password(password)
        with open("users.txt", "a") as file:
            file.write(f"{username}:{email}:{password_hash.decode('utf-8')}\n")

        self.current_user = username
        self.save_current_user()  # Save the current user
        messagebox.showinfo("Success", "Sign-up successful! You are now signed in.")
        self.show_chat_screen()

    def show_signin_screen(self):
        """Display the sign-in screen."""
        self.clear_window()
        self.configure(bg="#f0f0f0")

        # Heading
        tk.Label(self, text="Sign In", font=self.heading_font, bg="#f0f0f0").pack(pady=20)

        # Form frame
        form_frame = tk.Frame(self, bg="#f0f0f0")
        form_frame.pack(pady=20)

        # Username
        tk.Label(form_frame, text="Username:", font=self.body_font, bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.username_entry = tk.Entry(form_frame, font=self.body_font, width=30)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        # Password
        tk.Label(form_frame, text="Password:", font=self.body_font, bg="#f0f0f0").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.password_entry = tk.Entry(form_frame, font=self.body_font, width=30, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        # Buttons
        button_frame = tk.Frame(self, bg="#f0f0f0")
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Submit", command=self.handle_signin, font=self.button_font, bg="#0078d7", fg="white", width=20).grid(row=0, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Back", command=self.show_main_menu, font=self.button_font, bg="#d83b01", fg="white", width=20).grid(row=0, column=1, padx=10, pady=10)

    def handle_signin(self):
        """Handle the sign-in process."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            with open("users.txt", "r") as file:
                users = file.readlines()
                for user in users:
                    stored_username, _, stored_hash = user.strip().split(":")
                    if stored_username == username and check_password(stored_hash.encode("utf-8"), password):
                        self.current_user = username
                        self.save_current_user()  # Save the current user
                        messagebox.showinfo("Success", "Sign-in successful!")
                        self.show_chat_screen()
                        return
        except FileNotFoundError:
            messagebox.showerror("Error", "No users found. Please sign up first.")
            return

        messagebox.showerror("Error", "Invalid username or password!")

    def show_forgot_password_screen(self):
        """Display the forgot password screen."""
        self.clear_window()
        self.configure(bg="#f0f0f0")

        # Heading
        tk.Label(self, text="Forgot Password", font=self.heading_font, bg="#f0f0f0").pack(pady=20)

        # Form frame
        form_frame = tk.Frame(self, bg="#f0f0f0")
        form_frame.pack(pady=20)

        # Username
        tk.Label(form_frame, text="Username:", font=self.body_font, bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.username_entry = tk.Entry(form_frame, font=self.body_font, width=30)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10)

        # Buttons
        button_frame = tk.Frame(self, bg="#f0f0f0")
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Submit", command=self.handle_forgot_password, font=self.button_font, bg="#0078d7", fg="white", width=20).grid(row=0, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Back", command=self.show_main_menu, font=self.button_font, bg="#d83b01", fg="white", width=20).grid(row=0, column=1, padx=10, pady=10)

    def handle_forgot_password(self):
        """Handle the forgot password process."""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Username is required!")
            return

        try:
            with open("users.txt", "r") as file:
                users = file.readlines()
                for i, user in enumerate(users):
                    stored_username, email, _ = user.strip().split(":")
                    if stored_username == username:
                        verification_code = "123456"  # Replace with random generation for production
                        send_email(email, "Password Reset Code", f"Your verification code is: {verification_code}")
                        code = simpledialog.askstring("Verification Code", "Enter the verification code sent to your email:")
                        if code == verification_code:
                            new_password = simpledialog.askstring("New Password", "Enter your new password:", show="*")
                            if new_password:
                                hashed_password = hash_password(new_password)
                                users[i] = f"{username}:{email}:{hashed_password.decode('utf-8')}\n"
                                with open("users.txt", "w") as file:
                                    file.writelines(users)
                                messagebox.showinfo("Success", "Password reset successfully!")
                                return
                            else:
                                messagebox.showerror("Error", "New password is required!")
                                return
                        else:
                            messagebox.showerror("Error", "Invalid verification code!")
                            return
                messagebox.showerror("Error", "Username not found!")
        except FileNotFoundError:
            messagebox.showerror("Error", "No users found. Please sign up first.")

    def show_chat_screen(self):
        """Display the chat screen."""
        self.clear_window()
        self.configure(bg="#f0f0f0")

        # Heading
        tk.Label(self, text=f"Chat with AI Assistant (Logged in as: {self.current_user})", font=self.heading_font, bg="#f0f0f0").pack(pady=20)

        # Chat history
        self.chat_history = tk.Text(self, wrap=tk.WORD, state=tk.DISABLED, font=self.body_font, bg="white", fg="black", height=20, width=80)
        self.chat_history.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # Scrollbar for chat history
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.chat_history.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_history.config(yscrollcommand=scrollbar.set)

        # Question entry
        tk.Label(self, text="Enter your question:", font=self.body_font, bg="#f0f0f0").pack(pady=10)
        self.question_entry = tk.Entry(self, font=self.body_font, width=50)
        self.question_entry.pack(pady=10)

        # Buttons
        button_frame = tk.Frame(self, bg="#f0f0f0")
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Ask", command=self.handle_ask_question, font=self.button_font, bg="#0078d7", fg="white", width=20).grid(row=0, column=0, padx=10, pady=10)
        tk.Button(button_frame, text="Back", command=self.show_main_menu, font=self.button_font, bg="#d83b01", fg="white", width=20).grid(row=0, column=1, padx=10, pady=10)

    def handle_ask_question(self):
        """Handle asking a question to the AI assistant."""
        question = self.question_entry.get().strip()
        if not question:
            messagebox.showerror("Error", "Please enter a question!")
            return

        # Add the question to the chat history
        self.chat_history.config(state=tk.NORMAL)
        self.chat_history.insert(tk.END, f"You: {question}\n")
        self.chat_history.config(state=tk.DISABLED)

        # Add the user's question to the conversation history
        self.conversation_history.append({"role": "user", "content": question})

        # Get the AI's response
        try:
            role_description = load_role_description("role_description.txt")
            messages = [{"role": "system", "content": role_description}]
            messages.extend(self.conversation_history)

            stream = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                max_tokens=500,
                stream=True,
            )

            # Initialize the assistant response
            assistant_response = ""

            # Update the chat history in real-time as chunks arrive
            self.chat_history.config(state=tk.NORMAL)
            self.chat_history.insert(tk.END, "AI: ")
            self.chat_history.config(state=tk.DISABLED)

            for chunk in stream:
                if chunk.choices[0].delta.content:
                    # Append the chunk to the assistant response
                    assistant_response += chunk.choices[0].delta.content

                    # Update the chat history with the new chunk
                    self.chat_history.config(state=tk.NORMAL)
                    self.chat_history.insert(tk.END, chunk.choices[0].delta.content)
                    self.chat_history.config(state=tk.DISABLED)

                    # Scroll to the end of the chat history
                    self.chat_history.see(tk.END)
                    self.update_idletasks()  # Force update the UI

            # Add a newline after the AI's response
            self.chat_history.config(state=tk.NORMAL)
            self.chat_history.insert(tk.END, "\n\n")
            self.chat_history.config(state=tk.DISABLED)

            # Add the AI's response to the conversation history (not saved to file)
            self.conversation_history.append({"role": "assistant", "content": assistant_response})

            # Save only the user's questions to the conversation history file
            self.save_conversation_history(self.current_user)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def save_conversation_history(self, user_id):
        """Save only the user's questions to the conversation history file."""
        user_file = f"conversation_{user_id}.txt"
        with open(user_file, "a") as file:  # Use "a" (append mode) to add new questions without overwriting
            for message in self.conversation_history:
                if message["role"] == "user":  # Only save user questions
                    file.write(f"User: {message['content']}\n")

    def clear_window(self):
        """Clear all widgets from the window."""
        for widget in self.winfo_children():
            widget.destroy()

    def load_current_user(self):
        """Load the last signed-in user."""
        try:
            with open("current_user.txt", "r") as file:
                self.current_user = file.read().strip()
        except FileNotFoundError:
            self.current_user = None

    def save_current_user(self):
        """Save the current signed-in user."""
        if self.current_user:
            with open("current_user.txt", "w") as file:
                file.write(self.current_user)

    def logout(self):
        """Log out the current user."""
        self.current_user = None
        try:
            os.remove("current_user.txt")  # Remove the current user file
        except FileNotFoundError:
            pass  # If the file doesn't exist, simply ignore the error
        messagebox.showinfo("Success", "You have logged out successfully.")
        self.show_main_menu()


# Run the application
if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()