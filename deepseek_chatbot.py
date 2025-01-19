import os
import smtplib
import bcrypt
from email.mime.text import MIMEText
from openai import OpenAI


def load_api_key(file_path: str) -> str:
    """Load the Hugging Face API key from a configuration file."""
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

# Test API connection
try:
    print("Testing OpenAI API connection...")
    client.models.list()  # Simple API call to test connection
    print("API connection successful!")
except Exception as e:
    print(f"Failed to connect to OpenAI API: {e}")
    print("Please check your API key and internet connection.")
    exit(1)

conversation_history = []
current_user = None


def load_conversation_history(user_id):
    """Load previous conversation history for a specific user."""
    user_file = f"conversation_{user_id}.txt"
    if os.path.exists(user_file):
        with open(user_file, "r") as file:
            lines = file.readlines()
            history = []
            for line in lines:
                # Skip empty lines
                if not line.strip():
                    continue
                # Ensure the line contains a ":"
                if ":" not in line:
                    print(f"Warning: Malformed line in conversation history: {line.strip()}")
                    continue
                # Split the line into role and content
                role, content = line.split(":", 1)  # Split on the first occurrence of ":"
                history.append({"role": role.strip(), "content": content.strip()})
            return history
    return []


def save_conversation_history(user_id):
    """Save current conversation history for a specific user (only user questions)."""
    user_file = f"conversation_{user_id}.txt"
    with open(user_file, "w") as file:
        for message in conversation_history:
            if message["role"] == "user":  # Only save user questions
                file.write(f"{message['role']}: {message['content']}\n")


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


def sign_up():
    """Handle user sign-up."""
    global current_user
    print("Sign-Up:")
    username = input("Enter username: ").strip()
    email = input("Enter email: ").strip()

    if not check_username_unique(username):
        print(f"Username {username} already exists. Please choose a different username.")
        return

    password = input("Enter password: ").strip()

    # Hash the password before saving
    password_hash = hash_password(password)

    # Save username, email, and password hash
    with open("users.txt", "a") as file:
        file.write(f"{username}:{email}:{password_hash.decode('utf-8')}\n")
    
    # Automatically sign in the user after registration
    current_user = username  # Set the current user to the one who just signed up
    print(f"User {username} registered successfully! You are now signed in.")
    
    # Start the conversation immediately after sign-up
    ask_question()


def sign_in():
    """Handle user sign-in."""
    global current_user
    print("Sign-In:")
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    # Check if username exists and verify password
    try:
        with open("users.txt", "r") as file:
            users = file.readlines()
            for user in users:
                stored_username, _, stored_hash = user.strip().split(":")
                if stored_username == username and check_password(stored_hash.encode("utf-8"), password):
                    current_user = username  # Set the current user to the signed-in user
                    print(f"Welcome back, {username}!")
                    return username  # Return the username if login is successful
    except FileNotFoundError:
        print("No users found. Please sign up first.")
    print("Invalid username or password!")
    return None


def forgot_password():
    """Allow users to reset their password."""
    print("Forgot Password:")
    username = input("Enter your username: ").strip()

    try:
        with open("users.txt", "r") as file:
            users = file.readlines()
            for i, user in enumerate(users):
                stored_username, email, _ = user.strip().split(":")
                if stored_username == username:
                    verification_code = "123456"  # Replace with random generation for production
                    send_email(email, "Password Reset Code", f"Your verification code is: {verification_code}")
                    code = input("Enter the verification code sent to your email: ").strip()
                    if code == verification_code:
                        new_password = input("Enter your new password: ").strip()
                        hashed_password = hash_password(new_password)
                        users[i] = f"{username}:{email}:{hashed_password.decode('utf-8')}\n"
                        with open("users.txt", "w") as file:
                            file.writelines(users)
                        print("Password reset successfully!")
                        return
                    else:
                        print("Invalid verification code.")
                        return
        print("Username not found.")
    except FileNotFoundError:
        print("No users found. Please sign up first.")


def load_current_user():
    """Load the last signed-in user."""
    global current_user
    try:
        with open("current_user.txt", "r") as file:
            current_user = file.read().strip()
    except FileNotFoundError:
        current_user = None


def save_current_user():
    """Save the current signed-in user."""
    if current_user:
        with open("current_user.txt", "w") as file:
            file.write(current_user)


def logout():
    """Log out the current user."""
    global current_user
    current_user = None
    try:
        os.remove("current_user.txt")  # Remove the current user file
    except FileNotFoundError:
        pass  # If the file doesn't exist, simply ignore the error
    print("You have logged out successfully.")


def ask_question():
    global conversation_history

    # Load previous history from the file for the current user
    conversation_history.extend(load_conversation_history(current_user))

    # Load role description from external file
    role_description = load_role_description("role_description.txt")

    while True:
        question = input("Enter your question (or type 'exit' to quit): ").strip()
        if question.lower() == "exit":
            print("Goodbye!")
            break

        # Construct the messages list with:
        # 1. Role description (system message)
        # 2. Previous conversation history (for context)
        # 3. Current question (user message)
        messages = [{"role": "system", "content": role_description}]
        messages.extend(conversation_history)  # Include previous history for context
        messages.append({"role": "user", "content": question})  # Add current question

        try:
            print("\nResponse:")
            stream = client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                max_tokens=500,
                stream=True,
            )

            # Get the assistant's response and print it
            assistant_response = ""
            for chunk in stream:
                assistant_response += chunk.choices[0].delta.content
                print(chunk.choices[0].delta.content, end="")

            print("\n")

            # Add the user's question to the conversation history
            conversation_history.append({"role": "user", "content": question})

            # Save conversation history for this user
            save_conversation_history(current_user)
            save_current_user()  # Ensure current user is saved

        except OpenAI.APIConnectionError as e:
            print(f"Failed to connect to API: {e}")
            print("Please check your internet connection and try again.")
        except OpenAI.RateLimitError as e:
            print(f"API rate limit exceeded: {e}")
            print("Please wait a moment and try again.")
        except OpenAI.APIError as e:
            print(f"API error: {e}")
            print("Please check your API key and try again.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")


def main():
    global current_user
    load_current_user()  # Attempt to load the last signed-in user

    while True:
        print("\nDo you want to sign up, sign in, reset your password, log out, or exit? (signup/signin/reset/logout/exit): ", end="")
        action = input().strip().lower()

        if action == "signup":
            sign_up()
        elif action == "signin":
            if current_user is None:
                current_user = sign_in()
                if current_user:  # If sign-in is successful, start the conversation
                    ask_question()
            else:
                print(f"Welcome back, {current_user}!")
                ask_question()  # Start the conversation immediately after sign-in
        elif action == "reset":
            forgot_password()
        elif action == "logout":
            logout()
        elif action == "exit":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()
