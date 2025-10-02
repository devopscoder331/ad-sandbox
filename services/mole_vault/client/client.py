import curses

import requests
import typer

app = typer.Typer()

def register_user(stdscr, api_url):
    stdscr.clear()
    stdscr.addstr("Register User\n")
    curses.echo()  # Enable echoing of input characters
    stdscr.addstr("Username: ")
    username = stdscr.getstr().decode('utf-8')
    stdscr.addstr("Password: ")
    password = stdscr.getstr().decode('utf-8')
    curses.noecho()  # Disable echoing after input

    response = requests.post(f"{api_url}/register", data={"username": username, "password": password})
    if response.status_code == 200:
        stdscr.addstr("Registration successful!\n")
    else:
        error_message = response.json().get("error", "Registration failed!")
        stdscr.addstr(f"Error: {error_message}\n")
    stdscr.refresh()
    stdscr.getch()

def login_user(stdscr, api_url):
    stdscr.clear()
    stdscr.addstr("Login User\n")
    curses.echo()  # Enable echoing of input characters
    stdscr.addstr("Username: ")
    username = stdscr.getstr().decode('utf-8')
    stdscr.addstr("Password: ")
    password = stdscr.getstr().decode('utf-8')
    curses.noecho()  # Disable echoing after input

    response = requests.post(f"{api_url}/login", data={"username": username, "password": password})
    if response.status_code == 200:
        stdscr.addstr("Login successful!\n")
        stdscr.refresh()
        stdscr.getch()  # Wait for user input
        return response.headers.get("Authentication")
    else:
        error_message = response.json().get("error", "Login failed!")
        stdscr.addstr(f"Error: {error_message}\n")
        stdscr.refresh()
        stdscr.getch()  # Wait for user input
    return None

def add_secret(stdscr, token, api_url):
    stdscr.clear()
    stdscr.addstr("Add Secret\n")
    curses.echo()  # Enable echoing of input characters
    stdscr.addstr("Content: ")
    content = stdscr.getstr().decode('utf-8')
    stdscr.addstr("Is Public (true/false): ")
    is_public = stdscr.getstr().decode('utf-8')
    curses.noecho()  # Disable echoing after input

    headers = {"Authentication": token}
    response = requests.post(f"{api_url}/add", data={"content": content, "is_public": is_public}, headers=headers)
    if response.status_code == 201:
        stdscr.addstr("Secret added successfully!\n")
    else:
        error_message = response.json().get("error", "Failed to add secret!")
        stdscr.addstr(f"Error: {error_message}\n")
    stdscr.refresh()
    stdscr.getch()

def list_secrets(stdscr, token, api_url):
    stdscr.clear()
    stdscr.addstr("List of Secrets\n")
    headers = {"Authentication": token}
    response = requests.get(f"{api_url}/list", headers=headers)
    if response.status_code == 200:
        secrets = response.json()
        if secrets is None:
            secrets = []
        for secret in secrets:
            stdscr.addstr(f"ID: {secret['id']}, Content: {secret['content']}\n")
    else:
        error_message = response.json().get("error", "Failed to retrieve secrets!")
        stdscr.addstr(f"Error: {error_message}\n")
    stdscr.refresh()
    stdscr.getch()

def get_secret_by_id(stdscr, token, api_url):
    stdscr.clear()
    stdscr.addstr("Get Secret by ID\n")
    curses.echo()  # Enable echoing of input characters
    stdscr.addstr("Secret ID: ")
    secret_id = stdscr.getstr().decode('utf-8')
    curses.noecho()  # Disable echoing after input

    headers = {"Authentication": token}
    response = requests.get(f"{api_url}/get", params={"id": secret_id}, headers=headers)
    if response.status_code == 200:
        secret = response.json()
        stdscr.addstr(f"ID: {secret['id']}, Content: {secret['content']}\n")
    else:
        error_message = response.json().get("error", "Failed to retrieve secret!")
        stdscr.addstr(f"Error: {error_message}\n")
    stdscr.refresh()
    stdscr.getch()

def tui_main(stdscr, api_url):
    token = None
    while True:
        stdscr.clear()
        stdscr.addstr("Simple TUI for API\n")
        stdscr.addstr("1. Register\n")
        stdscr.addstr("2. Login\n")
        stdscr.addstr("3. Add Secret\n")
        stdscr.addstr("4. List Secrets\n")
        stdscr.addstr("5. Get Secret by ID\n")
        stdscr.addstr("6. Exit\n")
        stdscr.addstr("Choose an option: ")
        choice = stdscr.getch()

        if choice == ord('1'):
            register_user(stdscr, api_url)
        elif choice == ord('2'):
            token = login_user(stdscr, api_url)
        elif choice == ord('3'):
            if token:
                add_secret(stdscr, token, api_url)
            else:
                stdscr.addstr("Please login first!\n")
                stdscr.refresh()
                stdscr.getch()
        elif choice == ord('4'):
            if token:
                list_secrets(stdscr, token, api_url)
            else:
                stdscr.addstr("Please login first!\n")
                stdscr.refresh()
                stdscr.getch()
        elif choice == ord('5'):
            if token:
                get_secret_by_id(stdscr, token, api_url)
            else:
                stdscr.addstr("Please login first!\n")
                stdscr.refresh()
                stdscr.getch()
        elif choice == ord('6'):
            break

@app.command()
def main(host: str, port: int = 31339):
    api_url = f"http://{host}:{port}"
    curses.wrapper(tui_main, api_url)

if __name__ == "__main__":
    app()
