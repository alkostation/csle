import requests
from bs4 import BeautifulSoup
import argparse


def login_to_wordpress(session, url, username, password):
    """Log in to the WordPress admin panel."""
    login_payload = {
        "log": username,
        "pwd": password,
        "wp-submit": "Log In",
    }
    response = session.post(f"{url}/wp-login.php", data=login_payload)
    if "wp-admin" not in response.url:
        print("Login failed.")
        return None
    return response


def get_plugin_activation_link(session, url):
    """Get the activation link for the wpDiscuz plugin."""
    response = session.get(f"{url}/wp-admin/plugins.php")
    if not response.ok:
        print("Failed to fetch plugins page.")
        return None

    soup = BeautifulSoup(response.text, "html.parser")
    activate_link = soup.find('a', id="activate-wpdiscuz")
    deactivate_link = soup.find('a', id="deactivate-wpdiscuz")

    if activate_link:
        return activate_link.get('href')
    elif deactivate_link:
        print("wpDiscuz is already activated!")
        return None
    else:
        print("Activation link not found. The plugin might not be installed.")
        return None


def activate_plugin(session, url, activate_link):
    """Activate the wpDiscuz plugin."""
    response = session.get(f"{url}/wp-admin/{activate_link}")
    if response.ok:
        print("wpDiscuz activated successfully.")
        return True
    print("Failed to activate wpDiscuz.")
    return False


def complete_setup_wizard(session, url):
    """Complete the wpDiscuz setup wizard."""
    response = session.get(f"{url}/wp-admin")
    if not response.ok:
        print("Failed to fetch wp-admin page.")
        return False

    soup = BeautifulSoup(response.text, "html.parser")
    # setup_prompt = soup.find('p', string="Please complete required steps to start using wpDiscuz 7")
    p_elements = soup.findAll('p')
    setup_link = None
    for p_element in p_elements:
        if "Please complete required steps to start using wpDiscuz 7" in p_element.text:
            setup_link = p_element.find_all_next()[0]

    if not setup_link:
        print("Setup wizard link not found.")
        return False

    response = session.get(setup_link['href'])
    while response.ok:
        soup = BeautifulSoup(response.text, "html.parser")
        wizard_button = soup.find("a", class_="wpd-wizard-button")
        if wizard_button:
            print("Setup wizard completed.")
            return True

        form = soup.find('form')
        if not form:
            print("Setup form not found.")
            return False

        action_url = form.get('action')
        form_data = {
            input_tag.get('name'): input_tag.get('value', '')
            for input_tag in form.find_all('input')
            if input_tag.get('name') and (
                input_tag.get('type') != 'radio' or input_tag.get('checked')
            )
        }

        print("Submitting setup form...")
        response = session.post(action_url, data=form_data)

    print("Failed to complete setup wizard.")
    return False


def activate(url, username, password):
    """Main function to activate wpDiscuz plugin."""
    session = requests.Session()

    # Log in to WordPress
    if not login_to_wordpress(session, url, username, password):
        return 1

    # Get activation link
    activate_link = get_plugin_activation_link(session, url)
    if not activate_link:
        return 1

    # Activate plugin
    if not activate_plugin(session, url, activate_link):
        return 1

    # Complete setup wizard
    if not complete_setup_wizard(session, url):
        return 1

    print("wpDiscuz plugin activated and setup completed.")
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Activate the wpDiscuz plugin.")
    parser.add_argument("url", help="The URL of the WordPress site.", type=str)
    parser.add_argument("admin", help="The administrative username.", type=str)
    parser.add_argument("password", help="The administrative password.", type=str)
    args = parser.parse_args()
    exit(activate(args.url, args.admin, args.password))
