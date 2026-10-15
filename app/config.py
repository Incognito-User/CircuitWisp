# app/config.py
import os

# Load environment variables
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# Optional future integrations
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")

def config_status():
    return {
        "shodan": "configured" if SHODAN_API_KEY else "missing",
        "greynoise": "configured" if GREYNOISE_API_KEY else "missing",
        "github": "configured" if GITHUB_TOKEN else "missing",
        "epss": "public",
        "kev": "public",
        "nvd": "public",
        "exploitdb": "public",
        "metasploit": "public",
        "vendor": "public",
        "rss": "public",
    }
