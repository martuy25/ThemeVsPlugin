import requests
from bs4 import BeautifulSoup
#Constructing the URL (theme vs plugin) for searching vulnerabilities
def search_wordfence(plugin_or_theme, query):
    if plugin_or_theme.lower() == "plugin":
        url = f"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins?q={query}"
        item_type = "plugin"
    elif plugin_or_theme.lower() == "theme":
        url = f"https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-themes?q={query}"
        item_type = "theme"
    else:
        print("Invalid option. Please choose 'plugin' or 'theme'.")
        return
    
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table', class_='threat-intel-software-table')
        
        if table:
            rows = table.find_all('tr')
            if len(rows) > 1:  # Check if there are rows other than the header row
                print(f"Total vulnerabilities found for {item_type} '{query}': {len(rows) - 1}\n")  # Subtract 1 to exclude header row
                print(f"Vulnerabilities found for {item_type} '{query}':\n")
                for row in rows[1:]:  # Skip the header row
                    cells = row.find_all('td')
                    if len(cells) >= 3:
                        name = cells[0].find('a').text.strip()
                        link = cells[0].find('a')['href']
                        num_vulnerabilities = cells[1].text.strip()
                        last_vulnerability = cells[2].text.strip()
                        print(f"Name: {name}")
                        print(f"Number of Vulnerabilities: {num_vulnerabilities}")
                        print(f"Last Vulnerability: {last_vulnerability}")
                        print(f"Vulnerability Link: {link}")
                        print("-" * 50)
            else:
                print(f"No vulnerabilities found for {item_type} '{query}'.")
        else:
            print(f"No table found for {item_type} '{query}'.")
    else:
        print(f"Failed to retrieve data from {url}. Status code: {response.status_code}")

# searching plugins
search_wordfence("plugin", "kadence")

# searching themes
search_wordfence("theme", "elementor")
