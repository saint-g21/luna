import json
from playwright.sync_api import sync_playwright

def scrape_github_repo(username, repo_name):
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        # Navigate to the repository page
        url = f"https://github.com/{username}/{repo_name}"
        page.goto(url)

        try:
            code_elements = page.query_selector_all("pre code")
        except Exception as e:
            print(f"Error fetching code elements: {e}")
            browser.close()
            return

        # Extract the code from each element
        codes = []
        for element in code_elements:
            try:
                code = element.text_content()
                codes.append(code)
            except Exception as e:
                print(f"Error extracting code from element: {e}")

        # Close the browser and exit
        browser.close()

    return {'username': username, 'repo_name': repo_name, 'codes': codes}

if __name__ == "__main__":
    try:
        username = "octocat"
        repo_name = "Hello-World"
        data = scrape_github_repo(username, repo_name)
        print(json.dumps(data, indent=4))
    except Exception as e:
        print(f"Error: {e}")
