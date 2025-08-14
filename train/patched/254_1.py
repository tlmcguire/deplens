
from html_to_csv import HtmlToCsv
from bs4 import BeautifulSoup

html_content = """
<table>
    <tr>
        <th>Name</th>
        <th>Score</th>
    </tr>
    <tr>
        <td>John Doe</td>
        <td>=HYPERLINK("http://malicious-link.com", "Click Here")</td>
    </tr>
    <tr>
        <td>Jane Smith</td>
        <td>95</td>
    </tr>
</table>
"""

def sanitize_html(html):
    soup = BeautifulSoup(html, 'html.parser')

    for td in soup.find_all('td'):
        if '=' in td.text:
            td.string = 'Formula removed'

    return str(soup)

sanitized_html = sanitize_html(html_content)

converter = HtmlToCsv()
csv_output = converter.convert(sanitized_html)

with open('output.csv', 'w') as file:
    file.write(csv_output)

print("CSV file created successfully with sanitized content.")