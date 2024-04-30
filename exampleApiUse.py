import requests

publicationcode = 'jasaIx9LsDN7'  # Замените на реальный publicationcode
response = requests.get(f'http://127.0.0.1:19502/pubapi-{publicationcode}')
data = response.json()

if response.status_code == 200:
    print('Название произведения:', data['title'])
    print('Текст произведения:', data['text'])
else:
    print('Ошибка:', data['message'])
