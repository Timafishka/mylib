import requests

publicationcode = 'acHnhJxpWL02'
admin_pass = input()

headers = {'Authorization': admin_pass}
response = requests.get(f'http://127.0.0.1:19502/pubapi-{publicationcode}')
title = response.json()['title']
response = requests.delete(f'http://127.0.0.1:19502/pubapi-{publicationcode}', headers=headers)
data = response.json()

if response.status_code == 200:
    print('Успешно удалено:', data['message'])
else:
    print('Ошибка:', data['message'])