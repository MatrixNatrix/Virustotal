import requests
import zipfile
import pandas as pd
import json

# Загрузка архива по URL
url = "https://drive.google.com/uc?id=1ObNjHoXNIgc2iZ5QXGkYa4BRyapDNkbi"
response = requests.get(url)

with open("protected_archive.zip", "wb") as file:
    file.write(response.content)

# Распаковка архива с паролем "netology"
with zipfile.ZipFile("protected_archive.zip", "r") as zip_ref:
    zip_ref.extractall("extracted_folder", pwd=b"netology")

# Путь к файлу после распаковки
file_path = "extracted_folder/invoice-42369643.html"

# Дальнейшая обработка файла
api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
params = dict(apikey='тут надо ввести свой')

with open(file_path, 'rb') as file:
    files = dict(file=(file_path, file))
    response = requests.post(api_url, files=files, params=params)

    if response.status_code == 200:
        result = response.json()
        sha256_hash = result.get('sha256', '')  # Извлечь sha256 из результата первого запроса

        # Запрос для получения результатов сканирования
        url_scan_results = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        headers_scan_results = {
            "accept": "application/json",
            "x-apikey": "тут надо ввести свой"
        }
        response_scan_results = requests.get(url_scan_results, headers=headers_scan_results)

        if response_scan_results.status_code == 200:
            result_json = response_scan_results.json()
            antivirus_results = result_json.get('data', {}).get('attributes', {}).get('last_analysis_results', {})

            data = []
            for antivirus, info in antivirus_results.items():
                method = info.get("method", "")
                engine_name = info.get("engine_name", "")
                engine_version = info.get("engine_version", "")
                engine_update = info.get("engine_update", "")
                category = info.get("category", "")
                result = info.get("result", "")

                data.append([antivirus, method, engine_name, engine_version, engine_update, category, result])

            df = pd.DataFrame(data, columns=["Antivirus", "Method", "Engine Name", "Engine Version", "Engine Update", "Category", "Result"])
            pd.set_option('display.max_rows', None)  # Показать все строки без обрезки
            print("Результаты сканирования:")
            print(df)

            # Запрос для получения данных о поведении файла
            url_behaviours = f"https://www.virustotal.com/api/v3/files/{sha256_hash}/behaviours"
            headers_behaviours = {
                "accept": "application/json",
                "x-apikey": "тут надо ввести свой"
            }
            response_behaviours = requests.get(url_behaviours, headers=headers_behaviours)

            if response_behaviours.status_code == 200:
                result_behaviours = response_behaviours.json()
                print("\nДанные о поведении файла:")
                print(json.dumps(result_behaviours, indent=4))

                # Сохранение итогового результата на диск в формате JSON
                with open("C:/Users/Tech_/Downloads/final_result.json", "w") as json_file:
                    final_result = {
                        "scan_results": result_json,
                        "behaviour_data": result_behaviours
                    }
                    json.dump(final_result, json_file, indent=4)
                    print("Итоговый результат сохранен на диск в файле 'final_result.json'.")
            else:
                print("Ошибка при получении данных о поведении файла.")
        else:
            print("Ошибка при получении результатов сканирования.")
    else:
        print("Ошибка при отправке файла на сканирование.")