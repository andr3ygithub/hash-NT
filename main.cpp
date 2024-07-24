#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>

// Компилятору нужно знать, что мы используем библиотеку Crypt32.lib
#pragma comment(lib, "Crypt32.lib")

using namespace std;

// Функция для хеширования пароля в NTLM
string ntlmHash(const string& password) {
    // Создаем контекст криптографии
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        // Если контекст не создан, возвращаем пустую строку
        return "";
    }

    // Создаем хеш-объект
    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_MD4, 0, 0, &hHash)) {
        // Если хеш-объект не создан, освобождаем контекст и возвращаем пустую строку
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Конвертируем пароль в wchar_t для использования в CryptHashData
    wchar_t passwordW[1024];
    mbstowcs(passwordW, password.c_str(), password.size() + 1);

    // Хешируем пароль
    if (!CryptHashData(hHash, (const BYTE*)passwordW, password.size() * 2, 0)) {
        // Если хеширование не удалось, освобождаем хеш-объект и контекст
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Получаем хеш-значение
    BYTE hash[16];
    DWORD hashLen = 16;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        // Если получение хеш-значения не удалось, освобождаем хеш-объект и контекст
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Конвертируем хеш-значение в строку
    string hashStr;
    for (int i = 0; i < 16; i++) {
        char buf[5];
        sprintf(buf, "%02x", hash[i]);
        hashStr += buf;
    }

    // Освобождаем хеш-объект и контекст
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // Возвращаем хеш-строку
    return hashStr;
}

int main() {
    // Вводим имя файла с паролями
    string filename;
    cout << "Enter filename: ";
    cin >> filename;

    // Открываем файл с паролями для чтения
    ifstream fileIn(filename);
    if (!fileIn) {
        // Если файл не открыт, выводим ошибку и завершаем программу
        cerr << "Error opening file" << endl;
        return 1;
    }

    // Создаем имя файла для вывода результатов
    string outputFile = "file.txt";

    // Открываем файл для вывода результатов
    ofstream fileOut(outputFile);

    if (!fileOut) {
        // Если файл не открыт, выводим ошибку и завершаем программу
        cerr << "Error opening output file" << endl;
        return 1;
    }

    // Читаем файл с паролями построчно
    string password;
    while (getline(fileIn, password)) {
        // Хешируем пароль
        string hash = ntlmHash(password);

        // Выводим результат в файл
        fileOut << password << " -> " << hash << endl;
    }

    // Закрываем файлы
    fileIn.close();
    fileOut.close();

    // Завершаем программу
    return 0;
}
