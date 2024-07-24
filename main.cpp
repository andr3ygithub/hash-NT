#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>

// ����������� ����� �����, ��� �� ���������� ���������� Crypt32.lib
#pragma comment(lib, "Crypt32.lib")

using namespace std;

// ������� ��� ����������� ������ � NTLM
string ntlmHash(const string& password) {
    // ������� �������� ������������
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        // ���� �������� �� ������, ���������� ������ ������
        return "";
    }

    // ������� ���-������
    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, CALG_MD4, 0, 0, &hHash)) {
        // ���� ���-������ �� ������, ����������� �������� � ���������� ������ ������
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // ������������ ������ � wchar_t ��� ������������� � CryptHashData
    wchar_t passwordW[1024];
    mbstowcs(passwordW, password.c_str(), password.size() + 1);

    // �������� ������
    if (!CryptHashData(hHash, (const BYTE*)passwordW, password.size() * 2, 0)) {
        // ���� ����������� �� �������, ����������� ���-������ � ��������
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // �������� ���-��������
    BYTE hash[16];
    DWORD hashLen = 16;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        // ���� ��������� ���-�������� �� �������, ����������� ���-������ � ��������
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // ������������ ���-�������� � ������
    string hashStr;
    for (int i = 0; i < 16; i++) {
        char buf[5];
        sprintf(buf, "%02x", hash[i]);
        hashStr += buf;
    }

    // ����������� ���-������ � ��������
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // ���������� ���-������
    return hashStr;
}

int main() {
    // ������ ��� ����� � ��������
    string filename;
    cout << "Enter filename: ";
    cin >> filename;

    // ��������� ���� � �������� ��� ������
    ifstream fileIn(filename);
    if (!fileIn) {
        // ���� ���� �� ������, ������� ������ � ��������� ���������
        cerr << "Error opening file" << endl;
        return 1;
    }

    // ������� ��� ����� ��� ������ �����������
    string outputFile = "file.txt";

    // ��������� ���� ��� ������ �����������
    ofstream fileOut(outputFile);

    if (!fileOut) {
        // ���� ���� �� ������, ������� ������ � ��������� ���������
        cerr << "Error opening output file" << endl;
        return 1;
    }

    // ������ ���� � �������� ���������
    string password;
    while (getline(fileIn, password)) {
        // �������� ������
        string hash = ntlmHash(password);

        // ������� ��������� � ����
        fileOut << password << " -> " << hash << endl;
    }

    // ��������� �����
    fileIn.close();
    fileOut.close();

    // ��������� ���������
    return 0;
}
