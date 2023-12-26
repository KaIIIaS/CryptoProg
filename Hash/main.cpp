#include <iostream>
#include <fstream>
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
int main() {
    CryptoPP::MD5 hash;
    std::string message, result;

    // Открытие файла для чтения
    std::ifstream inputFile("input.txt");

    if (!inputFile.is_open()) {
        std::cerr << "Ошибка при открытии файла" << std::endl;
        return 1;
    }

    // Чтение содержимого файла
    getline(inputFile, message);

    // Хеширование сообщения
    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(result)
            )
        )
    );

    // Закрытие файла
    inputFile.close();

    // Открытие файла для записи
    std::ofstream outputFile("output.txt");

    if (!outputFile.is_open()) {
        std::cerr << "Ошибка при открытии файла" << std::endl;
        return 1;
    }

    // Запись результата в файл
    outputFile << result;

    // Закрытие файла
    outputFile.close();

    std::cout << "Хэш успешно записан в файл output.txt" << std::endl;

    return 0;
}
