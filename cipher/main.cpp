/**
@brief Создатель Маслинов А.А.
@warning Программа зашифрования и расшифрования с использованием алгоритма AES
 */
#include <iostream>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cstring>
#include <fstream>

void encrypt(std::string keystr,const char * orig_file,const char * encr_file,const char * iv_file){
    try{
    CryptoPP::SHA256 hash;
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::PKCS12_PBKDF<CryptoPP::SHA256> pbkdf;
    pbkdf.DeriveKey(key,key.size(),0,reinterpret_cast<const CryptoPP::byte*>(keystr.data()),keystr.size(),nullptr,0,1000,0.0f); //Генерация ключа на основе переданного пароля и соли
    CryptoPP::AutoSeededRandomPool prng; //Генерация случайного вектора инициализации с помощью объекта prng,
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    prng.GenerateBlock(iv, iv.size());
    //Сохранение вектора в файл
    CryptoPP::StringSource(iv, iv.size(), true,
                            new CryptoPP::HexEncoder(
                                new CryptoPP::FileSink(iv_file)));                        
    std::clog << "IV сгенерирован " << iv_file << std::endl;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encr;
    encr.SetKeyWithIV( key, key.size(), iv );
    CryptoPP::FileSource (orig_file, true,
                            new CryptoPP::StreamTransformationFilter(encr,
                                    new CryptoPP::FileSink(encr_file)));
    std::clog << "Файл " << orig_file << " зашифрован и сохранён в: " << encr_file << std::endl;
    }
    catch( const CryptoPP::Exception& e ) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}

void decrypt(std::string keystr,const char * encr_file,const char * decr_file,const char * iv_file){
    try{
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::SHA256 hash;
    CryptoPP::PKCS12_PBKDF<CryptoPP::SHA256> pbkdf;
    pbkdf.DeriveKey(key,key.size(),0,reinterpret_cast<const CryptoPP::byte*>(keystr.data()),keystr.size(),nullptr,0,1000,0.0f);
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    //Чтение вектора инициализации из файла
    CryptoPP::FileSource(iv_file, true,
                            new CryptoPP::HexDecoder(
                                new CryptoPP::ArraySink(iv, iv.size())));
    std::clog << "IV считан " << iv_file << std::endl;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decr;
    decr.SetKeyWithIV(key, key.size(), iv);
    CryptoPP::FileSource (encr_file, true, 
                            new CryptoPP::StreamTransformationFilter(decr,
                                    new CryptoPP::FileSink(decr_file)));
    std::clog << "Файл " << encr_file << " расшифрован и сохранён " << decr_file << std::endl;
    }
    catch( const CryptoPP::Exception& e ) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}
int main() {
    CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout));
    while (true){
    std::string type;
    std::cout<<"Выберите тип оперцации: "<<std::endl;
    std::cout<<"0 - выйти из программы; "<<std::endl;
    std::cout<<"e - зашифровать; "<<std::endl;
    std::cout<<"d - расшифровать. "<<std::endl;
    std::cin>>type;
    if(type=="e"){
        std::string key;
        std::cout<<"Введите ключ"<<std::endl;
        std::cin>>key;

        std::string orig_file;
        std::cout<<"Введите название файла для зашифрования"<<std::endl;
        std::cin>>orig_file;

        std::string en_file;
        std::cout<<"Введите название файла для результа зашифрования"<<std::endl;
        std::cin>>en_file;

        std::string iv_file;
        std::cout<<"Введите имя файла для сохранения IV"<<std::endl;
        std::cin>>iv_file;

        encrypt(key,orig_file.c_str(),en_file.c_str(),iv_file.c_str());

    }
    else if(type == "d"){
        std::string key;
        std::cout<<"Введите ключ"<<std::endl;
        std::cin>>key;

        std::string enc_file;
        std::cout<<"Введите название файла для расшифрования"<<std::endl;
        std::cin>>enc_file;

        std::string dec_file;
        std::cout<<"Введите название файла для результа расшифрования"<<std::endl;
        std::cin>>dec_file;

        std::string iv_file;
        std::cout<<"Введите имя файла для сохранения IV"<<std::endl;
        std::cin>>iv_file;

        decrypt(key,enc_file.c_str(),dec_file.c_str(),iv_file.c_str());
    }
    else if(type=="0"){
        std::cout<<"Программа завершена"<<std::endl;
        return 0;
    }
    else{
        std::cout<<"Неверный тип операции"<<std::endl;
        return 0;
        }
    }
    return 0;
}
