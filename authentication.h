#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstdlib> 
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include <iostream>
#include <fstream>
#include <iostream>
#include <algorithm>

#define RSA_KEY_LEN 4096
#define OFFSET 7
#define OFFSET2 6
#define OFFSET3 9
#define PLAINTEXT_MAX_LEN RSA_KEY_LEN / 8 - 42
std::string globalString = "!@#$%^&)(^*()&*()(*^%^&$$%#$%^^*&$%#$%^$^&^";

std::string read_seed() {

    std::string concatenatedString;
    for (int i = 0; i < 5; ++i) {
        concatenatedString += globalString;
    }
    
    std::reverse(concatenatedString.begin(), concatenatedString.end()-OFFSET3+OFFSET2-OFFSET);
    
    return concatenatedString.substr(concatenatedString.length()/2-OFFSET3+OFFSET2-OFFSET);
}

std::string encrypt_decrypt(const std::string& text) {
    std::string key = read_seed();
    std::string result = text;

    for (size_t i = 0; i < text.size(); ++i) {
        result[i] = text[i] ^ key[i % key.size()];
    }

    return result;
}

bool checkRole(const std::string& name){
    std::ifstream file("filesystem/.metadata/users.txt");
    std::stringstream buffer;
    if (file.is_open()) {
        // Read the rest of the file as the seed
        buffer << file.rdbuf();
        file.close();
    } else {
        std::cerr << "Unable to open file: " << std::endl;
    }
    std::string adminName = encrypt_decrypt(buffer.str());
    if (adminName == name) {
    	std::cout << "You login as the Admin Role." << std::endl;
    	return true;
    }else{
    	std::cout << "You login as the normal Role." << std::endl;
    	return false;
    }
    
    
}

std::string rsa_encrypt(std::string plaintext, std::string username)
{   
    // 1. Load private key
    BIO *bp_private = nullptr;
    RSA *private_key = nullptr;
    unsigned char *encrypted = nullptr;
    int encrypted_length = 0;
    const char *dir_private_path = "filesystem/.private_keys";
    char private_key_path[256];
    snprintf(private_key_path, sizeof(private_key_path), "%s/%s_private.pem", dir_private_path, username.c_str());
    bp_private = BIO_new_file(private_key_path, "r");
    if (!bp_private) {
        // handle error
        std::cerr << "User not found!" << std::endl;
        std::exit(EXIT_FAILURE);
      
    }
    private_key = PEM_read_bio_RSAPrivateKey(bp_private, nullptr, nullptr, nullptr);
    // 2. Check plaintext
    if (plaintext.length() == 0 || plaintext.length() > PLAINTEXT_MAX_LEN) {
        throw std::invalid_argument("The plaintext is invalid.");
    }

    // 3. Encrypt the data with the private key
    int data_len = plaintext.length();
    encrypted = (unsigned char*)malloc(RSA_size(private_key));
    encrypted_length = RSA_private_encrypt(data_len, (unsigned char*)plaintext.c_str(), encrypted, private_key, RSA_PKCS1_PADDING);
    if (encrypted_length == -1) {
        // handle error
       
    }
    // 4. Free
    BIO_free_all(bp_private);
    
    return std::string((char*)encrypted, encrypted_length);
}

std::string rsa_decrypt(std::string cypher, std::string username)
{   

    BIO *bp_public = nullptr;
    RSA *public_key = nullptr;
    unsigned char *decrypted = nullptr;
    int decrypted_length = 0;
    
    // 1. Load public key
    const char *dir_public_path = "public_keys";
    char public_key_path[256];
    snprintf(public_key_path, sizeof(public_key_path), "%s/%s_public.pem", dir_public_path , username.c_str());
    bp_public = BIO_new_file(public_key_path, "r");
    if (!bp_public) {
        // handle error
      
    }
    public_key = PEM_read_bio_RSAPublicKey(bp_public, nullptr, nullptr, nullptr);

    // 2. Decrypt the data with the public key
    decrypted = (unsigned char*)malloc(decrypted_length);
    decrypted_length = RSA_public_decrypt(RSA_size(public_key), (unsigned char*)cypher.c_str(), decrypted, public_key, RSA_PKCS1_PADDING);
    if (decrypted_length == -1) {
        std::cerr << "Invalid public key!" << std::endl;
        std::exit(EXIT_FAILURE);
       
    }
    // 4. Free
    BIO_free_all(bp_public);
    return std::string((char*)decrypted, decrypted_length);
}

void create_user_dir(const std::string& name) {
    std::string system_root_path = "filesystem";
    std::string cypher = encrypt_decrypt(name);
    std::string dir_path = system_root_path + "/" + cypher;
    const char* full_dir_path = dir_path.c_str();
    mkdir(full_dir_path, S_IRWXU);
    
    std::string personal_path = system_root_path + "/" + cypher + "/" + encrypt_decrypt("personal");
    std::string shared_path = system_root_path + "/" + cypher + "/" + encrypt_decrypt("shared");
    mkdir(personal_path.c_str(), S_IRWXU);
    mkdir(shared_path.c_str(), S_IRWXU);
}

void generate_key_pair(const std::string& name_prefix) {
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;

    int             bits = RSA_KEY_LEN;
    unsigned long   e = RSA_F4;
 
    // 1. Generate RSA key
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if(ret != 1){
        // handle error
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        // handle error
    }

    // 2. Save public key
    const char *dir_public_path = "public_keys";
    char public_key_path[256];
    snprintf(public_key_path, sizeof(public_key_path), "%s/%s_public.pem", dir_public_path , name_prefix.c_str());
    BIO *bp_public = BIO_new_file(public_key_path, "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if(ret != 1){
        // handle error
    }
    
    const char *dir_private_path = "filesystem/.private_keys";
    char private_key_path[256];
    snprintf(private_key_path, sizeof(private_key_path), "%s/%s_private.pem", dir_private_path, name_prefix.c_str());
    // 3. Save private key
    BIO *bp_private = BIO_new_file(private_key_path, "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
    if(ret != 1){
        // handle error
    }
    
    //4. create user directory
    create_user_dir(name_prefix);

    // 5. Free
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);
}

bool validate_login(const std::string& name_prefix, const std::string& data) {
    RSA *private_key = nullptr, *public_key = nullptr;
    BIO *bp_public = nullptr, *bp_private = nullptr;
    unsigned char *encrypted = nullptr, *decrypted = nullptr;
    bool result = false;

    // Initialize variables
    int encrypted_length = 0;
    int decrypted_length = 0;

    // 1. Load private key
    const char *dir_private_path = "filesystem/.private_keys";
    char private_key_path[256];
    snprintf(private_key_path, sizeof(private_key_path), "%s/%s_private.pem", dir_private_path, name_prefix.c_str());
    bp_private = BIO_new_file(private_key_path, "r");
    if (!bp_private) {
        // handle error
        std::cerr << "User not found!" << std::endl;
        std::exit(EXIT_FAILURE);
      
    }
    private_key = PEM_read_bio_RSAPrivateKey(bp_private, nullptr, nullptr, nullptr);

    // 2. Encrypt the data with the private key
    int data_len = data.length();
    encrypted = (unsigned char*)malloc(RSA_size(private_key));
    encrypted_length = RSA_private_encrypt(data_len, (unsigned char*)data.c_str(), encrypted, private_key, RSA_PKCS1_PADDING);
    if (encrypted_length == -1) {
        // handle error
       
    }

    // 3. Load public key
    const char *dir_public_path = "public_keys";
    char public_key_path[256];
    snprintf(public_key_path, sizeof(public_key_path), "%s/%s_public.pem", dir_public_path , name_prefix.c_str());
    bp_public = BIO_new_file(public_key_path, "r");
    if (!bp_public) {
        // handle error
      
    }
    public_key = PEM_read_bio_RSAPublicKey(bp_public, nullptr, nullptr, nullptr);

    // 4. Decrypt the data with the public key
    decrypted = (unsigned char*)malloc(encrypted_length);
    decrypted_length = RSA_public_decrypt(encrypted_length, encrypted, decrypted, public_key, RSA_PKCS1_PADDING);
    if (decrypted_length == -1) {
        std::cerr << "Invalid public key!" << std::endl;
        std::exit(EXIT_FAILURE);
       
    }

    // 5. Validate
    result = (data == std::string((char*)decrypted, decrypted_length));

    return result;
}
