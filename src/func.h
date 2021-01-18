#include "group.h"
/**
 * @brief 生成Elgamal的公私钥对。用户可以根据个人需求选择生成公私钥对或者从文件中导入公私钥对
 * @param privatekey 
 * @param publickey 
 * @param tag 
 */
inline void generate_elgamal(ElGamalKeys::PrivateKey &privatekey, ElGamalKeys::PublicKey &publickey, bool tag) {
    //cout << "Generating private key. This may take some time..." << endl;
    // 生成私钥对
    if (tag) {
        AutoSeededRandomPool rng;
        privatekey.GenerateRandomWithKeySize(rng, 1024);
        ElGamal::Decryptor decryptor(privatekey);
        ElGamal::Encryptor encryptor(decryptor);
        publickey = encryptor.AccessKey();
    }
    // 从文件导入公私钥对 
    else {
        privatekey.Load(FileSource(elgamal_key_priv.c_str(), true, NULL, true /*binary*/).Ref());
        publickey.Load(FileSource(elgamal_key_pub.c_str(), true, NULL, true /*binary*/).Ref());
    }
    return;
}

/**
 * @brief 生成DSA签名密钥对
 * @param role_signprivatekey 
 * @param role_signpublickey 
 * @param tag 
 */
inline void generate_dsa(DSA::PrivateKey &role_signprivatekey, DSA::PublicKey &role_signpublickey, bool tag) {
    if (tag) {
        AutoSeededRandomPool rng;
        role_signprivatekey.GenerateRandomWithKeySize(rng, 1024);
        role_signpublickey.AssignFrom(role_signprivatekey);
        if (!role_signprivatekey.Validate(rng, 3) || !role_signpublickey.Validate(rng, 3)) {
            cout << "DSA key generate fail" << endl;
        }
    } else {
        role_signprivatekey.Load(FileSource(sign_key_priv.c_str(), true, NULL, true /*binary*/).Ref());
        role_signpublickey.Load(FileSource(sign_key_pub.c_str(), true, NULL, true /*binary*/).Ref());
    }
    return;
}

/**
 * @brief 产生elgamal的公私钥对(生成新的用户)
 * @param username 
 */
void generate_user(std::string username) {
    cout << "Generating " + username << endl;
    // 生成公私钥对
    ElGamalKeys::PrivateKey privatekey;
    ElGamalKeys::PublicKey publickey;
    generate_elgamal(privatekey, publickey, false);
    // 将公私钥编码放入User中
    std::string pvkey;
    std::string pbkey;
    trans_elgamalsk_to_string(pvkey, privatekey);
    trans_elgamalpk_to_string(pbkey, publickey);

    DSA::PrivateKey role_signprivatekey;
    DSA::PublicKey role_signpublickey;
    generate_dsa(role_signprivatekey, role_signpublickey, false);
    // 将签名密钥密钥对编码放入User中
    std::string pvsign;
    std::string pbsign;
    trans_dsa_signsk_to_string(pvsign, role_signprivatekey);
    trans_dsa_signpk_to_string(pbsign, role_signpublickey);

    User user(username, pvkey, pbkey, pvsign, pbsign, "", "");
    user.serial();
}

/**
 * @brief 生成新的角色
 * @param rolename 
 */
void generate_role(std::string rolename) {
    cout << "Generating " + rolename << endl;

    ElGamalKeys::PrivateKey privatekey;
    ElGamalKeys::PublicKey publickey;
    generate_elgamal(privatekey, publickey, false);
    // 将公私钥编码放入Role中
    std::string pvkey;
    std::string pbkey;
    trans_elgamalsk_to_string(pvkey, privatekey);
    trans_elgamalpk_to_string(pbkey, publickey);
    // 将签名密钥对放入Role中
    DSA::PrivateKey role_signprivatekey;
    DSA::PublicKey role_signpublickey;
    generate_dsa(role_signprivatekey, role_signpublickey, false);

    std::string pvsign;
    std::string pbsign;
    trans_dsa_signsk_to_string(pvsign, role_signprivatekey);
    trans_dsa_signpk_to_string(pbsign, role_signpublickey);

    Role role(rolename, 0, pvkey, pbkey, pvsign, pbsign);
    role.serial();
}

/**
 * @brief 生成新的文件
 * @param filename 
 */
void generate_file(std::string filename) {
    cout << "Generating " + filename << endl;
    File f;
    f._filename = filename;
    //ifstream rfile((FILES+"file.txt").c_str(),ios::binary);
    //if(!rfile) cout<<"open file.txt fail in generate_file";
    int size = 100100;

    f._content = "qwertyuiop";
    f._content.resize(size);
    //f._content.resize(size+1);
    //rfile.read((char*)f._content.c_str(),size);
    cipher_fk part;
    generate_aeskey(part.k_0);
    part.k_t = part.k_0;
    part.t = 1;
    trans_zz_to_string(rpk, part.rpk);
    part.serial(f._key);
    f.serial();
    //同时生成元组F
    F file;
    file.filename = filename;
    string iv(16, 0);
    aes_e(part.k_0, file.crypto_file, f._content);

    DSA::PrivateKey privatekey;
    privatekey.Load(FileSource(sign_key_priv.c_str(), true, NULL, true /*binary*/).Ref());
    // DSA签名私钥对已AES加密的文件进行签名
    file.sign(privatekey);
    serial_to_file(file);

    //rfile.close();
    cout << "file complete" << endl;
}


/**
 * @brief 正常签名函数，不涉及可变签名(为指定字符串签名)
 * @param privatekey 
 * @param message 
 * @param signature 
 */
void sign(DSA::PrivateKey &privatekey, std::string &message, std::string &signature) {
    AutoSeededRandomPool rng;
    DSA::Signer signer(privatekey);
    StringSource ss1(message, true, new SignerFilter(rng, signer, new StringSink(signature))); // std::stringSource
    return;
}


/**
 * @brief 加密函数(elgamal加密)，对内部加密函数进行了进一步的封装：将明文通过加密器加密成密文
 * @param encryptor 
 * @param plaintext 
 * @param ciphertext 
 */
void encrypt(ElGamal::Encryptor &encryptor, std::string &plaintext, std::string &ciphertext) {
    AutoSeededRandomPool rng;
    int str_size = 125; //切片大小
    if (plaintext.size() <= str_size) {
        size_t ecl = encryptor.CiphertextLength(plaintext.size());
        ciphertext.resize(ecl);
        encryptor.Encrypt(rng, (byte *)plaintext.c_str(), plaintext.size(), (byte *)ciphertext.c_str());
        return;
    }
    int size = plaintext.size() / str_size + 1;
    vector<std::string> plain(size);
    vector<std::string> cipher(size);
    for (int i = 0; i < size; i++) {
        if (i * str_size + str_size > plaintext.size())
            plain[i] = plaintext.substr(i * str_size, plaintext.size() - i * str_size + 1);
        plain[i] = plaintext.substr(i * str_size, str_size);
        size_t ecl = encryptor.CiphertextLength(plain[i].size());
        cipher[i].resize(ecl);
        encryptor.Encrypt(rng, (byte *)plain[i].c_str(), plain[i].size(), (byte *)cipher[i].c_str());
        ciphertext = ciphertext + cipher[i];
    }
}

/**
 * @brief 解密字符串
 * @param decryptor 
 * @param recovered 
 * @param ciphertext 
 */
void decrypt(ElGamal::Decryptor &decryptor, std::string &recovered, std::string &ciphertext) {
    AutoSeededRandomPool rng;
    int str_size = 256; //这里的切片大小和encrypt的是配套的
    int size = ciphertext.size() / str_size;
    vector<std::string> cipher(size);
    vector<std::string> recover(size);
    for (int i = 0; i < size; i++) {
        cipher[i] = ciphertext.substr(i * str_size, str_size);
        size_t dpl = decryptor.MaxPlaintextLength(cipher[i].size());
        recover[i].resize(dpl);
        DecodingResult result = decryptor.Decrypt(rng, (byte *)cipher[i].c_str(), cipher[i].size(), (byte *)recover[i].c_str());
        recover[i].resize(result.messageLength);
        recovered = recovered + recover[i];
    }
}
/**
 * @brief 初始化生成num个用户
 * @param num 
 * @param username 
 */
void init_users(int num, vector<std::string> &username) {
    for (int i = 0; i < num; i++) {
        string tmp("user" + to_string(i));
        username.push_back(tmp);
        generate_user(tmp);
    }
    return;
}

/**
 * @brief 初始化生成num个角色
 * @param num 
 * @param rolename 
 */
void init_roles(int num, vector<std::string> &rolename) {
    for (int i = 0; i < num; i++) {
        string tmp("role" + to_string(i));
        rolename.push_back(tmp);
        generate_role(tmp);
    }
    return;
}

/**
 * @brief 初始化生成num个文件
 * @param num 
 * @param filename 
 */
void init_files(int num, vector<std::string> &filename) {
    for (int i = 0; i < num; i++) {
        string tmp("file" + to_string(i));
        filename.push_back(tmp);
        generate_file(tmp);
    }
    return;
}

/**
 * @brief 生成拓扑关系,通过这个函数可以调整拓扑关系的生成
 * @param username 
 * @param usernum 
 * @param rolename 
 * @param rolenum 
 * @param filename 
 * @param filenum 
 * @param user_role 
 * @param role_file 
 */
void init_topu(vector<std::string> &username, int usernum, vector<std::string> &rolename, int rolenum, vector<std::string> &filename, int filenum, vector<pair_user_role> &user_role, vector<pair_role_file> &role_file) {
    for (int i = 0; i < usernum; i++) {
        for (int j = 0; j < rolenum; j++) {
            pair_user_role tmp(username[i], rolename[j], 0);
            user_role.push_back(tmp);
        }
    }
    for (int i = 0; i < rolenum; i++) {
        for (int j = 0; j < filenum; j++) {
            pair_role_file tmp(rolename[i], filename[j], 'w', 0, 0);
            role_file.push_back(tmp);
        }
    }
    return;
}

/**
 * @brief 将拓扑生成的映射关系初始化并存入RK，FK元组
 * @param user_role 
 * @param role_file 
 */
void init(vector<pair_user_role> &user_role, vector<pair_role_file> &role_file) {
    DSA::PrivateKey privatekey;
    // 从文件里加载签名私钥
    privatekey.Load(FileSource(sign_key_priv.c_str(), true, NULL, true /*binary*/).Ref());
    for (int i = 0; i < user_role.size(); i++) {
        std::string username = user_role[i]._username;
        std::string rolename = user_role[i]._rolename;
        int version = user_role[i]._version;

        User user;
        Role role;
        user.unserial(username);
        role.unserial(rolename);
        // 拿出用户u的公钥
        ElGamalKeys::PublicKey publickey;
        trans_elgamalpk_from_string(user._pbkey, publickey);
        ElGamal::Encryptor encryptor(publickey);
        std::string rolekey;
        std::string rolesign;
        encrypt(encryptor, role._pvkey, rolekey);
        encrypt(encryptor, role._pvsign, rolesign);

        RK rk;
        rk.username = username;
        rk.rolename = rolename;
        rk.crypto_rolekey = rolekey;
        rk.crypto_rolesign = rolesign;
        // 对RK元组签名
        rk.sign(privatekey);
        // 序列化至文件
        serial_to_file(rk);
    }

    for (int i = 0; i < role_file.size(); i++) {
        std::string rolename = role_file[i]._rolename;
        std::string filename = role_file[i]._filename;

        Role role;
        File file;
        role.unserial(rolename);
        file.unserial(filename);
        ElGamalKeys::PublicKey publickey;
        trans_elgamalpk_from_string(role._pbkey, publickey);
        ElGamal::Encryptor encryptor(publickey);

        FK fk;
        fk.rolename = rolename;
        fk.filename = filename;
        fk.version_role = 0;
        fk.version_file = 0;
        fk.operation = 'w';
        fk.tag = false;

        encrypt(encryptor, file._key, fk.cipher_fk);

        fk.sign(privatekey);
        serial_to_file(fk);
    }

    return;
}

/**
 * @brief 读文件函数
 * @param username 
 * @param filename 
 * @param user_role 
 * @param role_file 
 */
void File_read(string username, string filename, vector<pair_user_role> &user_role, vector<pair_role_file> &role_file) {
    pair_user_role tmp_user_role; //暂时存放rk相关信息
    pair_role_file tmp_role_file; //暂时存放FK相关信息
    for (int i = 0; i < user_role.size(); i++) {
        if (username == user_role[i]._username) {
            for (int j = 0; j < role_file.size(); j++) {
                if (user_role[i]._rolename == role_file[j]._rolename && role_file[j]._filename == filename) {
                    tmp_user_role = user_role[i];
                    tmp_role_file = role_file[j];
                }
            }
        }
    }

    string role = tmp_user_role._rolename;
    if (role == "") {
        cout << "this user can not access this file" << endl;
        return;
    }
    RK rk;
    FK fk;
    F f;
    unserial_from_file(rk, username + "_" + role + "_" + to_string(tmp_user_role._version) + suffix);
    unserial_from_file(fk, role + "_" + filename + "_" + to_string(tmp_role_file.version_role) + "_" + to_string(tmp_role_file.version_file) + suffix);
    unserial_from_file(f, filename + suffix);

    User user;
    user.unserial(username);
    ElGamalKeys::PrivateKey privatekey_user;
    trans_elgamalsk_from_string(user.get_pvkey(), privatekey_user);
    ElGamal::Decryptor decryptor_user(privatekey_user);
    string pvkey_role;
    decrypt(decryptor_user, pvkey_role, rk.crypto_rolekey);

    //解密文件密钥K
    ElGamalKeys::PrivateKey privatekey_role; //role的私钥
    trans_elgamalsk_from_string(pvkey_role, privatekey_role);
    ElGamal::Decryptor decryptor_role(privatekey_role);
    string key_list;
    decrypt(decryptor_role, key_list, fk.cipher_fk);
    cipher_fk c;
    c.unserial(key_list);
    string plain;
    aes_file(c, f, plain);

    cout << plain << endl;
    return;
}

/**
 * @brief user读文件测试
 * @param username 
 * @param filename 
 * @param user_role 
 * @param role_file 
 */
void File_read_test(string username, string filename, vector<pair_user_role> &user_role, vector<pair_role_file> &role_file) {
    pair_user_role tmp_user_role; //暂时存放rk相关信息
    pair_role_file tmp_role_file; //暂时存放FK相关信息
    // 判断是否存在这样的元组，如果不存在说明这个用户没有这个文件的相关权限
    for (int i = 0; i < user_role.size(); i++) {
        if (username == user_role[i]._username) {
            for (int j = 0; j < role_file.size(); j++) {
                if (user_role[i]._rolename == role_file[j]._rolename && role_file[j]._filename == filename) {
                    tmp_user_role = user_role[i];
                    tmp_role_file = role_file[j];
                }
            }
        }
    }

    string role = tmp_user_role._rolename;
    if (role == "") {
        cout << "this user can not access this file" << endl;
        return;
    }
    RK rk;
    FK fk;
    F f;
    unserial_from_file(rk, username + "_" + role + "_" + to_string(tmp_user_role._version) + suffix);
    unserial_from_file(fk, role + "_" + filename + "_" + to_string(tmp_role_file.version_role) + "_" + to_string(tmp_role_file.version_file) + suffix);
    unserial_from_file(f, filename + suffix);

    User user;
    user.unserial(username);
    ElGamalKeys::PrivateKey privatekey_user;
    trans_elgamalsk_from_string(user.get_pvkey(), privatekey_user);
    ElGamal::Decryptor decryptor_user(privatekey_user);
    string pvkey_role;
    // 解密rk元组中被加密的角色密钥放进pvkey_role
    decrypt(decryptor_user, pvkey_role, rk.crypto_rolekey);

    //解密文件密钥K
    ElGamalKeys::PrivateKey privatekey_role; //role的私钥
    trans_elgamalsk_from_string(pvkey_role, privatekey_role);
    ElGamal::Decryptor decryptor_role(privatekey_role);
    string key_list;
    // 解密FK元组获取密钥列表key_list
    decrypt(decryptor_role, key_list, fk.cipher_fk);
    cipher_fk c;
    c.unserial(key_list);
    string plain;

    string test;
    test.resize(100000000);
    f.crypto_file = test;
    aes_file(c, f, plain);
    // 解密出的内容最终放入到了plain里面
    //cout<<plain<<endl;
    return;
}

/**
 * @brief 写文件函数
 * @param filename 
 * @param file 
 * @param role_file 
 * @return int 
 */
int File_write(string filename, string &file, vector<pair_role_file> &role_file) {
    for (int i = 0; i < role_file.size(); i++) {
        if (role_file[i]._filename == filename) {
            FK tmp;
            string tuple_name = role_file[i]._rolename + "_" + role_file[i]._filename + "_" + to_string(role_file[i].version_role) + "_" + to_string(role_file[i].version_file) + suffix;
            unserial_from_file(tmp, tuple_name);
            ElGamalKeys::PrivateKey privatekey;
            Role r;
            r.unserial(role_file[i]._rolename);
            trans_elgamalsk_from_string(r._pvkey, privatekey);
            ElGamal::Decryptor decryptor(privatekey);
            string tmp2;
            // 解密FK元组获得密钥列表tmp2
            decrypt(decryptor, tmp2, tmp.cipher_fk);
            cipher_fk fk_help;
            fk_help.unserial(tmp2);
            string cipher;
            // 对写入内容进行加密，加密后存入cipher
            aes_file_e(fk_help, cipher, file);
            write_to_file(UPDATES, cipher);
            break;
        }
    }
    return 1;
}

// TODO
int File_write_more(string filename, string &file, vector<pair_role_file> &role_file, int count) {
    for (int i = 0; i < role_file.size(); i++) {
        if (role_file[i]._filename == filename) {
            FK tmp;
            string tuple_name = role_file[i]._rolename + "_" + role_file[i]._filename + "_" + to_string(role_file[i].version_role) + "_" + to_string(role_file[i].version_file) + suffix;
            unserial_from_file(tmp, tuple_name);
            ElGamalKeys::PrivateKey privatekey;
            Role r;
            r.unserial(role_file[i]._rolename);
            trans_elgamalsk_from_string(r._pvkey, privatekey);
            ElGamal::Decryptor decryptor(privatekey);
            string tmp2;
            decrypt(decryptor, tmp2, tmp.cipher_fk);
            cipher_fk fk_help;
            fk_help.unserial(tmp2);
            string cipher;
            // TODO
            aes_file_e_more_test(fk_help, cipher, file, count);
            write_to_file(UPDATES, cipher);
            break;
        }
    }
    return 1;
}

/**
 * @brief 用户权限撤销：委托云更新F元组
 * @param username 
 * @param rolename 
 * @param user_role 
 * @param role_file 
 */
void User_revocation_F(std::string username, std::string rolename, vector<pair_user_role> &user_role, vector<pair_role_file> &role_file) {
    cout << "User_revocation_F..." << endl;
    AutoSeededRandomPool prng;
    //第一层循环遍历属于role的所有file，第二层循环遍历相关file的所有role，重新生成FK，版本号加一
    // TODO：理解注释掉的代码
    for (int i = 0; i < role_file.size(); i++) {
        if (role_file[i]._rolename == rolename) {
            //生成新的AES密钥
            //File f;
            //f.unserial(role_file[i]._filename);
            FK fk;
            //18-3-29
            //unserial_from_file(fk,rolename+"_"+role_file[i]._filename+"_"+to_string(role_file[i].version_role)+"_"+to_string(role_file[i].version_file)+suffix);

            Role r;
            r.unserial(rolename);
            ElGamalKeys::PrivateKey privatekey;
            trans_elgamalsk_from_string(r._pvkey, privatekey);
            ElGamal::Decryptor decryptor(privatekey);
            string file_key;
            //18-3-29
            //decrypt(decryptor,file_key,fk.cipher_fk);

            cipher_fk tmp;
            //18-3-29
            //tmp.unserial(file_key);
            ZZ k_t;

            //18-3-29
            //trans_zz_from_string(k_t,tmp.k_t);
            ZZ next = BDri(rsk, k_t, N);
            string new_key_t;
            trans_zz_to_string(next, new_key_t);
            tmp.k_t = new_key_t;
            if (tmp.t < 20)
                tmp.t++;
            string data;
            tmp.serial(data);
            //18-3-29
            //write_to_file(UPDATES,new_key_t);
            write_to_file(UPDATES, group::p_t);
        }
    }
    //send_to_server();
    return;
}

/**
 * @brief 用户权限撤销：委托云提供商更新RK与FK元组
 * @param username 
 * @param rolename 
 * @param user_role 
 * @param role_file 
 */
void User_revocation_RK_FK(std::string username, std::string rolename, vector<pair_user_role> &user_role, vector<pair_role_file> &role_file) {
    cout << "User_revocation_rk_fk..." << endl;
    AutoSeededRandomPool rng;
    // 为role生成elgamal公私钥对(生成新的角色密钥)
    ElGamalKeys::PrivateKey role_privatekey;
    ElGamalKeys::PublicKey role_publickey;

    generate_elgamal(role_privatekey, role_publickey, false);

    std::string pvkey;
    std::string pbkey;

    trans_elgamalsk_to_string(pvkey, role_privatekey);
    trans_elgamalpk_to_string(pbkey, role_publickey);

    //为role生成DSA公私钥对
    DSA::PrivateKey role_signprivatekey;
    DSA::PublicKey role_signpublickey;

    generate_dsa(role_signprivatekey, role_signpublickey, false);

    std::string pvsign;
    std::string pbsign;

    trans_dsa_signsk_to_string(pvsign, role_signprivatekey);
    trans_dsa_signpk_to_string(pbsign, role_signpublickey);

    for (int i = 0; i < user_role.size(); i++) {
        //将该user从user_role中删除并同时删除相应的RK
        if (user_role[i]._rolename == rolename) {
            if (user_role[i]._username == username) {
                vector<pair_user_role>::iterator iter = user_role.begin();
                iter = iter + i;
                //user_role.erase(iter);
            } else {
                // 委托云提供商为剩下的用户更新RK元组
                User user;
                user.unserial(user_role[i]._username);
                ElGamalKeys::PublicKey user_publickey;
                trans_elgamalpk_from_string(user.get_pbkey(), user_publickey);
                ElGamal::Encryptor encryptor(user_publickey);
                std::string cipherpvkey;
                std::string cipherpvsign;
                encrypt(encryptor, pvkey, cipherpvkey);
                encrypt(encryptor, pvsign, cipherpvsign);
                write_to_file(UPDATES, cipherpvkey);
                write_to_file(UPDATES, cipherpvsign); //
                user_role[i]._version++;
            }
        }
    }

    AutoSeededRandomPool prng;
    //第一层循环遍历属于role的所有file，第二层循环遍历相关file的所有role，重新生成FK，版本号加一
    for (int i = 0; i < role_file.size(); i++) {
        if (role_file[i]._rolename == rolename) {
            //生成新的AES密钥
            //File f;
            //f.unserial(role_file[i]._filename);

            cipher_fk tmp;
            tmp.k_t = string(16, 0);
            string data;
            tmp.serial(data);

            for (int j = 0; j < role_file.size(); j++) {
                if (role_file[j]._filename == role_file[i]._filename) {
                    //cout<<role_file[j]._rolename<<" "<<role_file[j]._filename<<endl;;
                    Role role;
                    role.unserial(role_file[j]._rolename);
                    ElGamalKeys::PublicKey role_publickey;
                    trans_elgamalpk_from_string(role._pbkey, role_publickey);
                    ElGamal::Encryptor encryptor(role_publickey);
                    string cipher;
                    encrypt(encryptor, data, cipher);
                    write_to_file(UPDATES, cipher);
                }
            }
        }
    }
    //send_to_server();
    return;
}

/**
 * @brief 用户权限撤销，包含了F元组更新与RK、FK元组更新两个过程
 * Core Function of User Revocation
 * @param username 
 * @param rolename 
 * @param user_role 
 * @param role_file 
 */
void User_revocation(std::string username, std::string rolename, vector<pair_user_role> &user_role, vector<pair_role_file> &role_file) {
    cout << "User_revocation..." << endl;
    AutoSeededRandomPool rng;
    //TODO：为role生成elgamal公私钥对（新密钥对文件哪来？）
    ElGamalKeys::PrivateKey role_privatekey;
    ElGamalKeys::PublicKey role_publickey;

    generate_elgamal(role_privatekey, role_publickey, false);

    std::string pvkey;
    std::string pbkey;

    trans_elgamalsk_to_string(pvkey, role_privatekey);
    trans_elgamalpk_to_string(pbkey, role_publickey);

    //为role生成DSA公私钥对
    DSA::PrivateKey role_signprivatekey;
    DSA::PublicKey role_signpublickey;

    generate_dsa(role_signprivatekey, role_signpublickey, false);

    std::string pvsign;
    std::string pbsign;

    trans_dsa_signsk_to_string(pvsign, role_signprivatekey);
    trans_dsa_signpk_to_string(pbsign, role_signpublickey);

    for (int i = 0; i < user_role.size(); i++) {
        //将该user从user_role中删除并同时删除相应的RK
        if (user_role[i]._rolename == rolename) {
            if (user_role[i]._username == username) {
                vector<pair_user_role>::iterator iter = user_role.begin();
                iter = iter + i;
                //user_role.erase(iter);
            } else {
                User user;
                user.unserial(user_role[i]._username);
                ElGamalKeys::PublicKey user_publickey;
                trans_elgamalpk_from_string(user.get_pbkey(), user_publickey);
                ElGamal::Encryptor encryptor(user_publickey);
                std::string cipherpvkey;
                std::string cipherpvsign;
                encrypt(encryptor, pvkey, cipherpvkey);
                encrypt(encryptor, pvsign, cipherpvsign);
                write_to_file(UPDATES, cipherpvkey);
                write_to_file(UPDATES, cipherpvsign); 
                // TODO ：version含义
                user_role[i]._version++;
            }
        }
    }

    AutoSeededRandomPool prng;
    //第一层循环遍历属于role的所有file，第二层循环遍历相关file的所有role，重新生成FK，版本号加一
    for (int i = 0; i < role_file.size(); i++) {
        if (role_file[i]._rolename == rolename) {
            //生成新的AES密钥
            //File f;
            //f.unserial(role_file[i]._filename);

            //测量re-key和re-enc F元组的时间
            /*
			struct timeval start, end;
			double interval;
			string F_time_ro="//home//lyc//ntl//key_rotation_version//F_time_ro.txt";
			ofstream ofile(F_time_ro.c_str(),ios::app);
			gettimeofday(&start, NULL);
			*/
            //

            FK fk;
            unserial_from_file(fk, rolename + "_" + role_file[i]._filename + "_" + to_string(role_file[i].version_role) + "_" + to_string(role_file[i].version_file) + suffix);

            Role r;
            r.unserial(rolename);
            ElGamalKeys::PrivateKey privatekey;
            trans_elgamalsk_from_string(r._pvkey, privatekey);
            ElGamal::Decryptor decryptor(privatekey);
            string file_key;
            decrypt(decryptor, file_key, fk.cipher_fk);

            cipher_fk tmp;
            tmp.unserial(file_key);
            ZZ k_t;
            trans_zz_from_string(k_t, tmp.k_t);
            ZZ next = BDri(rsk, k_t, N);
            string new_key_t;
            trans_zz_to_string(next, new_key_t);
            tmp.k_t = new_key_t;
            if (tmp.t < 20)
                tmp.t++;
            string data;
            tmp.serial(data);
            write_to_file(UPDATES, new_key_t);
            // 找到要更新的file对应的角色重新加密
            for (int j = 0; j < role_file.size(); j++) {
                if (role_file[j]._filename == role_file[i]._filename) {
                    Role role;
                    role.unserial(role_file[j]._rolename);
                    ElGamalKeys::PublicKey role_publickey;
                    trans_elgamalpk_from_string(role._pbkey, role_publickey);
                    ElGamal::Encryptor encryptor(role_publickey);
                    string cipher;
                    encrypt(encryptor, data, cipher);
                    write_to_file(UPDATES, cipher);
                }
            }
        }
    }
    //send_to_server();
    return;
}

/**
 * @brief 回收角色名为rolename角色对文件名filename的文件权限
 * @param rolename 
 * @param filename 
 * @param role_file 
 */
void Role_revocation(string rolename, string filename, vector<pair_role_file> &role_file) {
    // 生成一个新的加密层
    string key;
    generate_aeskey(key);
    for (int i = 0; i < role_file.size(); i++) {
        if (role_file[i]._filename == filename) {
            //如果role不是被撤销的role，那么为其生成新的FK元组
            if (role_file[i]._rolename != rolename) {
                FK fk;
                unserial_from_file(fk, rolename + "_" + filename + "_" + to_string(role_file[i].version_role) + "_" + to_string(role_file[i].version_file) + suffix);
                Role r;
                r.unserial(rolename);
                ElGamalKeys::PrivateKey privatekey;
                trans_elgamalsk_from_string(r._pvkey, privatekey);
                ElGamal::Decryptor decryptor(privatekey);
                string tmp;
                // 解密文件密钥列表
                decrypt(decryptor, tmp, fk.cipher_fk);
                cipher_fk fk_help;
                fk_help.unserial(tmp);
                // 安全模式：添加加密层，使密钥列表多一个密钥
                fk_help.k_t = key;
                if (fk_help.t < 20)
                    fk_help.t++;
                string tmp2;
                fk_help.serial(tmp2);

                ElGamalKeys::PublicKey publickey;
                trans_elgamalpk_from_string(r._pbkey, publickey);
                ElGamal::Encryptor encryptor(privatekey);
                string cipher;
                encrypt(encryptor, tmp2, cipher);
                write_to_file(UPDATES, cipher);
            } else {
                vector<pair_role_file>::iterator iter = role_file.begin();
                iter = iter + i;
                //role_file.erase(iter);
            }
        }
    }
    //send_to_server();
    return;
}
