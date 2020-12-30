#include "func.h"

vector<pair_user_role> user_role;
vector<pair_role_file> role_file;
const string user_revocation_time = "//home//lyc//ntl//key_rotation_version//user_revocation_time_ro.txt";
const string role_revocation_time = "//home//lyc//ntl//key_rotation_version//role_revocation_time_ro.txt";
const string file_read_time = "//home//lyc//ntl//key_rotation_version//file_read_time_ro.txt";
const string file_write_time = "//home//lyc//ntl//key_rotation_version//file_write_time_ro.txt";
const string file_write_time_more = "//home//lyc//ntl//key_rotation_version//file_write_time_more_ro.txt";
const string upload_file_time = "//home//lyc//ntl//key_rotation_version//upload_file_time_ro.txt";
const string user_revocation_time_f = "//home//lyc//ntl//key_rotation_version//user_revocation_time_f_ro.txt";
const string user_revocation_time_rk_fk = "//home//lyc//ntl//key_rotation_version//user_revocation_time_rk_fk_ro.txt";

/**
 * @brief 产生公钥私钥对存到文件中
 */
void test_genkey() {
    AutoSeededRandomPool rng;
    DSA::PrivateKey privatekey;
    privatekey.GenerateRandomWithKeySize(rng, 1024);
    DSA::PublicKey publickey;
    publickey.AssignFrom(privatekey);
    privatekey.Save(FileSink(sign_key_priv.c_str(), true /*binary*/).Ref());
    publickey.Save(FileSink(sign_key_pub.c_str(), true /*binary*/).Ref());

    ElGamalKeys::PrivateKey privatekey_elgamal;
    ElGamalKeys::PublicKey publickey_elgamal;
    privatekey_elgamal.GenerateRandomWithKeySize(rng, 1024);
    ElGamal::Decryptor decryptor(privatekey_elgamal);
    ElGamal::Encryptor encryptor(decryptor);
    publickey_elgamal = encryptor.AccessKey();
    privatekey_elgamal.Save(FileSink(elgamal_key_priv.c_str(), true /*binary*/).Ref());
    publickey_elgamal.Save(FileSink(elgamal_key_pub.c_str(), true /*binary*/).Ref());
    return;
}

/**
 * @brief 生成旋转密钥对的公钥rpk和私钥rsk
 */
void test_gen() {
    ZZ p = gen_prime();
    ZZ q = gen_prime();
    N = gen_N(p, q);
    fi = gen_fi(p, q);
    rpk = getrpk(fi);
    //rpk=7;
    rsk = getrsk(rpk, fi);

    my_hash.keygen();
}

/**
 * @brief 测试密钥旋转
 */
void test_rotation() {
    test_gen();
    ZZ rsk = getrsk(rpk, fi);
    cout << "rsk:" << rsk << endl;
    cout << "N:" << N << endl;
    ZZ cur(1480);
    for (int i = 0; i < 9; i++) {
        cout << cur << endl;
        cur = BDri(rsk, cur, N);
    }
    cout << cur << endl << endl;
    vector<ZZ> result = FDri(rpk, cur, 10, N);
    for (int i = 0; i < 10; i++) {
        cout << result[i] << endl;
    }
    return;
}

/**
 * @brief 测试初始化
 */
void test_init() {
    vector<string> username;
    vector<string> rolename;
    vector<string> filename;
    init_users(200, username);
    init_roles(9, rolename);
    init_files(200, filename);

    init_topu(username, username.size(), rolename, rolename.size(), filename, filename.size(), user_role, role_file);
    init(user_role, role_file);
}

/**
 * @brief 测试生成相应topu关系
 * @param user 
 * @param role 
 * @param file 
 */
void test_init_topu(int user, int role, int file) {
    vector<string> username;
    vector<string> rolename;
    vector<string> filename;
    for (int i = 0; i < user; i++) {
        string tmp("user" + to_string(i));
        username.push_back(tmp);
    }

    for (int i = 0; i < role; i++) {
        string tmp("role" + to_string(i));
        rolename.push_back(tmp);
    }

    for (int i = 0; i < file; i++) {
        string tmp("file" + to_string(i));
        filename.push_back(tmp);
    }

    init_topu(username, username.size(), rolename, rolename.size(), filename, filename.size(), user_role, role_file);
}

/**
 * @brief 测试用户读文件
 */
void test_read() {
    struct timeval start, end;
    double interval;
    int count = 50;
    ofstream ofile(file_read_time.c_str(), ios::binary);
    for (int i = 0; i < count; i++) {
        gettimeofday(&start, NULL);
        //test
        File_read_test("user1", "file4", user_role, role_file);
        //test
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("File_read time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
    return;
}

/**
 * @brief 测试用户写文件
 */
void test_write() {
    string content;
    int size = 1000000;
    content.resize(size);
    struct timeval start, end;
    double interval;
    int count = 1;
    ofstream ofile(file_write_time.c_str(), ios::binary);
    for (int i = 0; i < count; i++) {
        string line = "rm ~/ntl/key_rotation_version/update.txt";
        system(line.c_str());

        gettimeofday(&start, NULL);
        // TODO : 未验证user写入权限，加密层数变化？
        File_write("file1", content, role_file);
        send_to_server();
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("File_write time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
    return;
}

// TODO
void test_write_20() {
    string content;
    content.resize(10010000);
    struct timeval start, end;
    double interval;
    int count = 10;
    ofstream ofile(file_write_time.c_str(), ios::binary);
    for (int i = 0; i < count; i++) {
        string line = "rm ~/ntl/key_rotation_version/update.txt";
        system(line.c_str());

        gettimeofday(&start, NULL);
        File_write_more("file1", content, role_file, 15);
        send_to_server();
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("File_write_20 time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
    return;
}

/**
 * @brief 测试上传F元组
 * @param filename 
 */
void test_upload_f(string filename) {
    File f;
    f._filename = filename;

    int size = 100100;

    f._content = "qwertyuiop";
    f._content.resize(size);

    cipher_fk part;
    generate_aeskey(part.k_0);
    part.k_t = part.k_0;
    part.t = 1;
    trans_zz_to_string(rpk, part.rpk);
    part.serial(f._key);
    //f.serial();
    //同时生成元组F
    F file;
    file.filename = filename;
    string iv(16, 0);
    aes_e(part.k_0, file.crypto_file, f._content);

    DSA::PrivateKey privatekey;
    privatekey.Load(FileSource(sign_key_priv.c_str(), true, NULL, true /*binary*/).Ref());
    file.sign(privatekey);
    serial_to_file(file);

    return;
}

/**
 * @brief 实际的测试F元组上传函数并统计元组F上传时间
 * @param filename 
 */
void test_upload(string filename) {
    struct timeval start, end;
    double interval;
    int count = 10;
    ofstream ofile(upload_file_time.c_str(), ios::binary);
    for (int i = 0; i < count; i++) {
        gettimeofday(&start, NULL);
        test_upload_f(filename);
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("upload time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
    return;
}

/**
 * @brief 测试角色权限吊销
 */
void test_role_revocation() {
    struct timeval start, end;
    double interval;
    int count = 10;
    ofstream ofile(role_revocation_time.c_str(), ios::binary);
    for (int i = 0; i < count; i++) {

        string line = "rm ~/ntl/key_rotation_version/update.txt";
        system(line.c_str());

        gettimeofday(&start, NULL);
        Role_revocation("role1", "file1", role_file);
        send_to_server();
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("Role_revocation time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
    return;
}

/**
 * @brief 测试用户权限吊销：委托云更新RK，FK元组
 */
void test_user_revocation_rk_fk() {
    struct timeval start, end;
    double interval;
    int count = 1;
    ofstream ofile(user_revocation_time_rk_fk.c_str(), ios::binary);
    for (int i = 0; i < count; i++) {

        string line = "rm ~/ntl/key_rotation_version/update.txt";
        system(line.c_str());

        gettimeofday(&start, NULL);
        User_revocation_RK_FK("user0", "role0", user_role, role_file);
        //send_to_server();
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("User_revocation_rk_fk time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
};

/**
 * @brief 测试用户权限吊销：委托云更新F元组
 */
void test_user_revocation_f() {
    struct timeval start, end;
    double interval;
    int count = 1;
    ofstream ofile(user_revocation_time_f.c_str(), ios::binary);
    for (int i = 0; i < count; i++) {

        string line = "rm ~/ntl/key_rotation_version/update.txt";
        system(line.c_str());

        gettimeofday(&start, NULL);
        User_revocation_F("user0", "role0", user_role, role_file);
        //send_to_server();
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("User_revocation_f time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
};

/**
 * @brief 测试用户权限吊销：整个过程
 */
void test_user_revocation() {
    std::cout << "function test_user_revocation" << std::endl;
    struct timeval start, end;
    double interval;
    int count = 1;
    ofstream ofile(user_revocation_time.c_str(), ios::binary);
    for (int i = 0; i < count; i++) {

        string line = "rm ~/ntl/key_rotation_version/update.txt";
        system(line.c_str());

        gettimeofday(&start, NULL);
        User_revocation("user1", "role1", user_role, role_file);
        //send_to_server();
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("User_revocation time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
};
// TODO
void test_server_en(int size, int layers) {
    string content;
    content.resize(size);
    string key(16, 'a');
    string cipher;
    struct timeval start, end;
    double interval;
    gettimeofday(&start, NULL);
    //aes_e(key,cipher,content);
    //string plain;
    aes_e_more_test(cipher, content, layers);
    //aes_d(key,cipher,plain);
    gettimeofday(&end, NULL);
    interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    printf("%f\n", interval / 1000000.0);
}
// TODO
void test_server_en_fork() {
    struct timeval start, end;
    double interval;
    gettimeofday(&start, NULL);
    for (int i = 0; i < 200; i++) {
        int pid = fork();
        if (pid == 0) {
            test_server_en(10000000, 15);
            exit(0);
        }
    }
    for (int i = 0; i < 200; i++) {
        wait(NULL);
    }
    gettimeofday(&end, NULL);
    interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    printf("aes 10 time = %f\n", interval / 1000000.0);
    return;
}

/**
 * @brief 测试加密解密函数的正确性
 */
void test_aes() {
    string plain("qwertyuiop");
    string cipher1;
    string cipher2;
    string re1;
    string re2;
    string key1("123");
    string key2("234");
    aes_e(key1, cipher1, plain);
    aes_e(key2, cipher2, cipher1);
    aes_d(key2, cipher2, re1);
    aes_d(key1, re1, re2);
    cout << re2 << endl;
}

/**
 * @brief 测试python下载文件
 */
void test_down() {
    struct timeval start, end;
    double interval;
    gettimeofday(&start, NULL);

    string tmp = "python test.py download File_10M.txt";
    int status = system(tmp.c_str());

    gettimeofday(&end, NULL);
    interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    printf("down time = %f\n", interval / 1000000.0);
}

/**
 * @brief 测试python上传文件
 */
void test_up() {
    struct timeval start, end;
    double interval;
    gettimeofday(&start, NULL);

    string tmp = "python test.py upload //home//lyc//ntl//File_10M.txt";
    int status = system(tmp.c_str());

    gettimeofday(&end, NULL);
    interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
    printf("up time = %f\n", interval / 1000000.0);
}

void test_user_revocation_rk_fk_user() {
    struct timeval start, end;
    double interval;
    int count = 1;
    string file = "//home//lyc//ntl//user_revocation_rk_fk_user_ro.txt";
    ofstream ofile(file.c_str(), ios::binary);
    for (int i = 40; i <= 200; i += 40) {

        string line = "rm ~/ntl/key_rotation_version/update.txt";
        system(line.c_str());

        user_role.clear();
        role_file.clear();
        test_init_topu(i, 9, 200);

        gettimeofday(&start, NULL);
        User_revocation_RK_FK("user0", "role0", user_role, role_file);
        send_to_server();
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("User_revocation_f time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
};

void test_user_revocation_rk_fk_role() {
    struct timeval start, end;
    double interval;
    int count = 1;
    string file = "//home//lyc//ntl//user_revocation_rk_fk_role_ro.txt";
    ofstream ofile(file.c_str(), ios::binary);
    for (int i = 1; i <= 9; i++) {

        string line = "rm ~/ntl/key_rotation_version/update.txt";
        system(line.c_str());

        user_role.clear();
        role_file.clear();
        test_init_topu(200, i, 200);

        gettimeofday(&start, NULL);
        User_revocation_RK_FK("user0", "role0", user_role, role_file);
        send_to_server();
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("User_revocation_f time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
};

void test_user_revocation_rk_fk_file() {
    struct timeval start, end;
    double interval;
    int count = 1;
    string file = "//home//lyc//ntl//user_revocation_rk_fk_file_ro.txt";
    ofstream ofile(file.c_str(), ios::binary);
    for (int i = 40; i <= 200; i += 40) {

        string line = "rm ~/ntl/key_rotation_version/update.txt";
        system(line.c_str());

        user_role.clear();
        role_file.clear();
        test_init_topu(200, 9, i);

        gettimeofday(&start, NULL);
        User_revocation_RK_FK("user0", "role0", user_role, role_file);
        send_to_server();
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("User_revocation_f time = %f\n", interval / 1000000.0);
        ofile << interval / 1000000.0 << endl;
    }
    ofile.close();
};

int main() {
    //test_genkey();

    test_gen(); //very important for many functions

    //test_user_revocation_rk_fk_user();
    //test_user_revocation_rk_fk_role();
    //test_user_revocation_rk_fk_file();
    //test_init();
    test_init_topu(200, 9, 40);
    //test_up();
    //test_down();
    //test_user_revocation();

    //test_user_revocation_rk_fk();
    //test_user_revocation_f();
    //test_read();
    //test_write();
    //test_role_revocation();
    //string file_upload("upload_file");
    //test_upload(file_upload);
    //test_read();
    //test_write();
    //test_write_20();
    test_server_en_fork();
    return 0;
}
