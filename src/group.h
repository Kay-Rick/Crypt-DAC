/**
 * @file group.h
 * @author Rick (Kay_Rick@outlook.com)
 * @version 1.0
 * @date 2020-12-23 20:56:38
 * @brief 项目所需要使用的基本函数
 * 
 * @copyright Copyright (c) 2020 Rick, All Rights Reserved.
 * 
 */
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "aes.h"
#include "base64.h"
#include "bench.h"
#include "cryptlib.h"
#include "default.h"
#include "dsa.h"
#include "elgamal.h"
#include "factory.h"
#include "files.h"
#include "filters.h"
#include "gzip.h"
#include "hex.h"
#include "ida.h"
#include "osrng.h"
#include "randpool.h"
#include "ripemd.h"
#include "rng.h"
#include "smartptr.h"
#include "socketft.h"
#include "tiger.h"
#include "validate.h"
#include "wait.h"
#include "whrlpool.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <locale>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <time.h>

#include "boost/any.hpp"
#include "boost/archive/binary_iarchive.hpp"
#include "boost/archive/binary_oarchive.hpp"
#include "boost/foreach.hpp"
#include "boost/serialization/serialization.hpp"
#include <boost/serialization/export.hpp>
#include <boost/serialization/vector.hpp>

#include <md5.h>
//#include <cryptopp/hex.h>
#include "cryptlib.h"
#include "dsa.h"
#include "files.h"
#include "filters.h"
#include "osrng.h"
#include <rng.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rotation.h"
using namespace std;
using namespace NTL;
using namespace CryptoPP;

//定义常用的字符串以方便后面程序使用
const std::string signpk_of_admin = "//home//lyc//ntl//signpk_of_admin.txt";
const std::string signsk_of_admin = "//home//lyc//ntl//signsk_of_admin.txt";
const std::string pkhash_g = "//home//lyc//ntl//pkhash_g.txt";
const std::string pkhash_y = "//home//lyc//ntl//pkhash_y.txt";
const std::string skhash = "//home//lyc//ntl//skhash.txt";
const std::string sign_key_pub = "//home//lyc//ntl//sign_key_pub.txt";
const std::string sign_key_priv = "//home//lyc//ntl//sign_key_priv.txt";
const std::string elgamal_key_pub = "//home//lyc//ntl//elgamal_key_pub.txt";
const std::string elgamal_key_priv = "//home//lyc//ntl//elgamal_key_priv.txt";
//const std::string location="//home//lyc//new_crypt_data//";
const std::string TUPLES = "//home//lyc//ntl//key_rotation_version//tuples//";
const std::string USERS = "//home//lyc//ntl//key_rotation_version//users//";
const std::string ROLES = "//home//lyc//ntl//key_rotation_version//roles//";
const std::string KEYS = "//home//lyc//ntl//key_rotation_version//keys//";
const std::string FILES = "//home//lyc//ntl//key_rotation_version//files//";
const std::string UPDATES = "//home//lyc//ntl//key_rotation_version//update.txt";
const std::string suffix = ".txt";
const std::string rk_ = "1_";
const std::string fk_ = "2_";
const std::string f_ = "3_";

ZZ N; //安全系数
ZZ rpk;
ZZ rsk;
ZZ fi;

/**
 * @brief 辅助函数
 * @param num 
 * @return string 
 */
string to_string(int num) {
    std::stringstream ss;
    std::string str;
    ss << num;
    ss >> str;
    return str;
}

void read_from_file(const string &filename, string &m) {
    ifstream rfile(filename.c_str(), ios::binary);
    if (!rfile)
        cout << "open file fail in read_from_file" << endl;
    int size;
    rfile.read((char *)m.c_str(), size);
    rfile.close();
    return;
}

/**
 * @brief 默认app
 * @param filename 
 * @param blocktext 
 */
void write_to_file(const string &filename, string &blocktext) {
    ofstream wfile(filename.c_str(), ios::app);
    if (!wfile)
        cout << "open file fail in write_to_file";
    wfile.write((char *)blocktext.c_str(), blocktext.size());
    wfile.close();
    return;
}

void send_to_server() {
    string tmp = "python test.py upload " + UPDATES;
    int status = system(tmp.c_str());
    if (status == -1)
        cout << "system()失败！" << endl;
    /*
	int status=-1;
	int pid=fork();
	if(pid==0){
		execl("/bin/sh","sh","-c",tmp.c_str(),NULL);	
	}
	else{
		wait(NULL);
	}
	*/
}

void send_to_server(string filename_and_path) {
    string tmp = "python test.py upload " + filename_and_path;
    int status = system(tmp.c_str());
    if (status == -1)
        cout << "system()失败！" << endl;
    return;
}

// 命名空间group
namespace group {
std::string p_t = "154832590885624877771060372806205385413142391566678508396446386791765289133151890555903226060612469794823636335716361477716811201889616957164323746637059223973296263052495236079057879936758234229218100933167771139308703317575246829476543387421928000740455970241206725495181995400476210600223963943361549656067";
std::string q_t = "77416295442812438885530186403102692706571195783339254198223193395882644566575945277951613030306234897411818167858180738858405600944808478582161873318529611986648131526247618039528939968379117114609050466583885569654351658787623414738271693710964000370227985120603362747590997700238105300111981971680774828033";

struct PK {
    ZZ g;
    ZZ y;
};

struct SK {
    ZZ x;
};

struct MD {
    ZZ C;
    ZZ r;
    ZZ s;
};

class IntegerGroup {
  public:
    ZZ p;
    ZZ q;
    int r;
    void paramgen(int bits, int s = 2);
    ZZ randomGen();
};

class ChamHash {
  public:
    IntegerGroup group;
    PK pk;
    SK sk;
    ChamHash();
    void keygen();
    void setpk(PK _pk);
    void setsk(SK _sk);
    MD hash(std::string m, ZZ r = ZZ(), ZZ s = ZZ());
    MD forge(std::string m, MD md);
};

void group::IntegerGroup::paramgen(int bits, int s) {
    std::stringstream tmp(group::p_t);
    tmp >> p;
    std::stringstream tmp2(group::q_t);
    tmp2 >> q;
    r = s;
    /*
        q=GenGermainPrime_ZZ(bits,80);
        p=2*q+1;
        r=s; 
	long a1=NumBytes(q);
	unsigned char p1[128];
	long a2=NumBytes(p);
	unsigned char p2[129];
	BytesFromZZ(p1,q,a1);
	BytesFromZZ(p2,p,a2);
	cout<<p<<endl;
	cout<<q<<endl;
	*/
}

NTL::ZZ group::IntegerGroup::randomGen() {
    NTL::ZZ g;
    while (true) {
        ZZ h = RandomBnd(p);
        g = PowerMod(h, ZZ(r), p);
        if (g != 1)
            break;
    }
    return g;
}

group::ChamHash::ChamHash() {
    group.paramgen(1024);
}

void group::ChamHash::keygen() {
    pk.g = group.randomGen();
    sk.x = ZZ(0);
    while (sk.x == ZZ(0)) {
        sk.x = RandomBnd(group.q);
    }
    //cout<<"sk.x"<<sk.x<<endl;
    pk.y = PowerMod(pk.g, sk.x, group.p);
}

void group::ChamHash::setpk(PK _pk) {
    pk = _pk;
    return;
}

void group::ChamHash::setsk(SK _sk) {
    sk = _sk;
    return;
}

group::MD group::ChamHash::hash(std::string m, ZZ r, ZZ s) {
    ZZ p = group.p;
    ZZ q = group.q;
    while (r == ZZ(0)) {
        r = RandomBnd(q);
    }
    //
    //cout<<"r:"<<r<<endl;
    while (s == ZZ(0)) {
        s = RandomBnd(q);
    }
    //cout<<"s:"<<s<<endl;
    MD md;

    int len = NumBytes(r);
    std::string r_byte;
    r_byte.resize(len);
    BytesFromZZ((unsigned char *)r_byte.c_str(), r, len);
    std::string msg = m + r_byte;

    byte digest[CryptoPP::Weak::MD5::DIGESTSIZE];
    CryptoPP::Weak::MD5 hash;
    hash.CalculateDigest(digest, (const byte *)msg.c_str(), msg.size());

    ZZ e = ZZFromBytes((unsigned char *)digest, 16);
    e = AddMod(e, ZZ(), q);

    ZZ tmp1 = PowerMod(pk.y, e, p);
    ZZ tmp2 = PowerMod(pk.g, s, p);
    ZZ tmp3 = MulMod(tmp1, tmp2, p);
    ZZ tmp4 = AddMod(tmp3, ZZ(), q);
    ZZ C = SubMod(r, tmp4, q);
    //ZZ C=r - PowerMod( PowerMod( PowerMod(pk.y , e , p) * PowerMod(pk.g , s , p) , p , p) , p , q);
    md.C = C;
    md.r = r;
    md.s = s;
    return md;
}

group::MD group::ChamHash::forge(std::string m, MD md) {
    ZZ p = group.p;
    ZZ q = group.q;

    ZZ k = ZZ(0);
    while (k == ZZ(0)) {
        k = RandomBnd(q);
    }
    //if(k>q) cout<<"error!!!!!"<<endl<<endl;
    ZZ tmp1 = PowerMod(pk.g, k, p);
    ZZ tmp2 = AddMod(tmp1, ZZ(), q);
    md.r = AddMod(md.C, tmp2, q);

    int len = NumBytes(md.r);
    std::string r_byte;
    r_byte.resize(len);
    BytesFromZZ((unsigned char *)r_byte.c_str(), md.r, len);
    std::string msg = m + r_byte;

    byte digest[CryptoPP::Weak::MD5::DIGESTSIZE];
    CryptoPP::Weak::MD5 hash;
    hash.CalculateDigest(digest, (const byte *)msg.c_str(), msg.size());

    ZZ e = ZZFromBytes((unsigned char *)digest, 16);
    //cout<<"e:"<<e<<endl;
    e = AddMod(e, ZZ(), q);
    //md.r=md.C + PowerMod( PowerMod(pk.g,k,p) , ZZ(1) , q);
    ZZ tmp3 = MulMod(e, sk.x, q);
    ZZ tmp4 = SubMod(k, tmp3, q);
    md.s = AddMod(tmp4, ZZ(), q);
    return md;
}

} // namespace group

// TODO
// 全局变量，放在这里有些奇怪，以后要改
group::ChamHash my_hash;

group::PK get_pkhash() {
    return my_hash.pk;
}
group::SK get_skhash() {
    return my_hash.sk;
}

void trans_zz_to_string(const ZZ &c, std::string &m) {
    int len = NumBytes(c);
    //unsigned char msg[len];
    m.resize(len);
    BytesFromZZ((unsigned char *)m.c_str(), c, len);
    //m=std::string((char*)msg);
    return;
}

void trans_zz_from_string(ZZ &c, std::string &m) {
    int len = m.size();
    ZZFromBytes(c, (unsigned char *)m.c_str(), len);
    return;
}

inline void trnas_dsa_signpk_from_string(std::string &m, DSA::PublicKey &pk) {
    pk.Load(StringStore(m).Ref());
    return;
}

inline void trans_dsa_signsk_from_string(std::string &m, DSA::PrivateKey &sk) {
    sk.Load(StringStore(m).Ref());
    return;
}

inline void trans_dsa_signpk_to_string(std::string &m, DSA::PublicKey &pk) {
    pk.Save(StringSink(m).Ref());
    return;
}

inline void trans_dsa_signsk_to_string(std::string &m, DSA::PrivateKey &sk) {
    sk.Save(StringSink(m).Ref());
    return;
}

template <class T>
inline void trans_to_string(std::string &m, T &key) {
    key.Save(StringSink(m).Ref());
    return;
}

template <class T>
inline void trans_from_string(std::string &m, T &key) {
    key.Load(StringStore(m).Ref());
    return;
}

inline void trans_aes_key_to_string(std::string &m, byte key[], byte iv[], int len = 16) {
    m = std::string((const char *)key, 16) + std::string((const char *)iv, 16);
    return;
}

inline void trans_aes_key_from_string(std::string &m, byte *key, byte *iv, int len = 16) {
    std::string m1(m.begin(), m.begin() + 16);
    std::string m2(m.begin() + 16, m.end());
    key = (byte *)m1.c_str();
    iv = (byte *)m2.c_str();
    return;
}
// TODO
inline void trans_elgamalpk_from_string(std::string tmp, ElGamalKeys::PublicKey &publickey) {
    CryptoPP::HexDecoder decoder;
    decoder.Put((byte *)tmp.c_str(), tmp.size());
    decoder.MessageEnd();
    publickey.Load(decoder);
}

/**
 * @brief 将16进制编码的字符串解码为私钥
 * @param tmp 
 * @param privatekey 
 */
inline void trans_elgamalsk_from_string(std::string tmp, ElGamalKeys::PrivateKey &privatekey) {
    CryptoPP::HexDecoder decoder;
    decoder.Put((byte *)tmp.c_str(), tmp.size());
    decoder.MessageEnd();
    privatekey.Load(decoder);
}

inline void trans_elgamalpk_to_string(std::string &m, ElGamalKeys::PublicKey &publickey) {
    CryptoPP::HexEncoder encoder_pb;
    encoder_pb.Attach(new CryptoPP::StringSink(m));
    publickey.Save(encoder_pb);
    return;
}

inline void trans_elgamalsk_to_string(std::string &m, ElGamalKeys::PrivateKey &privatekey) {
    CryptoPP::HexEncoder encoder_pv;
    encoder_pv.Attach(new CryptoPP::StringSink(m));
    privatekey.Save(encoder_pv);
    return;
}

group::MD _sign(const std::string &message, std::string &signature, group::PK pkhash, group::SK skhash, DSA::PrivateKey &privatekey) {
    //先做哈希
    group::ChamHash cham;
    cham.setpk(pkhash);
    cham.setsk(skhash);
    group::MD h = cham.hash(message);
    std::string msg;
    trans_zz_to_string(h.C, msg);
    //再签名
    AutoSeededRandomPool rng;
    DSA::Signer signer(privatekey);
    StringSource ss1(msg, true, new SignerFilter(rng, signer, new StringSink(signature))); // std::stringSource
    return h;
}

/**
 * @brief RK元组定义
 */
class RK {
  private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &version_role;
        ar &username;
        ar &rolename;
        ar &crypto_rolekey;
        ar &crypto_rolesign;
        ar &signature;
        ar &r;
        ar &s;
    }

  public:
    static const int sential = 1;
    int version_role;
    std::string username;
    std::string rolename;
    std::string crypto_rolekey; //用用户公閽????密后的role的私钥
    std::string crypto_rolesign;
    std::string signature;
    std::string r;
    std::string s;

    RK() : version_role(0), username(""), rolename(""), crypto_rolekey(""), crypto_rolesign(""), signature(""), r(""), s("") {}
    RK(int ver, std::string &user, std::string &role, std::string &_crypto_rolekey, std::string &_crypto_rolesign, std::string &_signature, std::string &_r, std::string &_s) : version_role(ver), username(user), rolename(role), crypto_rolekey(_crypto_rolekey), crypto_rolesign(_crypto_rolesign), signature(_signature), r(_r), s(_s) {}

    void sign(DSA::PrivateKey &privatekey) {
        std::string message = to_string(version_role) + username + rolename + crypto_rolekey + crypto_rolesign;
        group::PK pkhash = get_pkhash();
        group::SK skhash = get_skhash();
        group::MD md = _sign(message, signature, pkhash, skhash, privatekey);
        trans_zz_to_string(md.r, r);
        trans_zz_to_string(md.s, s);
        return;
    }
};

/**
 * @brief 辅助FK
 */
class cipher_fk {
  private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &k_0;
        ar &k_t;
        ar &rpk;
        ar &t;
    }

  public:
    std::string k_0;
    std::string k_t;
    std::string rpk;
    int t;

    cipher_fk() : k_0(""), k_t(""), rpk(""), t(1) {}
    cipher_fk(std::string &k0, std::string &kt, std::string &_rpk, int &_t) : k_0(k0), k_t(kt), rpk(_rpk), t(_t) {}

    void serial(string &m) {
        std::ostringstream os;
        boost::archive::binary_oarchive oa(os);
        oa << *this;
        m = os.str();
        return;
    }
    void unserial(std::string &m) {
        std::istringstream is(m);
        boost::archive::binary_iarchive ia(is);
        ia >> *this;
        return;
    }
};

/**
 * @brief FK元组定义
 */
class FK {
  private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &rolename;
        ar &filename;
        ar &operation;
        ar &version_file;
        ar &version_role;
        ar &cipher_fk;
        ar &signature;
        ar &r;
        ar &s;
        ar &tag;
    }

  public:
    static const int sential = 2;
    std::string rolename;
    std::string filename;
    char operation;
    int version_file;
    int version_role;
    std::string cipher_fk;
    std::string signature;
    std::string r;
    std::string s;
    bool tag;

    FK() : rolename(""), filename(""), operation('r'), version_file(0), version_role(0), cipher_fk(""), signature(""), r(""), s(""), tag(false) {}

    void sign(DSA::PrivateKey &privatekey) {
        std::string message = to_string(version_role) + to_string(version_file) + filename + rolename + cipher_fk;
        group::PK pkhash = get_pkhash();
        group::SK skhash = get_skhash();
        group::MD md = _sign(message, signature, pkhash, skhash, privatekey);
        trans_zz_to_string(md.r, r);
        trans_zz_to_string(md.s, s);
        return;
    }
};


/**
 * @brief F元组
 */
class F {
  private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &filename;
        ar &crypto_file;
        ar &signature;
        ar &r;
        ar &s;
    }

  public:
    static const int sential = 3;
    std::string filename;
    std::string crypto_file; //加密后的文件内容
    std::string signature;
    std::string r;
    std::string s;

    F() : filename(""), crypto_file(std::string()), signature(""), r(""), s("") {}
    F(std::string &file, std::string &cryptofile, std::string &signature, std::string &r, std::string &s) : filename(file), crypto_file(cryptofile), signature(signature), r(r), s(s) {}

    void sign(DSA::PrivateKey &privatekey) {
        std::string message(filename + crypto_file);
        group::PK pkhash = get_pkhash();
        group::SK skhash = get_skhash();
        group::MD md = _sign(message, signature, pkhash, skhash, privatekey);
        trans_zz_to_string(md.r, r);
        trans_zz_to_string(md.s, s);
        return;
    }
};


/**
 * @brief 元组序列化函数。将??地生成的元组对象序列化、签名、保存至本地文件、上传文件。
 * @tparam T 
 * @param tuple 
 * @param message 
 */
template <class T>
void serial_to_string(T &tuple, std::string &message) {
    std::ostringstream os;
    boost::archive::binary_oarchive oa(os);
    oa << tuple;
    message = os.str();
    return;
}

/**
 * @brief 将RK元组序列化到文件
 * @param tuple 
 */
void serial_to_file(RK &tuple) {
    string filename_and_path(TUPLES + tuple.username + "_" + tuple.rolename + "_" + to_string(tuple.version_role) + suffix);
    std::ofstream os_file(filename_and_path.c_str(), ios::binary);
    if (!os_file)
        cout << "open file error" << endl;
    boost::archive::binary_oarchive oa(os_file);
    oa << tuple;
    os_file.close();
    send_to_server(filename_and_path);
    return;
}

/**
 * @brief 将FK元组序列化到文件
 * @param tuple 
 */
void serial_to_file(FK &tuple) {
    string filename_and_path(TUPLES + tuple.rolename + "_" + tuple.filename + "_" + to_string(tuple.version_role) + "_" + to_string(tuple.version_file) + suffix);
    std::ofstream os_file(filename_and_path.c_str(), ios::binary);
    if (!os_file)
        cout << "open file error" << endl;
    boost::archive::binary_oarchive oa(os_file);
    oa << tuple;
    os_file.close();
    send_to_server(filename_and_path);
    return;
}

/**
 * @brief 将F元组序列化至文件
 * @param tuple 
 */
void serial_to_file(const F &tuple) {
    string filename_and_path(TUPLES + tuple.filename + suffix);
    std::ofstream os_file(filename_and_path.c_str(), ios::binary);
    if (!os_file)
        cout << "open file error" << endl;
    boost::archive::binary_oarchive oa(os_file);
    oa << tuple;
    os_file.close();
    send_to_server(filename_and_path);
    return;
}


/**
 * @brief 元组反序列化函数：从字符串反序列化
 * @tparam T 
 * @param tuple 
 * @param content 
 */
template <class T>
void unserial_from_string(T &tuple, const std::string &content) {
    std::istringstream is(content);
    boost::archive::binary_iarchive ia(is);
    ia >> tuple;
    return;
}

/**
 * @brief 元组反序列化函数：从文件反序列化
 * @tparam T 
 * @param tuple 
 * @param filename 
 */
template <class T>
void unserial_from_file(T &tuple, const std::string &filename) {
    //首先下载元组
    cout << "download file" << endl;
    string tmp = "python test.py download " + filename;
    int status = system(tmp.c_str());
    if (status == -1)
        cout << "system()失败！" << endl;

    std::ifstream is_file((TUPLES + filename).c_str(), ios::binary);
    if (!is_file)
        cout << "open file fail in unserial_from_file";
    boost::archive::binary_iarchive ia(is_file);
    ia >> tuple;
    is_file.close();
    return;
}


/**
 * @brief user和role的映射关系
 */
class pair_user_role {
  public:
    std::string _username;
    std::string _rolename;
    int _version; //瀵????RK元组的最新版本号

    pair_user_role() : _username(""), _rolename(""), _version(0) {}
    pair_user_role(std::string username, std::string rolename, int ver) : _username(username), _rolename(rolename), _version(ver) {}
};


/**
 * @brief role和file的映射关系
 */
class pair_role_file {
  public:
    std::string _rolename;
    std::string _filename;
    char _op;
    int version_file;
    int version_role;

    pair_role_file() : _rolename(""), _filename(""), _op('0'), version_file(0), version_role(0) {}
    pair_role_file(std::string rolename, std::string filename, char op, int ver_file, int ver_role) : _rolename(rolename), _filename(filename), _op(op), version_file(ver_file), version_role(ver_role) {}
};


/**
 * @brief 该类用于保存用户的公私钥，并提供了序列化功能
 */
class User {
    // Boost.Serialization 库能够将c++项目中的对象转换为一序列的比特（bytes），用来保存和加载还原对象
  private:
    // access对象可以访问User的私有成员
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        //ar & rk;
        ar &_username;
        ar &_pvkey;
        ar &_pbkey;
        ar &_pvsign;
        ar &_pbsign;
        ar &_g;
        ar &_y;
    }

  public:
    std::string _username;
    std::string _pvkey;
    std::string _pbkey;
    std::string _pvsign;
    std::string _pbsign;
    std::string _g;
    std::string _y;

    /**
     * @brief Construct a new User object
     * @param username 
     * @param pvkey 
     * @param pbkey 
     * @param pvsign 
     * @param pbsign 
     * @param g 
     * @param y 
     */
    User(std::string username, std::string pvkey, std::string pbkey, std::string pvsign, std::string pbsign, std::string g, std::string y) : _username(username), _pvkey(pvkey), _pbkey(pbkey), _pvsign(pvsign), _pbsign(pbsign), _g(g), _y(y) {}

    User() : _username(""), _pvkey(""), _pbkey(""), _pvsign(""), _pbsign(""), _g(""), _y("") {}

    /**
     * @brief Set the pvkey object
     * @param pvkey 
     */
    void set_pvkey(const std::string &pvkey) { _pvkey = pvkey; }
    void set_pbkey(const std::string &pbkey) { _pbkey = pbkey; }
    void set_pvsign(const std::string &pvsign) { _pvsign = pvsign; }
    void set_pbsign(const std::string &pbsign) { _pbsign = pbsign; }
    void set_g(const std::string &g) { _g = g; }
    void set_y(const std::string &y) { _y = y; }

    /**
     * @brief Get the pvkey object
     * @return std::string 
     */
    std::string get_pvkey() { return _pvkey; }
    std::string get_pbkey() { return _pbkey; }
    std::string get_pvsign() { return _pvsign; }
    std::string get_pbsign() { return _pbsign; }
    std::string get_g() { return _g; }
    std::string get_y() { return _y; }

    /**
     * @brief 序列化
     */
    void serial() {
        std::ofstream os_file((USERS + _username + suffix).c_str(), ios::binary);
        if (!os_file)
            cout << "open USER file fail";
        boost::archive::binary_oarchive oa(os_file);
        oa << *this;
        os_file.close();
    }

    /**
     * @brief 反序列化
     * @param filename 
     */
    void unserial(std::string filename) {
        std::ifstream is_file((USERS + filename + suffix).c_str(), ios::binary);
        if (!is_file)
            cout << "open USER file fail";
        boost::archive::binary_iarchive ia(is_file);
        ia >> *this; //序列化到一个ostd::stringstream里面
        is_file.close();
    }
};

class Role {
  private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &_rolename;
        ar &_ver;
        ar &_pvkey;
        ar &_pbkey;
        ar &_pvsign;
        ar &_pbsign;
    }

  public:
    std::string _rolename;
    int _ver;
    std::string _pvkey;
    std::string _pbkey;
    std::string _pvsign;
    std::string _pbsign;

    Role(std::string rolename, int ver, std::string pvkey, std::string pbkey, std::string pvsign, std::string pbsign) : _rolename(rolename), _ver(ver), _pvkey(pvkey), _pbkey(pbkey), _pvsign(pvsign), _pbsign(pbsign) {}
    Role() : _rolename(""), _ver(0), _pvkey(""), _pbkey(""), _pvsign(""), _pbsign("") {}
    void serial() {
        std::ofstream os_file((ROLES + _rolename + suffix).c_str(), ios::binary);
        if (!os_file)
            cout << "open file fail in role serial";
        boost::archive::binary_oarchive oa(os_file);
        oa << *this;
        os_file.close();
    }
    void unserial(std::string filename) {
        std::ifstream is_file((ROLES + filename + suffix).c_str(), ios::binary);
        if (!is_file)
            cout << "open file fail in role unserial";
        boost::archive::binary_iarchive ia(is_file);
        ia >> *this; //序列化到一个ostd::stringstream里面
        is_file.close();
    }
};

class File {
  private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &_filename;
        ar &_key;
        ar &_content;
    }

  public:
    std::string _filename;
    std::string _key;
    std::string _content;

    File(std::string &filename, std::string &key, std::string &content) : _filename(filename), _key(key), _content(content) {}
    File() : _filename(""), _key(""), _content("") {}
    void serial() {
        std::ofstream os_file((FILES + _filename + suffix).c_str(), ios::binary);
        if (!os_file)
            cout << "open file fail in file serial";
        boost::archive::binary_oarchive oa(os_file);
        oa << *this;
        os_file.close();
    }
    void unserial(std::string filename) {
        std::ifstream is_file((FILES + filename + suffix).c_str(), ios::binary);
        if (!is_file)
            cout << "open file fail in file unserial";
        boost::archive::binary_iarchive ia(is_file);
        ia >> *this; //序列化到一个ostringstream里面
        is_file.close();
    }
};


/**
 * @brief 封装新的AES
 * @param key 
 */
void generate_aeskey(string &key) {
    srand((unsigned int)time(NULL));
    ZZ a(rand());
    a = a % N;
    trans_zz_to_string(a, key);
    //key="123";
    return;
}

/**
 * @brief 加密
 * @param k 
 * @param cipher 
 * @param plain 
 */
void aes_e(string &k, string &cipher, string &plain) {
    SecByteBlock key(0, 16);
    for (int i = 0; i < k.size() && i < 16; i++) {
        key[i] = k[i];
    }
    SecByteBlock iv(0, 16);
    cipher = plain;
    CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
    cfbEncryption.ProcessData((byte *)cipher.c_str(), (byte *)cipher.c_str(), cipher.size());
    return;
}

/**
 * @brief 解密文件
 * @param k 
 * @param cipher 
 * @param plain 
 */
void aes_d(string &k, string &cipher, string &plain) {
    SecByteBlock key(0, 16);
    for (int i = 0; i < k.size() && i < 16; i++) {
        key[i] = k[i];
    }
    SecByteBlock iv(0, 16);
    plain = cipher;
    CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
    cfbDecryption.ProcessData((byte *)plain.c_str(), (byte *)plain.c_str(), plain.size());
}

void aes_file(cipher_fk &c, F &f, string &plain) {
    int t = c.t;
    ZZ k;
    ZZ rpk;
    trans_zz_from_string(k, c.k_0);
    trans_zz_from_string(rpk, c.rpk);
    vector<ZZ> list = FDri(rpk, k, t, N);
    string iv(16, 0);

    string cipher(f.crypto_file);

    for (int i = t - 1; i >= 0; i--) {
        string key;
        trans_zz_to_string(list[i], key);
        aes_d(key, cipher, plain);
        cipher = plain;
    }
    /*
	string key;
	trans_zz_to_string(k,key);
	aes_d(key,f.crypto_file,plain);
	*/
    //cipher=plain;
    return;
}

void aes_file_e(cipher_fk &c, string &cipher, string &plain) {
    int t = c.t;
    ZZ k;
    ZZ rpk;
    trans_zz_from_string(k, c.k_0);
    trans_zz_from_string(rpk, c.rpk);
    vector<ZZ> list = FDri(rpk, k, t, N);
    string iv(16, 0);

    string p(plain);

    for (int i = 0; i < t; i++) {
        string key;
        trans_zz_to_string(list[i], key);
        aes_e(key, cipher, p);
        p = cipher;
    }
    return;
}

void aes_file_e_more_test(cipher_fk &c, string &cipher, string &plain, int count) {
    int t = c.t;
    ZZ k;
    ZZ rpk;
    trans_zz_from_string(k, c.k_0);
    trans_zz_from_string(rpk, c.rpk);
    vector<ZZ> list = FDri(rpk, k, t, N);
    string iv(16, 0);

    cout << "p isze:" << plain.size() << endl;
    for (int i = 0; i < t; i++) {
        string key;
        trans_zz_to_string(list[i], key);
        cout << "true time" << endl;
        struct timeval start, end;
        double interval;
        gettimeofday(&start, NULL);
        for (int i = 0; i < 20; i++) {
            aes_e(key, cipher, plain);
        }
        gettimeofday(&end, NULL);
        interval = 1000000 * (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec);
        printf("true time:%f\n", interval / 1000000.0);
        plain = cipher;
    }
    return;
}

void aes_e_more_test(string &cipher, string &plain, int count) {
    SecByteBlock key(0, 16);
    SecByteBlock iv(0, 16);
    cipher = plain;
    for (int i = 0; i < count; i++) {
        CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
        cfbEncryption.ProcessData((byte *)cipher.c_str(), (byte *)cipher.c_str(), cipher.size());
        cipher = plain;
    }
    return;
}
