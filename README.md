# Crypt-DAC
Crypt-DAC: Cryptographically Enforced Dynamic Access Control in the Cloud

## group.h

> 该文件声明了需使用的基本函数并且定义了group命名空间，该命名空间用来实现与可变哈希相关的函数，以及相关的序列化函数

- `string to_string(int num)`：int类型转字符串函数
- `void read_from_file(const string &filename, string &m)`：从名为filename的文件中读出到字符串m中存储
- `void write_to_file(const string &filename, string &blocktext) `：将文件内容blocktext写入到名为filename的文件中
- `void send_to_server()`：发送文件到服务器（更新）
- `void send_to_server(string filename_and_path) `：发送文件到服务器
- group命名空间：该命名空间用来实现与可变哈希相关的函数，以及相关的序列化函数
- `group::PK get_pkhash() `：TODO
- `group::SK get_skhash() `：TODO
- `void trans_zz_to_string(const ZZ &c, std::string &m) `：将大整型数c转换成字符串m存储
- `void trans_zz_from_string(const ZZ &c, std::string &m) `：将字符串m转换成大整型数c
- `inline void trnas_dsa_signpk_from_string(std::string &m, DSA::PublicKey &pk)`：把字符串m转换成公钥pk
- `inline void trans_dsa_signsk_from_string(std::string &m, DSA::PrivateKey &sk) `：将字符串m转换成私钥sk
- `inline void trans_dsa_signpk_to_string(std::string &m, DSA::PublicKey &pk) `：将公钥pk转换到字符串m存储
- `inline void trans_dsa_signsk_to_string(std::string &m, DSA::PrivateKey &sk)`：将私钥sk转换到字符串m存储
- `inline void trans_to_string(std::string &m, T &key) `：将密钥key转换成字符串m存储
- `inline void trans_from_string(std::string &m, T &key) `：将字符串m转换成密钥key存储
- `inline void trans_aes_key_to_string(std::string &m, byte key[], byte iv[], int len = 16) `：将AES密钥转换成字符串
- `inline void trans_aes_key_from_string(std::string &m, byte *key, byte *iv, int len = 16) `：把AES密钥转换成字符串
- `inline void trans_elgamalpk_from_string(std::string tmp, ElGamalKeys::PublicKey &publickey) `：将16进制编码的字符串解码为公钥
- `inline void trans_elgamalsk_from_string(std::string tmp, ElGamalKeys::PrivateKey &privatekey) `：将16进制编码的字符串解码为私钥
- `inline void trans_elgamalpk_to_string(std::string &m, ElGamalKeys::PublicKey &publickey) `：将公钥编码为字符串存储
- `inline void trans_elgamalsk_to_string(std::string &m, ElGamalKeys::PrivateKey &privatekey) `：将私钥编码为字符串存储
- `group::MD _sign(const std::string &message, std::string &signature, group::PK pkhash, group::SK skhash, DSA::PrivateKey &privatekey) `：签名函数
-  `void serial_to_string(T &tuple, std::string &message) `：元组序列化函数。将新生成的元组对象序列化、签名、保存至本地文件、上传文件
- `void serial_to_file(RK &tuple) `：将RK元组序列化到文件并上传文件
- `void unserial_from_string(T &*tuple*, const std::string &*content*) `：元组反序列化函数：从字符串反序列化
- `void unserial_from_file(T &*tuple*, const std::string &*filename*) `：元组反序列化函数：从文件反序列化
- `void generate_aeskey(string &*key*) `：封装新的AES密钥
- `void aes_e(string &*k*, string &*cipher*, string &*plain*) `：AES加密
- `void aes_d(string &*k*, string &*cipher*, string &*plain*) `：AES解密
- `void aes_file(cipher_fk &*c*, F &*f*, string &*plain*) `：AES解密文件
- `void aes_file_e(cipher_fk &*c*, string &*cipher*, string &*plain*) `：AES加密文件


### 用户元组U

- $<U, (u, vk_{u}), \delta_{SU}>$

> 包含验证密钥$vk_{u}$和管理员的签名

**User类设计**

![image-20201226191921613](https://kay-rick.oss-cn-beijing.aliyuncs.com/img/20201226191922.png)

- $\_pvkey$：
- $\_pvsign$：
- $\_pbsign$：
- $\_g$：
- $\_y$：

### 角色密钥元组RK

- $<RK, u, r, Enc_{ek_{u}}^{Pub}(dk_{r})>$

> 为$u$提供了对$r$的解密密钥$dk_{r}$的加密强制访问

**Role类设计**

![image-20201226170505003](https://kay-rick.oss-cn-beijing.aliyuncs.com/img/20201226170506.png)

- $\_pvkey$：
- $\_pbkey$：
- $\_pvsign$：
- $\_pbsign$：
- $\_version$：

**User_Role映射类设计**

![image-20201226171018973](https://kay-rick.oss-cn-beijing.aliyuncs.com/img/20201226171020.png)

- $version$：

**RK类设计**

![image-20201226171005988](https://kay-rick.oss-cn-beijing.aliyuncs.com/img/20201226171006.png)

- $crypto\_rolekey$：
- $crypto\_rolesign$：
- $signature$：
- $r$：
- $s$：
- $sign(DSA::PrivateKey) : void$：

### 文件密钥元组FK

- $<FK, r, (f_{n}, op), Enc_{ek_{r}}^{Pub}(k)>$

> 存在一个具有$f$权限的角色$r$，管理员通过文件密钥FK元组分给$r$

**Role_File映射类设计**

![image-20201226171446486](https://kay-rick.oss-cn-beijing.aliyuncs.com/img/20201226171447.png)

- $\_op$：
- $version\_file$：
- $version\_role$：

**FK类设计**

![image-20201226171606480](https://kay-rick.oss-cn-beijing.aliyuncs.com/img/20201226171607.png)

- $operation$：
- $version\_file$：
- $version\_role$：
- $cipher\_fk$：
- $signature$：
- $r$：
- $s$：
- $tag$：

**辅助FK设计**

![image-20201226191322984](https://kay-rick.oss-cn-beijing.aliyuncs.com/img/20201226191323.png)

- $k\_0$：
- $k\_t$：
- $rpk$：
- $t$：

### 文件元组F

- $<F, f_{n}, Enc_{k}^{Sym}(f)>$

> 文件元组F包含文件名$f$和密文：提供了对$f$的文件密钥$k$的加密强制访问

- 只要读到了文件密钥k，就可以访问文件

**File类设计**

![image-20201226191647338](https://kay-rick.oss-cn-beijing.aliyuncs.com/img/20201226191648.png)

- $\_key$：
- $\_content$：

**F元组设计**

![image-20201226191812349](https://kay-rick.oss-cn-beijing.aliyuncs.com/img/20201226191813.png)

- $crypto\_file$：
- $signature$：
- $r$：
- $s$：

