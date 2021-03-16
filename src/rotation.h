/**
 * @file rotation.h
 * @author Rick (Kay_Rick@outlook.com)
 * @version 1.0
 * @date 2020-12-23 20:52:07
 * @brief 密钥列表压缩相关函数
 * 
 * @copyright Copyright (c) 2020 Rick, All Rights Reserved.
 * 
 */
#include <iostream>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <vector>

#include <NTL/ZZ.h>
#pragma comment(lib, "ntl.lib")
#pragma comment(lib, "cryptlib.lib")
using namespace std;
using namespace NTL;

/**
 * @brief 生成素数的位数
 * @return ZZ 
 */
ZZ gen_prime() {
    return GenPrime_ZZ(10);
}

ZZ gen_N(ZZ &p, ZZ &q) {
    return p * q;
}

ZZ gen_fi(ZZ &p, ZZ &q) {
    return (p - 1) * (q - 1);
}

/**
 * @brief 判断两个数是否互质
 * @param a 
 * @param b 
 * @return true 
 * @return false 
 */
bool primejudges(ZZ &a, ZZ &b) {
    ZZ j;
    for (j = 2; j <= a; j++) {
        if (a % j == 0 && b % j == 0) {
            return false;
        }
    }
    return true;
}

/**
 * @brief 获得公钥rpk
 * @param fi 
 * @return ZZ 
 */
ZZ getrpk(ZZ &fi) {
    ZZ a(10000000);
    ZZ low, high, dis;
    ZZ rpk;
    long bit = 10; //10位公钥
    low = power(ZZ(10), bit);
    high = power(ZZ(10), bit + 1);
    dis = (high - low + 1);
    while (1) {
        //srand((unsigned)time(NULL));
        //a=( ZZ(rand()) % dis+low);
        if (primejudges(a, fi)) {
            rpk = a;
            break;
        }
        a++;
    }
    cout << rpk << endl;
    return rpk;
}

/**
 * @brief 获得私钥
 * @param rpk 
 * @param fi 
 * @return ZZ 
 */
ZZ getrsk(ZZ &rpk, ZZ &fi) {
    ZZ i;
    ZZ rsk;
    for (i = 1;; i++) {
        if (((i * rpk) % fi) == 1) {
            rsk = i;
            break;
        }
    }
    return rsk;
}

/**
 * @brief 根据私钥和当前密钥，让所有者获得下一个的密钥
 * @param rsk 
 * @param cur 
 * @param N 
 * @return ZZ 
 */
ZZ BDri(ZZ &rsk, ZZ &cur, ZZ &N) {
    ZZ next;
    if (cur > N)
        cout << "too big" << endl;
    next = PowerMod(cur, rsk, N);
    return next;
}

/**
 * @brief 根据公钥和当前密钥，让用户获得密钥列表<k0, k1, ..., kt-1>
 * @param rpk 
 * @param cur 
 * @param t 
 * @param N 
 * @return vector<ZZ> 
 */
vector<ZZ> FDri(ZZ rpk, ZZ cur, int t, ZZ N) {
    vector<ZZ> list(t);
    list[t - 1] = cur;
    for (int i = 0; i < t - 1; i++) {
        list[t - 2 - i] = PowerMod(list[t - 1 - i], rpk, N);
    }
    return list;
}