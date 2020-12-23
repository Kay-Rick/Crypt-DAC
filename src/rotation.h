#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include<vector>

#include <NTL/ZZ.h>
#pragma comment( lib, "myntl.lib")
#pragma comment( lib, "cryptlib.lib")
using namespace std;
using namespace NTL;

ZZ gen_prime(){
	return GenPrime_ZZ(10);//生成素数的位数
}

ZZ gen_N(ZZ& p,ZZ& q){
	return p*q; 
}

ZZ gen_fi(ZZ& p,ZZ& q){
	return (p-1)*(q-1);
}

bool primejudges(ZZ& a,ZZ& b)       //判断两个数是否互质
{
    ZZ j;
    for(j=2;j<=a;j++)
    {
        if(a%j==0 && b%j==0)
        {
                return false;
        }   
    }   
    return true;
}

ZZ getrpk(ZZ& fi)      //获得公钥rpk
{
    ZZ a(10000000);
    ZZ low,high,dis;
	ZZ rpk;
    long bit=10;//10位公钥
    low=power(ZZ(10),bit);
    high=power(ZZ(10),bit+1);
    dis=(high-low+1);
    while(1)
    {
        //srand((unsigned)time(NULL));
        //a=( ZZ(rand()) % dis+low);
        if(primejudges(a,fi))
        {
                rpk=a;
                break;
        }
		a++;
    }
	cout<<rpk<<endl;
    return rpk;
}

ZZ getrsk(ZZ& rpk,ZZ& fi)         //获得私钥
{
    ZZ i;
	ZZ rsk;
    for(i=1;;i++){
        if(((i*rpk)%fi)==1)
		{
			rsk=i;
			break;
		}
	}
    return rsk;
}

ZZ BDri(ZZ& rsk,ZZ& cur,ZZ& N)           //根据私钥和当前密钥，让所有者获得下一个的密钥
{
	ZZ next;
	if(cur>N) cout<<"too big"<<endl;
	next=PowerMod(cur,rsk,N);
	return next;
}

vector<ZZ> FDri(ZZ rpk,ZZ cur,int t,ZZ N)        //根据公钥和当前密钥，让用户获得以前所有的密钥
{
	vector<ZZ> list(t);
	list[t-1]=cur;
	for(int i=0;i<t-1;i++){
		list[t-2-i]=PowerMod(list[t-1-i],rpk,N);
	}
	return list;
}