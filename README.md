# AES加密算法
一个简单的，只按照算法的描述流程完成的代码，没有为了使用而弄的一些更复杂的东西，更适合新手宝宝体制
## 简介
AES支持128、192、256位长度的密钥，我只实现了128位的。192位要进行12轮循环，生成13个轮密钥，加解密需要12轮迭代；256对应要进行14轮循环。
## 使用方法
``` shell
git clone https://github.com/myh456/AES-encryption.git
cd ./AES-encryption
g++ main-128.cpp aes-128.cpp -o main.out    # Windows下写main.exe，对应下一行同样
./main.out
```