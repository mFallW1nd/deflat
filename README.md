# Deobfuscation: recovering an OLLVM program
## Flatten Control Flow
### Description
基于cq674350529的deflat，利用angr框架生成目标函数CFG，然后利用unicorn框架重写了模拟执行并去除控制流平坦化的部分
>脚本依赖于angr框架及unicorn框架，以及capstone / keystone汇编与反汇编引擎
>
>具体依赖版本如下
>
>angr                   9.2.14
>
>unicorn                1.0.2rc4
>
>capstone               4.0.2
>
>keystone-engine        0.9.2
### Usage
```Plant Text
usage: my_deflat.py [-h] [-f FILE] [-a ADDR] [-e END]

deflat control flow script

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  binary to analyze
  -a ADDR, --addr ADDR  address of target function in hex format
  -e END, --end END     end address of target function in hex format
```
### Example
测试用例./ezam，标准控制流平坦化实现，来源于2022年春秋杯
```Plain Text
fallw1nd@fallw1nd-virtual-machine:~/Desktop/my/my_project/deflat$ python3 my_deflat.py -f ./ezam -a 0x4008F0 -e 0x00

[+] < Preparing for emulate execution >

[+] < Reconstructing control flow >
[0x401b3b] relevant executing!
                retn node
[0x4008f0] relevant executing!
                branch is:0x4010c3
[0x40157b] relevant executing!
                branch is:0x40144c
[0x40140b] relevant executing!
                branch is:0x401157
[0x4015e4] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401630
                branch 1 executing!
                        branch 1 is:0x401603
[0x4017f3] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401811
                branch 1 executing!
                        branch 1 is:0x4018c5
[0x401630] relevant executing!
                branch is:0x401646
[0x401668] relevant executing!
                branch 0 executing!
                        branch 0 is:0x4016ff
                branch 1 executing!
                        branch 1 is:0x401691
[0x401603] relevant executing!
                branch is:0x401b3b
[0x401913] relevant executing!
                branch is:0x401922
[0x4011fa] relevant executing!
                branch is:0x401398
[0x401a1e] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401acf
                branch 1 executing!
                        branch 1 is:0x401aa2
[0x40173b] relevant executing!
                branch is:0x401646
[0x40175c] relevant executing!
                branch is:0x401790
[0x4013c8] relevant executing!
                branch is:0x40140b
[0x401691] relevant executing!
                branch 0 executing!
                        branch 0 is:0x4016ff
                branch 1 executing!
                        branch 1 is:0x4016ba
[0x401922] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401974
                branch 1 executing!
                        branch 1 is:0x401947
[0x401974] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401996
                branch 1 executing!
                        branch 1 is:0x401aa2
[0x401179] relevant executing!
                branch is:0x4011d8
[0x40146e] relevant executing!
                branch is:0x40149a
[0x401ade] relevant executing!
                branch is:0x401790
[0x40159c] relevant executing!
                branch 0 executing!
                        branch 0 is:0x4015e4
                branch 1 executing!
                        branch 1 is:0x401603
[0x401646] relevant executing!
                branch 0 executing!
                        branch 0 is:0x40175c
                branch 1 executing!
                        branch 1 is:0x401668
[0x4017d5] relevant executing!
                branch 0 executing!
                        branch 0 is:0x4017f3
                branch 1 executing!
                        branch 1 is:0x40182f
[0x4014bc] relevant executing!
                branch is:0x401548
[0x40149a] relevant executing!
                branch 0 executing!
                        branch 0 is:0x40156c
                branch 1 executing!
                        branch 1 is:0x4014bc
[0x4010c3] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401141
                branch 1 executing!
                        branch 1 is:0x4010e5
[0x40156c] relevant executing!
                branch is:0x40157b
[0x401811] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401913
                branch 1 executing!
                        branch 1 is:0x4018ec
[0x401aa2] relevant executing!
                branch is:0x401b3b
[0x4017b2] relevant executing!
                branch is:0x4017d5
[0x4016ff] relevant executing!
                branch is:0x401b3b
[0x401947] relevant executing!
                branch is:0x401b3b
[0x40184d] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401913
                branch 1 executing!
                        branch 1 is:0x40186b
[0x4016ba] relevant executing!
                branch is:0x40172c
[0x401b0e] relevant executing!
                branch is:0x401b3b
[0x401120] relevant executing!
                branch is:0x4010c3
[0x401996] relevant executing!
                branch 0 executing!
                        branch 0 is:0x4019da
                branch 1 executing!
                        branch 1 is:0x401aa2
[0x401548] relevant executing!
                branch is:0x40149a
[0x401898] relevant executing!
                branch is:0x401922
[0x4011d8] relevant executing!
                branch 0 executing!
                        branch 0 is:0x4013c8
                branch 1 executing!
                        branch 1 is:0x4011fa
[0x401436] relevant executing!
                branch is:0x40144c
[0x401acf] relevant executing!
                branch is:0x401ade
[0x4018c5] relevant executing!
                branch is:0x401922
[0x401790] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401b0e
                branch 1 executing!
                        branch 1 is:0x4017b2
[0x401141] relevant executing!
                branch is:0x401157
[0x4019da] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401a1e
                branch 1 executing!
                        branch 1 is:0x401aa2
[0x401398] relevant executing!
                branch is:0x4011d8
[0x401157] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401436
                branch 1 executing!
                        branch 1 is:0x401179
[0x40182f] relevant executing!
                branch 0 executing!
                        branch 0 is:0x401898
                branch 1 executing!
                        branch 1 is:0x40184d
[0x4010e5] relevant executing!
                branch is:0x401120
[0x40172c] relevant executing!
                branch is:0x40173b
[0x4018ec] relevant executing!
                branch is:0x401922
[0x40186b] relevant executing!
                branch is:0x401922
[0x40144c] relevant executing!
                branch 0 executing!
                        branch 0 is:0x40159c
                branch 1 executing!
                        branch 1 is:0x40146e

[+] < Patching binary file >

[*] Recovered successfully! The output file is: ./ezam_recovered_0x4008f0
```
#### 恢复前
![image](https://user-images.githubusercontent.com/87085697/194522536-e2fcbcdc-0b78-44b0-a2af-d56ee7db4538.png)

#### 恢复后
![image](https://user-images.githubusercontent.com/87085697/194522590-7b691c40-db0d-45c9-80a0-bf50933e5570.png)
