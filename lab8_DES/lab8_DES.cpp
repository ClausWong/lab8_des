// DES_lab.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include"math.h"
#include <stdio.h>
#include<iostream>  
#include<string.h>  
#include"DES_encode.h"

char tempkey[17] = { "34e9f71a20756231" }; //系统指定的秘钥;

//生成固定明文
void write(CDes des, int *isum){
	//自动生成指定数量的明文并分别写入plain.txt文本中，isum为控制数
	FILE *fileSrc;
	char cplaintext[17];
	int icount = 0;
	errno_t err;

	/*err = fopen_s(&fileSrc,"plain.txt", "w+");
	if (err!= 0){
		printf("无法打开 plain.txt!\n");
		exit(0);
	}*/
	fileSrc = fopen("plain.txt", "r+");
	if (fileSrc == NULL){
		printf("无法打开 plain.txt!\n");
		exit(0);
	}

	while (icount<*isum)
	{
		des.Randomplaintext(cplaintext);
		fwrite(cplaintext, sizeof(char), 16, fileSrc);
		icount++;
	}
	fclose(fileSrc);
}
//用获得的秘钥和明文加密
bool Des_encryption(CDes des,bool nolinear){
	bool bCry[64], bPlain[64], bKey[64]; //bKey储存64位2进制的秘钥 bPlain储存64位2进制的原文 bCry储存64位2进制的密文
	char *pkeyhex = new char;  //指向16进制的秘钥的指针
	char cselect[10] = { '0' };
	bool bflag = 1;
	FILE* fileSrc , *fileDest ;
	char tempsrc[17];
	errno_t err;

	printf("请选择秘钥生成的方式:(i or r)\n ");
	printf("i-实验者手动输入\n");
	printf(" r-随机自动生成\n");
	while (bflag)
	{
		int ilen = 0;
		scanf_s("%s", &cselect,10);//获得输入并判断
		getchar();
		while (cselect[ilen] != '\0')
			ilen++;
		if (ilen > 1)
			cselect[0] = 'e';
		if (cselect[0] == 'i' || cselect[0] == 'I'){
			pkeyhex = des.Inputkey();//手动输入秘钥
			bflag = 0;
		}
		else if (cselect[0] == 'r' || cselect[0] == 'R'){
			pkeyhex = tempkey;//系统制定秘钥
			bflag = 0;
		}
		else
			printf("输入字符无效！请重新输入！\n");
	}
	des.HexToBit(bKey, pkeyhex, 16);//16进制到2进制
	if (nolinear)
	{
		/*err = fopen_s(&fileSrc, "plain.txt", "w+");
		if (err != 0){
			printf("无法打开 plain.txt!\n");
			return 0;
		}*/
		fileSrc = fopen("plain.txt", "w+");
		if (fileSrc == NULL){
			printf("无法打开 plain.txt!\n");
			exit(0);
		}

		/*err = fopen_s(&fileDest, "cipher.txt", "w+");
		if (err != 0){
			printf("无法打开 cipher.txt!\n");
			return 0;
		}*/
		fileDest = fopen("cipher.txt", "w+");
		if (fileDest == NULL){
			printf("无法打开 cipher.txt!\n");
			exit(0);
		}

	}
	else
	{
		/*err = fopen_s(&fileSrc, "plain.txt", "r+");
		if (err != 0){
			printf("无法打开 plain.txt!\n");
			return 0;
		}*/
		fileSrc = fopen("plain.txt", "r+");
		if (fileSrc == NULL){
			printf("无法打开 plain.txt!\n");
			exit(0);
		}

		/*err = fopen_s(&fileDest, "cipher.txt", "w+");
		if (err != 0){
			printf("无法打开 cipher.txt!\n");
			return 0;
		}*/
		fileDest = fopen("cipher.txt", "w+");
		if (fileDest == NULL){
			printf("无法打开 cipher.txt!\n");
			exit(0);
		}

	}	
	fwrite("7e5a6d012c890f2a", sizeof(char), 16, fileSrc);
	rewind(fileSrc);
	while (!feof(fileSrc))//循环读取明文并加密
	{
		unsigned int nRead = fread(tempsrc, sizeof(char), 16, fileSrc);
		if (nRead == 0)
			break;
		if ((nRead < 16) && (nRead>0))
			memset(tempsrc + nRead, 0, 16 - nRead);
		des.HexToBit(bPlain,tempsrc,16);
		des.Encrypt(bCry,bPlain,bKey);
		des.Setflag();
		char tempdest[16];
		des.BitToHex(tempdest,bCry,16);
		fwrite(tempdest, sizeof(char), 16, fileDest);
		if (nolinear)
		{
			printf("系统自动加密，加密后的密文是：\n");
			for (int i = 0; i < 16; i++)
				printf("%c", tempdest[i]);

		}
	}
	fclose(fileSrc);
	fclose(fileDest);
	//	delete pkeyhex;
	printf("\n");
	return true;
}
void Des_Analysis(CDes des, int *inum){
	bool bflag = 1;
	char cinput[10] = { 0 };
	printf("下面我们将进行5轮DES线性密码破解。在已知明密文对的情况下用线性攻击法攻击5轮DES的时候，可以将5轮DES看作是4+1轮的DES（前面4轮加上最后一轮），首先，我们要由上面可得到前4轮的线性关系式，然后猜测最后一轮的部分子秘钥来将最后一轮与前面4轮的线性关系式串联起来。\n");
	printf("第一步：对Kn的每一个候选值Ki，设Ti是使得等式（1）的左边等于0的明文的个数。\n第二步：设Tmax=max{Ti},Tmin=min{Ti}.\n如果|Tmax-N/2|>|Tmin-N/2|(N为明文的个数)，那么Tmax将所对应的密钥候选值作为Kn，当p>1/2时，猜想K[k1,k2,...,kc]=1；当p<1/2时，猜想K[k1,k2,...,kc]=0\n如果|Tmax-N/2|<|Tmin-N/2|，那么Tmin将所对应的密钥候选值作为Kn，当p>1/2时，猜想K[k1,k2,...,kc]=1；当p<1/2时，猜想K[k1,k2,...,kc]=0(其中N为明文的个数)\n");
	printf("以上算法成功率： ∞\n");
	printf("               ∫                1/(2π）^(1/2))e^((-x^2)/2)dx\n");
	printf("                -2N^(1/2)|p-1/2|\n");
	printf("我们列出了明密文对N和算法成功率的部分表，帮助研究者输入随机生成明密文对的个数。\n");
	printf("\t┏━━━┳━━━┳━━━┳━━━┳━━━┓\n");
	printf("\t┃  N   ┃  700 ┃ 1400 ┃ 2800 ┃ 5600 ┃\n");
	printf("\t┣━━━╋━━━╋━━━╋━━━╋━━━┫\n");
	printf("\t┃成功率┃84.1%\t┃92.1%\t┃97.7%\t┃ 99.8%\t┃    \n");
	printf("\t┗━━━┻━━━┻━━━┻━━━┻━━━┛\n");
	des.Setflag();
	printf("请输入随机生成明密文对的个数，系统将自动生成！\n");
	while (bflag)
	{
		int ilen=0;
		scanf_s("%s",cinput,10);
		getchar();
		while (cinput[ilen]!='\0')
		{
			if (cinput[ilen] >= '0'&&cinput[ilen] <= '9')
				ilen++;
			else
			{
				ilen = 0;
				break;
			}
		}
		if (ilen > 0)
		{
			for (int i = 0; i < ilen; i++)
				*inum = *inum + pow(10, ilen -1- i)*(cinput[i]-'0');
			bflag = 0;
		}
		else
			printf("输入非法！请重新输入！\n");
	}
	write(des, inum);
	if (Des_encryption(des,0))
	{
		printf("随机生成了%d对明密文，按Enter键继续\n", *inum);
		getchar();
	}
//	system("CLS");

}
void linear_menu(){
	system("CLS");
	CDes linear(5);
	int iS1_table[63][15] = { 0 };//S1盒的分布表
	int iS5_table[63][15] = { 0 };//S5盒的分布表
	int ixbit[4][6] = { 0 };//ixbit[0]为第1轮X[] ixbit[1]为第2轮X[] ixbit[2]为第4轮X[] ixbit[3]为第5轮X[]
	int ikbit[4][6] = { 0 };//ikbit[0]为第1轮K[] ikbit[1]为第2轮K[] ikbit[2]为第4轮K[] ikbit[3]为第5轮K[]
	int ifbit[4][6] = { 0 };//ifbit[0]为第1轮F(X,K)[] ifbit[1]为第2轮F(X,K)[] ifbit[2]为第4轮F(X,K)[] ifbit[3]为第5轮F(X,K)[]
	int iin[5] = { 0 };//iin[0]为第1轮输入端为1的位数 iin[1]为第2轮输入端为1的位数 iin[3]为第4轮输入端为1的位数 iin[4]为第5轮输入端为1的位数
	int iout[5] = { 0 };//iout[0]为第1轮输出端为1的位数 iout[1]为第2轮输出端为1的位数 iout[3]为第4轮输出端为1的位数 iout[4]为第5轮输出端为1的位数
	float fp = 0, ftemp = 0;//fp是最佳逼近函数的成立概率 ftemp 为中间变量
	int inum = 0;//输入明密文对
	char ckey[17],tempsrc[17],tempdst[17];//tempkey储存16位16进制的秘钥 tempsrc储存16位16进制的原文 tempdst储存16位16进制的密文
	bool bCry[64], bPlain[64], bKey[64];//bKey储存64位2进制的秘钥 bPlain储存64位2进制的原文 bCry储存64位2进制的密文
	FILE* fileSrc = NULL, *fileDest = NULL;//fileSrc指向原文文件的指针 fileDest指向密文文件的指针
	int icounter[64] = { 0 };
	int icounter5[64] = { 0 };
	bool bcounter[6] = { 0 };
	bool bcounter5[6] = { 0 };
	bool btemp[56] = { 0 };
	int ik1 = 0, ik5 = 0;
	int iscope = 0;
	errno_t err;

	printf("线性密码分析的大致步骤可以分为如下四步。\n第一步，利用统计测试的方法给出轮函数中主要密码模块的输入、输出之间的一些线性逼近及其成立的概率。\n第二步，进一步构造每一轮的输入、输出之间的线性逼近，并计算出成立的概率；\n第三步，将各轮的线性逼近按顺序级别连起来，消除中间变量，得到涉及明文、密文和密钥的线性逼近；\n第四步，利用算法猜测密钥的某几位，并暴力破解剩下位数。具体如下：\n");
	printf("首先，要获得一个有效的线性表达式。具体的算法描述:\n 对于一个给定的S盒，Si（1≤i≤8）,1≤α≤63和1≤β≤15,定义 NSi（α,β）=|{x|1≤x≤63，x[0]&α[0]⊕x[1]&α[1]⊕x[2]&α[2]⊕x[3]&α[3]⊕x[4]&α[4]⊕x[5]&α[5]=S(x)[0]&β[0]⊕S(x)[1]&β[1]⊕S(x)[2]&β[2]⊕S(x)[3]&β[3]}|\n");
	linear.Sbox_distribution(iS1_table, 0);// S1盒的分布表
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	linear.Sbox_distribution(iS5_table, 4);;// S5盒的分布表
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	printf("然后我们把NS1(27,4)=22分别应用到5轮DES的第1、5轮，NS5(16,15)=12应用到5轮DES的第2、4轮，便可得到每一轮的逼近函数。\n");
	linear.Approximation(ixbit[0], ikbit[0], ifbit[0], 0, 27, 4, 0, iin, iout);//把NS1(27，4)应用到第1轮的逼近函数
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	linear.Approximation(ixbit[1], ikbit[1], ifbit[1], 4, 16, 15, 1, iin, iout);//把NS5(16，15)应用到第2轮的逼近函数
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	linear.Approximation(ixbit[2], ikbit[2], ifbit[2], 4, 16, 15, 3, iin, iout);//把NS5(16，15)应用到第4轮的逼近函数
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	linear.Approximation(ixbit[3], ikbit[3], ifbit[3], 0, 27, 4, 4, iin, iout);//把NS1(27，4)应用到第5轮的逼近函数
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	printf("将以上输出作为输入，自动进行异或，得到的5轮DES的线性逼近表达式为：\n");//输出5轮最佳逼近函数
	printf("PH[");
	for (int i = iout[0] - 1; i > 0; i--)
		printf("%2d,", 31 - ifbit[0][i]);
	printf("%2d]⊕PL[", 31 - ifbit[0][0]);
	for (int i = iout[1] - 1; i >= 0; i--)
		printf("%2d,", 31 - ifbit[1][i]);
	for (int i = iin[0] - 1; i >0; i--)
		printf("%2d,", 31 - ixbit[0][i]);
	printf("%2d]⊕CH[", 31 - ixbit[0][0]);
	for (int i = iout[4] - 1; i >0; i--)
		printf("%2d,", 31 - ifbit[3][i]);
	printf("%2d]⊕CL[", 31 - ifbit[3][0]);
	for (int i = iout[3] - 1; i >= 0; i--)
		printf("%2d,", 31 - ifbit[2][i]);
	for (int i = iin[4] - 1; i > 0; i--)
		printf("%2d,", 31 - ixbit[3][i]);
	printf("%2d]=K1[", 31 - ixbit[3][0]);
	for (int i = iin[0] - 1; i >0; i--)
		printf("%2d,", 47 - ikbit[0][i]);
	printf("%2d]⊕K2[", 47 - ikbit[0][0]);
	for (int i = iin[1] - 1; i >0; i--)
		printf("%2d,", 47 - ikbit[1][i]);
	printf("%2d]⊕K4[", 47 - ikbit[1][0]);
	for (int i = iin[3] - 1; i > 0; i--)
		printf("%2d,", 47 - ikbit[2][i]);
	printf("%2d]⊕K5[", 47 - ikbit[2][0]);
	for (int i = iin[4] - 1; i > 0; i--)
		printf("%2d,", 47 - ikbit[3][i]);
	printf("%2d]          (1)\n", 47 - ikbit[3][0]);//固定输出格式 输出5轮逼近函数的表达式
	fp = iS1_table[26][3] - 32;
	ftemp = iS5_table[15][14] - 32;
	fp = pow(2, 3)* pow(fp / 64, 2);
	fp = 1.0 / 2 + fp*pow(ftemp / 64, 2);
	printf("上式成立的概率是%.3f\n", fp);
	Des_Analysis(linear, &inum);
	/*err = fopen_s(&fileSrc, "plain.txt", "r+");
	if (err != 0){
		printf("无法打开 plain.txt!\n");
		exit(0);
	}*/
	fileSrc = fopen("plain.txt", "r+");
	if (fileSrc == NULL){
		printf("无法打开 plain.txt!\n");
		exit(0);
	}

	/*err = fopen_s(&fileDest, "cipher.txt", "r+");
	if (err != 0){
		printf("无法打开 cipher.txt!\n");
		exit(0);
	}*/
	fileDest = fopen("cipher.txt", "r+");
	if (fileDest == NULL){
		printf("无法打开 cipher.txt!\n");
		exit(0);
	}

	//枚举K1的6位带到算法2猜测k1的6位
	printf("系统在对K1的第42、43、44、45、46、47位进行猜测，请稍后！");
	for (int i = 0; i < 64; i++)
	{
		linear.IntToSixBit(bcounter,i);
		bool btemp[56] = { 0 };
		btemp[14] = bcounter[5]; btemp[17] = bcounter[4]; btemp[11] = bcounter[3]; btemp[24] = bcounter[2]; btemp[1] = bcounter[1]; btemp[5] = bcounter[0];
		rewind(fileSrc); rewind(fileDest);
		linear.Setflag();
		linear.Produce(btemp);
		while (!feof(fileSrc) && !feof(fileDest))
		{
			bool bxor = 0;
			bool bplow[32] = { 0 };
			unsigned int nRead = fread(tempsrc, sizeof(char), 16, fileSrc);
			unsigned int nRead1 = fread(tempdst, sizeof(char), 16, fileDest);
			if (nRead == 0)
				break;
			if ((nRead < 16) && (nRead>0))
				memset(tempsrc + nRead, 0, 16 - nRead);
			linear.HexToBit(bPlain, tempsrc, 16);
			if (nRead1 == 0)
				break;
			if ((nRead1 < 16) && (nRead1>0))
				memset(tempdst + nRead1, 0, 16 - nRead1);
			linear.HexToBit(bCry, tempdst, 16);
			for (int j = 0; j < 32; j++)
				bplow[j] = bPlain[32 + j];
			for (int j = 0; j < iout[0]; j++)
				bxor ^= bCry[32+ifbit[0][j]];
			for (int j = 0; j < iin[0]; j++)
				bxor ^= bCry[ ixbit[0][j]];
			for (int j = 0; j < iout[1]; j++)
				bxor ^= bCry[ifbit[1][j]];
			for (int j = 0; j < iout[3]; j++)
				bxor ^= bPlain[32 + ifbit[2][j]];
			for (int j = 0; j < iout[4]; j++)
				bxor ^= bPlain[ifbit[3][j]];
			linear.Function(bplow, bplow,0);
			for (int j = 0; j < iout[4]; j++)
				bxor ^= bplow[ifbit[3][j]];
			if (bxor == 0)
				icounter[i]++;
	   }
	}
	//枚举K5的6位带到算法2猜测k5的6位
	printf("系统在对K5的第42、43、44、45、46、47位进行猜测，请稍后！");
	for (int i = 0; i < 64; i++)
	{
		linear.IntToSixBit(bcounter, i);
		bool btemp5[56] = { 0 };
		btemp5[21] = bcounter[5]; btemp5[24] = bcounter[4]; btemp5[18] = bcounter[3]; btemp5[3] = bcounter[2]; btemp5[8] = bcounter[1]; btemp5[12] = bcounter[0];
		rewind(fileSrc); rewind(fileDest);
		linear.Setflag();
		linear.Produce(btemp5);
		while (!feof(fileSrc) && !feof(fileDest))
		{
			bool bxor = 0;
			bool bclow[32] = { 0 };
			unsigned int nRead = fread(tempsrc, sizeof(char), 16, fileSrc);
			unsigned int nRead1 = fread(tempdst, sizeof(char), 16, fileDest);
			if (nRead == 0)
				break;
			if ((nRead < 16) && (nRead>0))
				memset(tempsrc + nRead, 0, 16 - nRead);
			linear.HexToBit(bPlain, tempsrc, 16);
			if (nRead1 == 0)
				break;
			if ((nRead1 < 16) && (nRead1>0))
				memset(tempdst + nRead1, 0, 16 - nRead1);
			linear.HexToBit(bCry, tempdst, 16);
			for (int j = 0; j < 32; j++)
				bclow[j] = bCry[j];
			for (int j = 0; j < iout[0]; j++)
				bxor ^= bPlain[ ifbit[0][j]];
			for (int j = 0; j < iin[0]; j++)
				bxor ^= bPlain[32 +ixbit[0][j]];
			for (int j = 0; j < iout[1]; j++)
				bxor ^= bPlain[32 +ifbit[1][j]];
			for (int j = 0; j < iout[3]; j++)
				bxor ^= bCry[ifbit[2][j]];
			for (int j = 0; j < iout[4]; j++)
				bxor ^= bCry[32+ifbit[3][j]];
			linear.Function(bclow, bclow, 4);
			for (int j = 0; j < iout[4]; j++)
				bxor ^= bclow[ifbit[3][j]];
			if (bxor == 0)
				icounter5[i]++;
		}
	}
	for (int i = 0; i < 64; i++)
	{
		if (abs(icounter[ik1] - inum / 2) < abs(icounter[i] - inum / 2))
			ik1 = i;
		if (abs(icounter5[ik5] - inum / 2) < abs(icounter5[i] - inum / 2))
			ik5 = i;
	}
	//这之前完成估计K5的6位和K1的6位
	linear.IntToSixBit(bcounter, ik1);
	linear.IntToSixBit(bcounter5, ik5);
	rewind(fileSrc); rewind(fileDest);
	linear.Setflag();
	unsigned int nRead = fread(tempsrc, sizeof(char), 16, fileSrc);
	unsigned int nRead1 = fread(tempdst, sizeof(char), 16, fileDest);
	if (nRead == 0)
		exit(0);
	if ((nRead < 16) && (nRead>0))
		memset(tempsrc + nRead, 0, 16 - nRead);
	linear.HexToBit(bPlain, tempsrc, 16);
	if (nRead1 == 0)
		exit(0);
	if ((nRead1 < 16) && (nRead1>0))
		memset(tempdst + nRead1, 0, 16 - nRead1);
	linear.HexToBit(bCry, tempdst, 16);
	printf("通过上述算法，我们获得了秘钥的第2、4、6、9、12、13、15、18、19、22、25位，分别是%d、%d、%d、%d、%d、%d、%d、%d、%d、%d、%d", bcounter[1], bcounter5[2], bcounter[0], bcounter5[1], bcounter[3], bcounter5[0], bcounter[5], bcounter[4], bcounter5[3], bcounter5[5], bcounter[2]);
	printf("和K1[2,3,5,6]⊕K2[26]⊕K4[26]=%d、K2[26]⊕K4[26]⊕K5[2,3,5,6]=%d\n", (icounter5[ik5] > inum / 2 ? 1 : 0), (icounter[ik1] > inum / 2 ? 1 : 0));
	bool btempl[28] = { 0 };
	linear.Keyscope(btempl, tempkey);
	btemp[21] = bcounter5[5];  btemp[24] = bcounter5[4]; btemp[18] = bcounter5[3]; btemp[3] = bcounter5[2]; btemp[8] = bcounter5[1]; btemp[12] = bcounter5[0]; btemp[14] = bcounter[5]; btemp[17] = bcounter[4];  btemp[11] = bcounter[3];btemp[1] = bcounter[1]; btemp[5] = bcounter[0];
	bool bflag2 ;
	for (int i = 0; i < 28; i++)
		btemp[28 + i] = btempl[i];
	for (int j = 0; j < pow(2, 17); j++)
	{
		bflag2 = false;
		bool btemph[17] = { 0 };
		bool btempcry[64] = { 0 };
		linear.IntToBit(btemph, j, 17);
		btemp[0] = btemph[16]; btemp[2] = btemph[15];  btemp[4] = btemph[14];
		btemp[6] = btemph[13]; btemp[7] = btemph[12]; btemp[9] = btemph[11]; btemp[10] = btemph[10];
		btemp[13] = btemph[9];  btemp[15] = btemph[8]; btemp[16] = btemph[7]; 
		btemp[19] = btemph[6]; btemp[20] = btemph[5]; btemp[22] = btemph[4]; btemp[23] = btemph[3];
		btemp[25] = btemph[2]; btemp[26] = btemph[1]; btemp[27] = btemph[0];
		linear.Produce(btemp);
		if (linear.limit(4, (icounter[ik1] > inum / 2 ? 1 : 0)) && linear.limit(0, (icounter5[ik5] > inum / 2 ? 1 : 0)))
		{
			linear.Encryption(btempcry, bPlain);	
			bool bresult = 1;
			for (int k = 0; k < 64; k++)
			{
				if (btempcry[k]!=bCry[k])
				{
					bresult = 0;
					break;
				}
			}
			if (bresult)
			{
				linear.Key(bKey, btemp);
			  linear.BitToHex(ckey, bKey,16);
				printf("当密钥的范围足够小时，我们将暴力破解剩下密钥位。经过暴力破解我们得到出密钥：");
				for (int k = 0; k < 16; k++)
					printf("%c",ckey[k]);
				printf("\n");
			    bflag2 = true;
				break ;
			}
		}
		if (bflag2)
			break;	
	}
	if (!bflag2){
		printf("明密文对太少，没能破解出正确的秘钥！\n");
	}
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	printf("\t\t**************************************************************************************\n");
	printf("\t\t*                                主菜单                                              *\n");
	printf("\t\t*                                                                                    *\n");
	printf("\t\t*                           1-  5轮DES线性分析                                       *\n");
	printf("\t\t*                           2-  5轮DES非线性分析                                     *\n");
	printf("\t\t*                           0-  退出                                                 *\n");
	printf("\t\t**************************************************************************************\n");
	printf("\t\t\t请选择功能：(0-2)\n");
}

void unlinear_menu(){
	int iS1_table[63][15] = { 0 };//S1盒的分布表
	int iS5_table[63][15] = { 0 };//S5盒的分布表
	int iS5_table1[63][15] = { 0 };//S5盒的分布表
	float fN_table[25][10] = { 0.5, 0.504, 0.508, 0.512, 0.516, 0.5199, 0.5239, 0.5279, 0.5319, 0.5359, 0.5398, 0.5438, 0.5478, 0.5517, .5557, 0.5596, 0.5636, 0.5675,0.5714, 0.5753, 
		0.5793, 0.5832, 0.5871, 0.591, 0.5948, 0.5987, 0.6026, 0.6064, 0.6103, 0.6141, 0.6179, 0.6217, 0.6255, 0.6293, .6331, 0.6368, 0.6406, 0.6443,0.648, 0.6517, 0.6554, 0.6591, 
		0.6628, 0.6664, 0.67, 0.6736, 0.6772, 0.6808, 0.6844, 0.6879, 0.6915, 0.695, 0.6985, 0.7019, .7054, .7088, .7123, .7157, .719, 0.7224,0.7257, 0.7291, 0.7324, 0.7357, 0.7389,
		0.7422, 0.7454, .7486, 0.7517, 0.7549, 0.758, 0.7611, 0.7642, 0.7673, 0.770, 0.7734, 0.7764, 0.7794, 0.7823, 0.7852, 0.7881, 0.791,0.7939, 0.7967, 0.7995, 0.8023, 0.8051, 0.8078, 
		0.8106, 0.8133, 0.8159, 0.8186, 0.8212, 0.8238, 0.8264, 0.8289, 0.8315, 0.834, 0.8365, 0.8389, 0.8413, 0.8438, 0.8461, 0.8485,0.8508, 0.8531, 0.8554, 0.8577, 0.8599, 0.8621, 0.8643,
		0.8665, 0.8686, 0.8708, .8729, 0.8749, 0.877, 0.879, 0.881, 0.883, 0.8849, 0.8869, 0.8888, 0.8907, 0.8925, 0.8944, 0.8962,0.898, 0.8997, 0.9015, 0.9032, 0.9049, 0.9066, 0.9082, 0.9099,
		0.9115, .9131, 0.9147, 0.9162, 0.9177, 0.9192, 0.9207, .9222, .9236, .9251, .9266, .9278, .9292, .9306, .9319, .9332, .9345, .937, .937, .9382, .9394, .9406, .9418, .943, .9441, .9452,
		.9463, .9474, .9484, .9495, .9505, .9515, .9525, .9535, .9545, .9554, .9564, .9573, .9582, .9591, .9599, .9608, .9616,.9625, .9633, .9641, .9648, .9656, .9664, .9671, .9678, .96836, .9693,
		.97, .9706, .9713, .9719, .9726, .9732, .9738, .9744, .975, .9756, .9762, .9767, .9772, .9778, .9783, .9788, .9793,.9798, .9803, .9808, .9812, .9817, .9821, .9826, .983, .9834, .9838, .9842,
		.9846, .985, .9854, .9857, .9861, .9864, .9868, .9871, .9874, .9878, .9881, .9884, .9887, .989, .9893, .9896, .9898,.9901, .9904, .9906, .9909, .9911, .9913, .9916, .9918, .992, .9922, .9925, .9927, .9929, .9931, .9932, .9934, 1 };
	int ixbit[4][6] = { 0 };//ixbit[0]为第1轮X[] ixbit[1]为第2轮X[] ixbit[2]为第4轮X[] ixbit[3]为第5轮X[]
	int ikbit[4][6] = { 0 };//ikbit[0]为第1轮K[] ikbit[1]为第2轮K[] ikbit[2]为第4轮K[] ikbit[3]为第5轮K[]
	int ifbit[4][6] = { 0 };//ifbit[0]为第1轮F(X,K)[] ifbit[1]为第2轮F(X,K)[] ifbit[2]为第4轮F(X,K)[] ifbit[3]为第5轮F(X,K)[]
	int iin[5] = { 0 };//iin[0]为第1轮输入端为1的位数 iin[1]为第2轮输入端为1的位数 iin[3]为第4轮输入端为1的位数 iin[4]为第5轮输入端为1的位数
	int iout[5] = { 0 };//iout[0]为第1轮输出端为1的位数 iout[1]为第2轮输出端为1的位数 iout[3]为第4轮输出端为1的位数 iout[4]为第5轮输出端为1的位数
	float fp[5] = {0},ftemp=0,fptemp=0;
	char cselect[10] = { 0 };
	int icouple,irank,irow;
	char cinput[10] = { 0 };
	bool bflag = 1;
	system("CLS");
	CDes des(5);
	Des_encryption(des,1);
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	des.Sbox_distribution(iS5_table,4);
	fp[0] = iS5_table[15][14] - 32;
	fp[0] = abs(fp[0] / 64);
	printf("请输入轨迹A:NS5(16,15)线性可能性偏移量！(四舍五入，保留四位小数)\n");
	while (bflag)
	{
		int ilen = 0,ipoint=0;
		scanf_s("%s", cinput,10);
		getchar();
		while (cinput[ilen]!='\0')
		{
			if ((cinput[ilen] >= '0' && cinput[ilen] <='9') || cinput[ilen] == '.')
			{
				if (cinput[ilen] == '.')
					ipoint = ilen;
				ilen++;
			}
			else
			{
				ilen = 0;
				break;
			}
		}
		if (ilen > 0)
		{
			for (int i = 0; i < ilen; i++)
			{
				if (i<ipoint)
					ftemp = ftemp + pow(10, ipoint - 1 - i)*(cinput[i] - '0');
				if (i>ipoint)
					ftemp = ftemp + pow(10, ipoint - i)*(cinput[i] - '0');
			}
			bflag = 0;
		}
		else
			printf("输入非法！请重新输入！\n");

	}
	if ((int)(ftemp * 10000) == (int)((fp[0] + 0.00005) * 10000))
		printf("恭喜你！计算正确！\n");
	else
	{
		printf("很遗憾！计算错误！\n");
		printf("正确的可能性偏移量是：%.4f\n", fp[0]);
	}
	fp[1] = iS5_table[15][13] - 32;
	fp[1] = abs(fp[1] / 64);
	ftemp = 0; bflag = 1;
	printf("请输入轨迹D:NS5(16,14)线性可能性偏移量!(四舍五入，保留四位小数)\n");
	while (bflag)
	{
		int ilen = 0, ipoint = 0;
		scanf_s("%s", cinput,10);
		getchar();
		while (cinput[ilen] != '\0')
		{
			if ((cinput[ilen] >= '0' && cinput[ilen] <= '9') || cinput[ilen] == '.')
			{
				if (cinput[ilen] == '.')
					ipoint = ilen;
				ilen++;
			}
			else
			{
				ilen = 0;
				break;
			}
		}
		if (ilen > 0)
		{
			for (int i = 0; i < ilen; i++)
			{
				if (i<ipoint)
					ftemp = ftemp + pow(10, ipoint - 1 - i)*(cinput[i] - '0');
				if (i>ipoint)
					ftemp = ftemp + pow(10, ipoint - i)*(cinput[i] - '0');
			}
			bflag = 0;
		}
		else
			printf("输入非法！请重新输入！\n");

	}
	if ((int)(ftemp * 10000) == (int)((fp[1] + 0.00005) * 10000))
		printf("恭喜你！计算正确！\n");
	else
	{
		printf("很遗憾！计算错误！\n");
		printf("正确的可能性偏移量是：%.4f\n", fp[1]);
	}
	fp[2] = abs(18.0 / 64);
	printf("轨迹D'的线性可能性偏移量是：%.4f\n",fp[2]);
	fp[3] = abs(24.0 / 64);
	printf("轨迹A'的线性可能性偏移量是：%.4f\n",fp[3]);
	des.Sbox_distribution(iS1_table, 0);
	fp[4] = iS1_table[3][3] - 32;
	fp[4] = abs(fp[4] / 64);
	ftemp = 0; bflag = 1;
	printf("请输入轨迹C:NS1(4,4)线性可能性偏移量！(四舍五入，保留四位小数)\n");
	while (bflag)
	{
		int ilen = 0, ipoint = 0;
		scanf_s("%s", cinput,10);
		getchar();
		while (cinput[ilen] != '\0')
		{
			if ((cinput[ilen] >= '0' && cinput[ilen] <= '9') || cinput[ilen] == '.')
			{
				if (cinput[ilen] == '.')
					ipoint = ilen;
				ilen++;
			}
			else
			{
				ilen = 0;
				break;
			}
		}
		if (ilen > 0)
		{
			for (int i = 0; i < ilen; i++)
			{
				if (i<ipoint)
					ftemp = ftemp + pow(10, ipoint - 1 - i)*(cinput[i] - '0');
				if (i>ipoint)
					ftemp = ftemp + pow(10, ipoint - i)*(cinput[i] - '0');
			}
			bflag = 0;
		}
		else
			printf("输入非法！请重新输入！\n");

	}
	if ((int)(ftemp * 10000) == (int)((fp[4]+0.00005) * 10000))
		printf("恭喜你！计算正确！\n");
	else
	{
		printf("很遗憾！计算错误！\n");
		printf("正确的可能性偏移量是：%.4f\n", fp[4]);
	}
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	printf("请在下列非线性轨迹方案选择一个!\n");
	printf("1-   A'CD-D'\n2-   A'CA-D'\n3-   D'A-AA'\n");
	bflag = 1;
	while (cselect[0] != '1' && cselect[0] != '2' && cselect[0] != '3' )
	{
		int ilen = 0;
		scanf_s("%s", &cselect,10);
		getchar();
		while (cselect[ilen]!='\0')
			ilen++;
		if (ilen > 1)
			cselect[0] = 'e';
		switch (cselect[0])
		{
		case '1':
		{
			while (bflag)
			{
				int ilen = 0, ipoint = 0;
				printf("请计算该非线性轨迹的逼近概率！(四舍五入，保留三位小数)\n");
				scanf_s("%s", cinput,10);
				getchar();
				while (cinput[ilen] != '\0')
				{
					if ((cinput[ilen] >= '0' && cinput[ilen] <= '9') || cinput[ilen] == '.')
					{
						if (cinput[ilen] == '.')
							ipoint = ilen;
						ilen++;
					}
					else
					{
						ilen = 0;
						break;
					}
				}
				if (ilen > 0)
				{
					for (int i = 0; i < ilen; i++)
					{
						if (i<ipoint)
							fptemp = fptemp + pow(10, ipoint - 1 - i)*(cinput[i] - '0');
						if (i>ipoint)
							fptemp = fptemp + pow(10, ipoint - i)*(cinput[i] - '0');
					}
					bflag = 0;
				}
				else
					printf("输入非法！请重新输入！\n");
			}
			ftemp = 1.0 / 2 + pow(2, 3)*fp[3] * fp[4] * fp[1] * fp[2];
			if ((int)(ftemp * 1000) == (int)((fptemp + 0.0005) * 1000))
				printf("恭喜你！计算正确！\n");
			else
			{
				printf("很遗憾！计算错误！\n");
				printf("正确的可能性偏移量是：%.3f\n", ftemp);
			}
			break;
		}
		case '2': 
		{
			while (bflag)
			{
				int ilen = 0, ipoint = 0;
				printf("请计算该非线性轨迹的逼近概率！(四舍五入，保留三位小数)\n");
				scanf_s("%s", cinput,10);
				getchar();
				while (cinput[ilen] != '\0')
				{
					if ((cinput[ilen] >= '0' && cinput[ilen] <= '9') || cinput[ilen] == '.')
					{
						if (cinput[ilen] == '.')
							ipoint = ilen;
						ilen++;
					}
					else
					{
						ilen = 0;
						break;
					}
				}
				if (ilen > 0)
				{
					for (int i = 0; i < ilen; i++)
					{
						if (i<ipoint)
							fptemp = fptemp + pow(10, ipoint - 1 - i)*(cinput[i] - '0');
						if (i>ipoint)
							fptemp = fptemp + pow(10, ipoint - i)*(cinput[i] - '0');
					}
					bflag = 0;
				}
				else
					printf("输入非法！请重新输入！\n");
			}
			ftemp = 1.0 / 2 + pow(2, 3)*fp[3] * fp[4] * fp[0] * fp[2];
			if ((int)(ftemp * 1000) == (int)((fptemp+0.0005) * 1000))
				printf("恭喜你！计算正确！\n");
			else
			{
				printf("很遗憾！计算错误！\n");
				printf("正确的可能性偏移量是：%.3f\n", ftemp);
			}
			break;
		}
		case '3':
		{
			while (bflag)
			{
				int ilen = 0, ipoint = 0;
				printf("请计算该非线性轨迹的逼近概率！(四舍五入，保留三位小数)\n");
				scanf_s("%s", cinput,10);
				getchar();
				while (cinput[ilen] != '\0')
				{
					if ((cinput[ilen] >= '0' && cinput[ilen] <= '9') || cinput[ilen] == '.')
					{
						if (cinput[ilen] == '.')
							ipoint = ilen;
						ilen++;
					}
					else
					{
						ilen = 0;
						break;
					}
				}
				if (ilen > 0)
				{
					for (int i = 0; i < ilen; i++)
					{
						if (i<ipoint)
							fptemp = fptemp + pow(10, ipoint - 1 - i)*(cinput[i] - '0');
						if (i>ipoint)
							fptemp = fptemp + pow(10, ipoint - i)*(cinput[i] - '0');
					}
					bflag = 0;
				}
				else
					printf("输入非法！请重新输入！\n");
			}
			ftemp = 1.0 / 2 + pow(2, 3)*fp[2] * fp[0] * fp[0] * fp[3];
			if ((int)(ftemp * 1000) == (int)((fptemp + 0.0005) * 1000))
				printf("恭喜你！计算正确！\n");
			else
			{
				printf("很遗憾！计算错误！\n");
				printf("正确的可能性偏移量是：%.3f\n", ftemp);
			}
			break;
		}
		default:printf("输入非法！请重新输入！\n"); break;
		}
	}
	ftemp = 1.0 / 2 + pow(2, 3)*fp[2] * fp[4] * fp[0] * fp[3];
	printf("系统给定非线性轨迹D'CA-A'的逼近概率是%.3f\n",ftemp);
	while (cselect[0] != '0')
	{
		int ilen = 0;
		printf("请选择功能：\n1-   已知明密文对得到成功率\n0-   退出\n");
		scanf_s("%s", &cselect,10);
		getchar();
		while (cselect[ilen] != '\0')
			ilen++;
		if (ilen > 1)
			cselect[0] = 'e';
		switch (cselect[0])
		{
		case '1':
		{
			bflag = 1; icouple = 0;
			printf("请输入明密文对！\n");
			while (bflag)
			{
				int ilen = 0;
				scanf_s("%s", cinput,10);
				getchar();
				while (cinput[ilen] != '\0')
				{
					if (cinput[ilen] >= '0'&&cinput[ilen] <= '9')
						ilen++;
					else
					{
						ilen = 0;
						break;
					}
				}
				if (ilen > 0)
				{
					for (int i = 0; i < ilen; i++)
						icouple = icouple + pow(10, ilen - 1 - i)*(cinput[i] - '0');
					bflag = 0;
				}
				else
					printf("输入非法！请重新输入！\n");
			}
			ftemp = 1.0 / 2 + pow(2, 3)*fp[2] * fp[4] * fp[0] * fp[3];
			fptemp = 2 * sqrt(icouple)*(ftemp - 0.5);
			irank = (int)(fptemp * 10);
			irow = (int)(fptemp * 100 - irank * 10);
			if (irank > 24)
			{
				irank = 24;
				irow = 9;
			}
			printf("\t┏━━━━━┳━━━━┓\n");
			printf("\t┃ 明密文对 ┃%6d  ┃\n",icouple);
			printf("\t┣━━━━━╋━━━━┫\n");
			printf("\t┃  D'CA-A  ┃%6.1f%% ┃\n",fN_table[irank][irow]*100);
			ftemp = 1.0 / 2 + pow(2, 3)*fp[1] * fp[4] * fp[0] * fp[0];
			fptemp = 2 * sqrt(icouple)*(ftemp - 0.5);
			irank = (int)(fptemp * 10);
			irow = (int)(fptemp * 100 - irank * 10);
			if (irank > 24){
				irank = 24;
				irow = 9;
			}
			printf("\t┣━━━━━╋━━━━┫\n");
			printf("\t┃  DCA-A   ┃%6.1f%% ┃\n", fN_table[irank][irow] * 100);
			printf("\t┗━━━━━┻━━━━┛\n");
			break;
		}
		case '0':
		{
			ftemp = 1.0 / 2 + pow(2, 3)*fp[2] * fp[4] * fp[0] * fp[3];
			fptemp = pow((ftemp - 0.5), (-2));
			printf("\t┏━━━━━━━━┳━━━┓\n");
			printf("\t┃成功率\t  ┃100%%  ┃\n");
			printf("\t┣━━━━━━━━╋━━━┫\n");
			printf("\t┃D'CA-A'明密文对 ┃%.0f ┃\n", fptemp);
			ftemp = 1.0 / 2 + pow(2, 3)*fp[1] * fp[4] * fp[0] * fp[0];
			fptemp = pow((ftemp - 0.5), (-2));
			printf("\t┣━━━━━━━━╋━━━┫\n");
			printf("\t┃  DCA-A明密文对 ┃%.0f ┃\n",fptemp);
			printf("\t┗━━━━━━━━┻━━━┛\n");
			break;
		}
		default:printf("输入错误！请重新输入！\n"); break;
		}
	}
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	printf("\t\t**************************************************************************************\n");
	printf("\t\t*                                主菜单                                              *\n");
	printf("\t\t*                                                                                    *\n");
	printf("\t\t*                           1-  5轮DES线性分析                                       *\n");
	printf("\t\t*                           2-  5轮DES非线性分析                                     *\n");
	printf("\t\t*                           0-  退出                                                 *\n");
	printf("\t\t**************************************************************************************\n");
	printf("\t\t\t请选择功能：(0-2)\n");
	
}

void main_menu(){
	char cchoose[10] = { 1 };
	
	printf("\t\t**************************************************************************************\n");
	printf("\t\t*                                主菜单                                              *\n");
	printf("\t\t*                                                                                    *\n");
	printf("\t\t*                           1-  5轮DES线性分析                                       *\n");
	printf("\t\t*                           2-  5轮DES非线性分析                                     *\n");
	printf("\t\t*                           0-  退出                                                 *\n");
	printf("\t\t**************************************************************************************\n");
	printf("\t\t\t请选择功能：(0-2)\n");
	while (cchoose[0] != '0')
	{
		int ilen = 0;
		scanf_s("%s", &cchoose,10);
		getchar();
		while (cchoose[ilen]!='\0')
			ilen++;
		if (ilen > 1)
			cchoose[0] = '3';
		switch (cchoose[0])
		{
		case '1': linear_menu();  break;
		case '2': unlinear_menu();  break;
		case '0':break;
		default:printf("输入错误！请重新输入！\n"); break;
		}
	}
}

int _tmain(int argc, _TCHAR* argv[])
{
	system("mode con cols=145 lines=85  ");
	main_menu();
	return 0;
}

