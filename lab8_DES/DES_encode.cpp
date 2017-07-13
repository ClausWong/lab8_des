#include "StdAfx.h"
#include <stdio.h>
#include<iostream>  
#include<string.h> 
#include "Des_encode.h"


#ifdef _DEBUG

#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


CDes::CDes(void)
{
	m_nRound = 3;
	m_flag = 1;
}
CDes::CDes(int nRound)
{
	if (nRound < 1)
		nRound = 1;
	if (nRound > 16)
		nRound = 16;
	m_nRound = nRound;
	m_flag = 1;
}
CDes::~CDes(void)
{
}
void CDes::Setflag(){
	m_flag = 0;
}
//初始置换
void CDes::IP(bool bDest[64], const bool bSrc[64])
{
	for (int i = 0; i < 64; i++)
	{
		bDest[i] = bSrc[IPTable[i]];
	}
}
void CDes::IPInvert(bool bDest[64], const bool bSrc[64])
{
	for (int i = 0; i < 64; i++)
	{
		bDest[i] = bSrc[IPInvertTable[i]];
	}
}
char* CDes::Inputkey(){
	char *ctempsrc = new char[17];
	bool bflag = 0;
	
	printf("请输入16位16进制的秘钥！\n");
	while (!bflag)
	{
		int ilenth = 0;
		scanf("%s", ctempsrc);
		getchar();
		while (*(ctempsrc + ilenth) != '\0') 
			ilenth++;
		if (ilenth!= 16)
			printf("秘钥长度错误，请重新输入！\n");
		else{
			for (int i = 0; i < 16; i++)
			{
				if (*(ctempsrc + i) >= '0' && *(ctempsrc + i) <= '9' || *(ctempsrc + i) >= 'a'&&*(ctempsrc + i) <= 'f'
					|| *(ctempsrc + i) >= 'A'&&*(ctempsrc + i) <= 'F')
					bflag = 1;
				else {
					printf("秘钥不全是16进制，可能有非法字符，请重新输入！\n");
					bflag = 0;
					break;
				}
			}
		}

	}
	return ctempsrc;
}
void CDes::Randomplaintext(char plaintext[16]){
	int inum = 0;
	for (int i = 0; i < 16; i++)
	{
		inum = rand() % 16;//随机产生16进制的一位整数
		if (inum >= 0 && inum < 10)  //将整数变成字符
			plaintext[i] = (char)(inum + '0');
		else
			plaintext[i] = (char)(inum - 10 + 'a');
	}

}
void CDes::Fk(bool bDest[32], const bool bSrc[32], const bool bKey[48], int bytes)
{
	bool bTmp2[32];
	bool bTmp[48];

	//扩充置换
	Expansion(bTmp, bSrc);
	if (m_flag){

		printf("E(R%d)=        ", bytes);
		for (int i = 0; i < 48; i++)
			printf("%2d", bTmp[i]);
		printf("\n");
		printf("E(R%d) ⊕ K%d=  \n              ", bytes, bytes + 1);
		for (int i = 0; i < 48; i++)
			printf("%2d", bKey[i]);
		printf("\n");
		printf("---------------------------------------------------------------------------------------------------------------\n              ");


	}
	//异或
	Xor(bTmp, bKey, 48);
	if (m_flag){
		for (int i = 0; i < 48; i++)
			printf("%2d", bTmp[i]);
		printf("\n              ");
		//代换/选择(S-Box)
	}
	S_BOX(bTmp2, bTmp);
	if (m_flag){
		printf("-----------------------------------------------------------------------------------------------------------------\n              ");
		printf("                                     P↓                                                         \nf(R%d,K%d)      ", bytes, bytes + 1);

	}
	//P置换
	P(bDest, bTmp2);
	if (m_flag){
		for (int i = 0; i < 32; i++)
			printf("%2d", bDest[i]);
		printf("\nf(R%d,K%d) ⊕ L%d", bytes, bytes + 1, bytes);
	}
}
void CDes::Function(bool bDest[32], bool  bSrc[32], int iround){
	bool bTmp[48],bTmp2[32];
	Expansion(bTmp, bSrc);
	Xor(bTmp, m_SubKey[iround], 48);
	S_BOX(bTmp2, bTmp);
	P(bDest, bTmp2);
}
void CDes::Produce(const bool bKey[56]){
	bool btemp[56] = { 0 };
	for (int i = 0; i < 56; i++)
		btemp[i] = bKey[i];
	for (int i = 0; i < m_nRound; i++)
	{
		RotateL(btemp, i);
		PC2(m_SubKey[i], btemp);
	}
}
bool CDes::limit(int iwheel, bool bbit){
	bool bkey[48] = { 0 };
	bool bxor = 0;
	GetSubKey(bkey, iwheel);
	bxor ^= bkey[1]; bxor ^= bkey[2]; bxor ^= bkey[4]; bxor ^= bkey[5];
	GetSubKey(bkey,1);
	bxor ^= bkey[25];
	GetSubKey(bkey, 3);
	bxor ^= bkey[25];
	return (bxor == bbit);
}
//扩充置换
void CDes::Expansion(bool bDest[48], const bool bSrc[32])
{
	for (int i = 0; i < 48; i++)
	{
		bDest[i] = bSrc[ETable[i]];
	}
}
void CDes::S_BOX(bool bDest[32], bool bSrc[48])
{
	bool *p1 = bSrc;
	bool *p2 = bDest;
	if (m_flag)
		printf("  S1↓        S2↓        S3↓        S4↓        S5↓        S6↓        S7↓        S8↓\n              ");
	//代换/选择(S-Box)
	for (char i = 0, j, k; i < 8; ++i, p1 += 6, p2 += 4)
	{
		j = (p1[0] << 1) + p1[5];
		k = (p1[1] << 3) + (p1[2] << 2) + (p1[3] << 1) + p1[4];
		int temp = SBOXTable[i][j][k];
		p2[0] = temp >> 3 & 1;
		p2[1] = temp >> 2 & 1;
		p2[2] = temp >> 1 & 1;
		p2[3] = temp & 1;
		if (m_flag){
			for (int j = 0; j < 4; j++)
			{
				printf("%2d", p2[j]);
			}
			printf("    ");
		}
	}
	//phetidai
	if (m_flag)
		printf("\n");
}
void CDes::P(bool bDest[32], const bool bSrc[32])
{
	for (int h = 0; h < 32; h++)
	{
		bDest[h] = bSrc[PTable[h]];//这里修改过
	}
}
void CDes::HexToBit(bool *Out,char *In, int bytes){
	int ibit[4];
	int k = 0;
	
	for (int i = 0; i <bytes; i++){
		int ivalue = 0;
		memset(ibit, 0, sizeof(ibit));
		if (*(In + i) >= '0'&&*(In + i) <= '9')
			ivalue=*(In + i) - '0';
		else if (*(In + i) >= 'A'&&*(In + i) <= 'F')
			ivalue = *(In + i) - 'A'+10;
		else
			ivalue = *(In + i) - 'a'+10;
		if (ivalue >= 8) ibit[0] = 1;
		if (ivalue - 8 * ibit[0] >= 4) ibit[1] = 1;
		if (ivalue - 8 * ibit[0] - 4 * ibit[1] >= 2) ibit[2] = 1;
		if (ivalue - 8 * ibit[0] - 4 * ibit[1] - 2 * ibit[2] > 0) ibit[3] = 1;
		for (int j = 0; j <4; j++, k++)
		{
			*(Out + k) = ibit[j];
		}
	}
}
//将2进制转换成16进制  如 1010——>a
void CDes::BitToHex(char *Out, bool *In, int bytes){

	for (int i = 0; i < bytes; i++)
	{
		int ivalue = *(In + i * 4 + 0) * 8 + *(In + i * 4 + 1) * 4 +
			*(In + i * 4 + 2) * 2 + *(In + i * 4 + 3) * 1;
		if (ivalue >= 0 && ivalue < 10)
			*(Out + i) = ivalue + '0';
		else
			*(Out + i) = ivalue - 10 + 'a';
	}
}
bool CDes::Encrypt(bool bCryptograph[64], const bool bPlaintext[64], const bool bKey[64])
{
	bool bTmpCry[64];
	ProduceKey(bKey);
	if (m_flag){
		printf("按Enter键继续\n");
		getchar();
		system("CLS");
		printf("下面我们将演示%d 轮DES 加密过程:\n", m_nRound);
	}
	//IP置换
	//IP(bTmpCry, bPlaintext);
	memcpy(bTmpCry, bPlaintext, 64);
	if (m_flag){
		printf("x0=L0R0       ");
		for (int i = 0; i < 64; i++)
			printf("%2d", bTmpCry[i]);
		printf("\n");
	}
	for (int i = 0; i < m_nRound; i++)
	{
		if (m_flag)
			printf("STEP%2d:   the %d wheel DES:\n", i + 1, i + 1);
		bool bSubKey[48];
		GetSubKey(bSubKey, i);

		bool bL[32], bR[32];
		memcpy(bL, bTmpCry, 32);
		memcpy(bR, bTmpCry + 32, 32);

		//复杂函数
		Fk(bR, bR, bSubKey, i);
		if (m_flag){
			for (int i = 0; i < 32; i++)
				printf("%2d", bL[i]);
			printf("\n              ");
			printf("---------------------------------------------------------------------------------------------------\nR%d=           ", i + 1);
		}
		//Ri = Li-1 XOR Fk(Ri-1,Ki);
		Xor(bR, bL, 32);
		memcpy(bL, bTmpCry + 32, 32);
		if (m_flag){
			for (int i = 0; i < 32; i++)
				printf("%2d", bR[i]);

			printf("\nL%d=R%d         ", i + 1, i);
			for (int i = 0; i < 32; i++)
				printf("%2d", bL[i]);
			printf("\nL%dR%d=         ", i + 1, i + 1);
		}
		memcpy(bTmpCry, bL, 32);
		memcpy(bTmpCry + 32, bR, 32);
		if (m_flag){
			for (int i = 0; i < 64; i++)
				printf("%2d", bTmpCry[i]);
			printf("\n");
		}
	}
	//IP逆
	//IPInvert(bCryptograph, bTmpCry);
	memcpy(bCryptograph, bTmpCry, 64);
	return true;
}
bool CDes::Encryption(bool bCryptograph[64], const bool bPlaintext[64]){
	bool bTmpCry[64];
	//IP置换
	//IP(bTmpCry, bPlaintext);
	memcpy(bTmpCry, bPlaintext, 64);
	for (int i = 0; i < m_nRound; i++)
	{
		bool bSubKey[48];
		GetSubKey(bSubKey, i);

		bool bL[32], bR[32];
		memcpy(bL, bTmpCry, 32);
		memcpy(bR, bTmpCry + 32, 32);

		//复杂函数
		Fk(bR, bR, bSubKey, i);
		Xor(bR, bL, 32);
		memcpy(bL, bTmpCry + 32, 32);
		memcpy(bTmpCry, bL, 32);
		memcpy(bTmpCry + 32, bR, 32);
	}
	//IP逆
	//IPInvert(bCryptograph, bTmpCry);
	memcpy(bCryptograph, bTmpCry, 64);
	return true;

}
void CDes::GetSubKey(bool bSubKey[48], const int nRound)
{
	//ASSERT((nRound >= 0) && (nRound < 16));
	memcpy(bSubKey, m_SubKey[nRound], 48);
}
bool CDes::ProduceKey(const bool bKey[64])
{
	bool bSubKeyTmp[56];
	PC1(bSubKeyTmp, bKey);
	if (m_flag){
		printf("下面将演示%d轮秘钥的生成过程！\n", m_nRound);
		printf("STEP1:   PC-1(K)=C0D0\n              ");
		for (int i = 0; i < 56; i++)
			printf("%2d", bSubKeyTmp[i]);
		printf("\n               ");
		printf("------------------------------------------------------- -------------------------------------------------------\n");
		printf("                                    C0                                                            D0                        \n");
	}
	for (int i = 0; i < m_nRound; i++)
	{
		if (m_flag)
			printf("STEP%d:   the %d wheel:\n", i + 2, i + 1);
		RotateL(bSubKeyTmp, i);
		PC2(m_SubKey[i], bSubKeyTmp);
		if (m_flag){
			printf("K%d=PC-2(C%dD%d)=", i + 1, i + 1, i + 1);
			for (int j = 0; j < 48; j++)
				printf("%2d", m_SubKey[i][j]);
			printf("\n");
		}
	}
	return true;
}

void CDes::PC1(bool bDest[56], const bool bSrc[64])
{
	for (int i = 0; i < 56; i++)
	{
		bDest[i] = bSrc[PC1Table[i]];
	}
}
void CDes::PC2(bool bDest[48], const bool bSrc[56])
{
	for (int i = 0; i < 48; i++)
	{
		bDest[i] = bSrc[PC2Table[i]];
	}
}
//单整数到四位2进制
void CDes::IntToFourBit(bool *Out, int In){
	int ibit[4];
	memset(ibit, 0, sizeof(ibit));
	if (In >= 8) ibit[0] = 1;
	if (In - 8 * ibit[0] >= 4) ibit[1] = 1;
	if (In - 8 * ibit[0] - 4 * ibit[1] >= 2) ibit[2] = 1;
	if (In - 8 * ibit[0] - 4 * ibit[1] - 2 * ibit[2] > 0) ibit[3] = 1;
	for (int j = 0; j < 4; j++)
		*(Out + j) = ibit[3 - j];
}
//单整数到6位2进制
void CDes::IntToSixBit(bool *Out, int In){
	int ibit[6];
	memset(ibit, 0, sizeof(ibit));
	if (In >= 32) ibit[0] = 1;
	if (In - ibit[0] * 32 >= 16) ibit[1] = 1;
	if (In - ibit[0] * 32 - ibit[1] * 16 >= 8) ibit[2] = 1;
	if (In - ibit[0] * 32 - ibit[1] * 16 - ibit[2] * 8 >= 4) ibit[3] = 1;
	if (In - ibit[0] * 32 - ibit[1] * 16 - ibit[2] * 8 - ibit[3] * 4 >= 2) ibit[4] = 1;
	if (In - ibit[0] * 32 - ibit[1] * 16 - ibit[2] * 8 - ibit[3] * 4 - ibit[4] * 2 > 0) ibit[5] = 1;
	for (int j = 0; j <6; j++)
		*(Out + j) = ibit[5 - j];
}
void CDes::IntToBit(bool *Out, unsigned int In, int inum){
	int i = 0;
	while (In!=0)
	{
		*(Out + i) = In % 2;
		In /= 2;
		i++;
	}
	while (i<inum)
	{
		*(Out + i) = 0;
		i++;
	}

}
void CDes::RotateL(bool *In, int i)
{

	bool* temp = new bool[57];
	if (m_flag)
		printf("C%d=C%d<<<%d\n", i + 1, i, I_ShiftTable[i]);
	//保存将要循环移动到右边的位
	memcpy(temp, In, I_ShiftTable[i]);
	memcpy(temp + I_ShiftTable[i], In + 28, I_ShiftTable[i]);

	//前28位移动
	memcpy(In, In + I_ShiftTable[i], 28 - I_ShiftTable[i]);
	memcpy(In + 28 - I_ShiftTable[i], temp, I_ShiftTable[i]);
	if (m_flag)
		printf("D%d=D%d<<<%d\n", i + 1, i, I_ShiftTable[i]);
	//后28位移动
	memcpy(In + 28, In + 28 + I_ShiftTable[i], 28 - I_ShiftTable[i]);
	memcpy(In + 56 - I_ShiftTable[i], temp + I_ShiftTable[i], I_ShiftTable[i]);
	delete temp;
}

void CDes::Xor(bool *pbDest, const bool *pbSrc, int len)
{
	for (int i = 0; i < len; ++i)
		pbDest[i] ^= pbSrc[i];
}

void CDes::Sbox_distribution(int(*itable)[15], int isbox){
	for (int i = 1; i < 64; i++)
	{
		bool brank[6] = { 0 };
		IntToSixBit(brank, i);
		for (int j = 1; j < 16; j++)
		{
			bool brow[4] = { 0 };
			IntToFourBit(brow, j);
			for (int k = 0; k < 64; k++)
			{
				bool binput[6] = { 0 };
				bool boutput[4] = { 0 };
				IntToSixBit(binput, k);
				int irank = binput[5] * 2 + binput[0] * 1;
				int irow = binput[4] * 8 + binput[3] * 4 + binput[2] * 2 + binput[1] * 1;
				int iout = SBOXTable[isbox][irank][irow];
				IntToFourBit(boutput, iout);
				bool bleft = 0, bright = 0;
				for (int m = 0; m < 6; m++)
					bleft ^= (brank[m] * binput[m]);
				for (int m = 0; m < 4; m++)
					bright ^= (brow[m] * boutput[m]);
				if (bleft == bright) itable[i - 1][j - 1]++;

				if (isbox == 0 && i == 27 && j == 4 && k < 3)
				{
					printf("\n例如当NS%d=（%d，%d）时,", isbox + 1, i, j);
					printf("输入端α=%d=%2d%2d%2d%2d%2d%2d    输出端β=%d=%2d%2d%2d%2d\n", i, brank[5], brank[4], brank[3], brank[2], brank[1], brank[0], j, brow[3], brow[2], brow[1], brow[0]);
					printf("\n当s%d盒的输入x=%d，转换成2进制即：x5 x4 x3 x2 x1 x0=%2d%2d%2d%2d%2d%2d,", isbox + 1, k, binput[5], binput[4], binput[3], binput[2], binput[1], binput[0]);
					printf("\n对照S%d盒的表查的S[%d][%d]=%d,转换成2进制即：S(x)3S(x)2S(x)1S(x)0=%2d%2d%2d%2d\n", isbox + 1, irank, irow, iout, boutput[3], boutput[2], boutput[1], boutput[0]);
					printf("\n判断%2d &%2d ⊕%2d &%2d ⊕%2d &%2d ⊕%2d &%2d ⊕%2d &%2d ⊕%2d &%2d是否等于", binput[5], brank[5], binput[4], brank[4], binput[3], brank[3], binput[2], brank[2], binput[1], brank[1], binput[0], brank[0]);
					printf("%2d &%2d ⊕%2d &%2d ⊕%2d &%2d ⊕%2d &%2d \n", boutput[3], brow[3], boutput[2], brow[2], boutput[1], brow[1], boutput[0], brow[0]);
					printf("\n若相等，则x=%2d为有效输入,将NS%d=（%d，%d）的值+1\n", k, isbox + 1, i, j);
				}
				if (isbox == 4 && i == 16 && j == 15 && k < 3)
				{
					printf("\n例如当NS%d=（%d，%d）时,", isbox + 1, i, j);
					printf("输入端α=%d=%2d%2d%2d%2d%2d%2d    输出端β=%d=%2d%2d%2d%2d\n", i, brank[5], brank[4], brank[3], brank[2], brank[1], brank[0], j, boutput[3], boutput[2], boutput[1], boutput[0]);
					printf("\n当s%d盒的输入x=%d，转换成2进制即：x5 x4 x3 x2 x1 x0=%2d%2d%2d%2d%2d%2d,", isbox + 1, k, binput[5], binput[4], binput[3], binput[2], binput[1], binput[0]);
					printf("\n对照S%d盒的表查的S[%d][%d]=%d,转换成2进制即：S(x)3S(x)2S(x)1S(x)0=%2d%2d%2d%2d\n", isbox + 1, irank, irow, iout, boutput[3], boutput[2], boutput[1], boutput[0]);
					printf("\n判断%2d &%2d ⊕%2d &%2d ⊕%2d &%2d ⊕%2d &%2d ⊕%2d &%2d ⊕%2d &%2d是否等于", binput[5], brank[5], binput[4], brank[4], binput[3], brank[3], binput[2], brank[2], binput[1], brank[1], binput[0], brank[0]);
					printf("%2d &%2d ⊕%2d &%2d ⊕%2d &%2d ⊕%2d &%2d \n", boutput[3], brow[3], boutput[2], brow[2], boutput[1], brow[1], boutput[0], brow[0]);
					printf("\n若相等，则x=%2d为有效输入,将NS%d=（%d，%d）的值+1\n", k, isbox + 1, i, j);
				}
				if (i == 29 && j*k == 7 * 62){
					char cchoose[10] = { 1 };
					printf("\n请判断对于NS%d(%d,%d)当输入x=%d时，是否满足如下等式(y or n )\n", isbox + 1, i, j, k);
					printf("x[0]&α[0]⊕x[1]&α[1]⊕x[2]&α[2]⊕x[3]&α[3]⊕x[4]&α[4]⊕x[5]&α[5]=S(x)[0]&β[0]⊕S(x)[1]&β[1]⊕S(x)[2]&β[2]⊕S(x)[3]&β[3]\n");
					while (cchoose[0] != 'y' && cchoose[0] != 'Y' &&  cchoose[0] != 'n' && cchoose[0] != 'N')
					{
						int ilen = 0;
						scanf("%s", &cchoose);
						getchar();
						while (cchoose[ilen] != '\0')
							ilen++;
						if (ilen > 1)
							cchoose[0] = '3';
						switch (cchoose[0])
						{
						case 'y':
						case 'Y':
						{
							if (bleft == bright)
								printf("回答正确！\n");
							else
								printf("回答错误！\n");
							break;
						}
						case 'n':
						case 'N':
						{
							if (bleft != bright)
								printf("回答正确！\n");
							else
								printf("回答错误！\n");
							break;
						}
						default:printf("输入错误！请重新输入！\n"); break;
						}
					}
				}
			}
		}
	}
	printf("按Enter键继续\n");
	getchar();
	system("CLS");
	printf("\n对于s%d盒每个输入端α和每个输出端β，遍历输入值x∈[0,63],便可以得到\n", isbox + 1);
	printf("\t\t\t\t\tS%d盒的线性分布表\n", isbox + 1);
	printf("\t        1   2   3   4   5   6   7   8   9   10  11  12  13  14  15\n");
	printf("\t━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
	for (int i = 0; i < 63; i++)
	{
		if (i <= 8)
			printf("\t%d  ┃ ", i + 1);
		else
			printf("\t%d ┃ ", i + 1);
		for (int j = 0; j < 15; j++)
			printf("%4d", itable[i][j] - 32);
		printf(" ┃\n");
	}
	printf("\t━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}
//分析s盒的分布表
void CDes::Approximation(int *iX, int *iK, int *iF, int isbox, int irank, int irow, int iwheel, int *iin, int *iout){
	bool brank[6] = { 0 };
	bool brow[4] = { 0 };
	int itemp[4] = { 0 };
	IntToSixBit(brank, irank);
	IntToFourBit(brow, irow);
	printf("当我们把轮函数NS%d=(%d,%d)应用到第%d轮时：\n", isbox + 1, irank, irow, iwheel + 1);
	printf("\t\t\t┏━━━━━━━━━━━━━━┓\n");
	printf("\t\t\t┃            S%d              ┃\n", isbox + 1);
	printf("\t\t\t┗━━━━━━━━━━━━━━┛\n");
	printf("\t\t\t  ↑   ↑   ↑   ↑   ↑   ↑\n");
	printf("\t\t\tx5=%d x4=%d x3=%d x2=%d x1=%d x0=%d", brank[5], brank[4], brank[3], brank[2], brank[1], brank[0]);
	printf("\t从右到左S%d盒前面还有%d个盒子%d位，把他们考虑进来，所以S%d盒的第", isbox + 1, isbox, isbox * 6, isbox + 1);
	for (int i = 5; i >= 0; i--)
		if (brank[i] == 1){
		printf("%2d ", i);
		iK[(*(iin + iwheel))++] = isbox * 6 + 5 - i;
		}
	printf("位是\n\t\t\t  ↑   ↑   ↑   ↑   ↑   ↑\n");
	printf("\t\t\tE(X)[");
	for (int i = (*(iin + iwheel)) - 1; i >0; i--)
		printf("%2d,", 47 - iK[i]);
	printf("%2d]⊕K[", 47 - iK[0]);
	for (int i = (*(iin + iwheel)) - 1; i >0; i--)
		printf("%2d,", 47 - iK[i]);

	printf("%2d]\n\t\t\t↑考虑上E（扩展函数）\n", 47 - iK[0]);
	for (int i = (*(iin + iwheel)) - 1; i >= 0; i--)
		iX[i] = ETable[iK[i]];
	printf("\t\t\tX[");
	for (int i = (*(iin + iwheel)) - 1; i >0; i--)
		printf("%2d,", 31 - iX[i]);
	printf("%2d]\n\n", 31 - iX[0]);

	printf("\t\t\t┏━━━━━━━━━━━━━━┓\n");
	printf("\t\t\t┃            S%d              ┃\n", isbox + 1);
	printf("\t\t\t┗━━━━━━━━━━━━━━┛\n");
	printf("\t\t\t      ↓   ↓   ↓   ↓    \n");
	printf("\t\t\t    y3=%d  y2=%d  y1=%d  y0=%d", brow[3], brow[2], brow[1], brow[0]);
	printf("\t从右到左S%d盒前面还有%d个盒子%d位，把他们考虑进来，所以S%d盒的第", isbox + 1, isbox, isbox * 4, isbox + 1);
	for (int i = 3; i >= 0; i--)
		if (brow[i] == 1){
		printf("%2d ", i);
		iF[(*(iout + iwheel))++] = isbox * 4 + 3 - i;
		}
	printf("位是\n\t\t\t     ↓   ↓   ↓   ↓\n");
	printf("\t\t\t    C[");
	for (int i = *(iout + iwheel) - 1; i >0; i--)
		printf("%2d,", 32 - iF[i]);
	printf("%2d]\n\t\t\t    ↓考虑上P（置换函数）\n", 32 - iF[0]);
	for (int i = 0; i<*(iout + iwheel); i++){
		for (int k = 0; k < 32; k++){
			if (iF[i] == PTable[k])
				itemp[i] = k;
		}
	}
	for (int i = 0; i < *(iout + iwheel); i++)
		iF[i] = itemp[i];
	printf("\t\t\t    F(X,K)[");
	for (int i = *(iout + iwheel) - 1; i >0; i--)
		printf("%2d,", 31 - iF[i]);
	printf("%2d]\n\n", 31 - iF[0]);
	if (iwheel == 0){
		printf("可得第%2d轮的关系式：\n\tPH[", iwheel + 1);
		for (int i = (*(iout + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iF[i]);
		printf("%2d]⊕X2[", 31 - iF[0]);
		for (int i = (*(iout + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iF[i]);
		printf("%2d]⊕PL[", 31 - iF[0]);
		for (int i = (*(iin + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iX[i]);
		printf("%2d]=K1[", 31 - iX[0]);
		for (int i = (*(iin + iwheel)) - 1; i >0; i--)
			printf("%2d,", 47 - iK[i]);
		printf("%2d]\n", 47 - iK[0]);
	}
	if (iwheel == 4){
		printf("可得第%2d轮的关系式：\n\tX4[", iwheel + 1);
		for (int i = (*(iout + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iF[i]);
		printf("%2d]⊕CH[", 31 - iF[0]);
		for (int i = (*(iout + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iF[i]);
		printf("%2d]⊕CL[", 31 - iF[0]);
		for (int i = (*(iin + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iX[i]);
		printf("%2d]=K5[", 31 - iX[0]);
		for (int i = (*(iin + iwheel)) - 1; i >0; i--)
			printf("%2d,", 47 - iK[i]);
		printf("%2d]\n", 47 - iK[0]);
	}
	if (iwheel == 1){
		printf("可得第%2d轮的关系式：\n\tPL[", iwheel + 1);
		for (int i = (*(iout + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iF[i]);
		printf("%2d]⊕X3[", 31 - iF[0]);
		for (int i = (*(iout + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iF[i]);
		printf("%2d]⊕X2[", 31 - iF[0]);
		for (int i = (*(iin + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iX[i]);
		printf("%2d]=K2[", 31 - iX[0]);
		for (int i = (*(iin + iwheel)) - 1; i >0; i--)
			printf("%2d,", 47 - iK[i]);
		printf("%2d]\n", 47 - iK[0]);
	}

	if (iwheel == 3){
		printf("可得第%2d轮的关系式：\n\tX3[", iwheel + 1);
		for (int i = (*(iout + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iF[i]);
		printf("%2d]⊕CL[", 31 - iF[0]);
		for (int i = (*(iout + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iF[i]);
		printf("%2d]⊕X4[", 31 - iF[0]);
		for (int i = (*(iin + iwheel)) - 1; i >0; i--)
			printf("%2d,", 31 - iX[i]);
		printf("%2d]=K4[", 31 - iX[0]);
		for (int i = (*(iin + iwheel)) - 1; i >0; i--)
			printf("%2d,", 47 - iK[i]);
		printf("%2d]\n", 47 - iK[0]);
	}

}

void CDes::Key(bool bDest[64],bool bSrc[56]){
	int icount = 0;
	for (int i = 0; i < 56; i++)
		bDest[PC1Table[i]] = bSrc[i];
	for (int i = 0; i < 64; i++)
	{
		if (i == 7 || i == 15 || i == 23 || i == 31 || i == 39 || i == 47 || i == 55 || i == 63)
		{
			bDest[i] =1- icount % 2;
			icount = 0;
		}
		else
		{
			if (bDest[i] == 1)
				icount++;
		}
	}
}
void CDes::Keyscope(bool *pbDest,char *In){
	bool btemp[56] = { 0 };
	bool bkey[64] = { 0 };
	bool ibit[4] = { 0 };
	HexToBit(bkey,In,16);
	PC1(btemp, bkey);
	for (int i = 0; i < 28; i++)
		*(pbDest + i) = btemp[28+i];
}

