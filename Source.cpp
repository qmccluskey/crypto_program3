//Quinn McCluskey
//qmccluskey@live.esu.edu
//CPSC 370, 12:30
//10/30/19
//S-DES encryption and decryption with CBC and then the 14th bit is corrupted and therefore changed

#include <iostream>
#include <string>
#include <stdio.h>

using namespace std;

string SDESEncryption(string, string, int);
string SDESDecryption(string, string, int);
string findKey(string, int);
string functionF(string, string);
string XOR(string, string);
string S1Box(string);
string S2Box(string);

//The added parts to SDES
string CBCencrypt(string, string, string, int);
string CBCdecrypt(string, string, string, int);

string CBCencrypt(string key, string plaintext, string IV, int rounds)
{
	string ct1, ct2, ct3, ct4;

	ct1.append(plaintext, 0, 12);
	ct2.append(plaintext, 12, 12);
	ct3.append(plaintext, 24, 12);
	ct4.append(plaintext, 36, 12);

	ct1 = XOR(ct1, IV);

	for (int i = 1; i <= rounds; i++)
	{
		ct1 = SDESEncryption(key, ct1, i);
	}

	ct2 = XOR(ct2, ct1);

	for (int i = 1; i <= rounds; i++)
	{
		ct2 = SDESEncryption(key, ct2, i);
	}

	ct3 = XOR(ct3, ct2);

	for (int i = 1; i <= rounds; i++)
	{
		ct3 = SDESEncryption(key, ct3, i);
	}

	ct4 = XOR(ct4, ct3);

	for (int i = 1; i <= rounds; i++)
	{
		ct4 = SDESEncryption(key, ct4, i);
	}

	return (ct1 + ct2 + ct3 + ct4);
}

string CBCdecrypt(string key, string ciphertext, string IV, int rounds)
{
	string pt1, pt2, pt3, pt4;

	pt1.append(ciphertext, 0, 12);
	pt2.append(ciphertext, 12, 12);
	pt3.append(ciphertext, 24, 12);
	pt4.append(ciphertext, 36, 12);

	for (int i = rounds; i > 0; i--)
	{
		pt4 = SDESDecryption(key, pt4, i);
	}

	pt4 = XOR(pt3, pt4);

	for (int i = rounds; i > 0; i--)
	{
		pt3 = SDESDecryption(key, pt3, i);
	}

	pt3 = XOR(pt2, pt3);

	for (int i = rounds; i > 0; i--)
	{
		pt2 = SDESDecryption(key, pt2, i);
	}

	pt2 = XOR(pt1, pt2);

	for (int i = rounds; i > 0; i--)
	{
		pt1 = SDESDecryption(key, pt1, i);
	}

	pt1 = XOR(IV, pt1);

	return (pt1 + pt2 + pt3 + pt4);
}

//All of this was kept the same from the previous program
string SDESEncryption(string key, string plaintext, int round)
{
	string Li;
	string Ri;
	string Ln;
	string Rn;
	string K;
	string f;

	K = findKey(key, round);

	Li.append(plaintext, 0, 6);
	Ri.append(plaintext, 6, 6);

	Ln = Ri;

	f.append(functionF(Ri, K));

	Rn.append(f);
	Rn = XOR(Li, f);

	return (Ln + Rn);
}

string SDESDecryption(string key, string ciphertext, int round)
{
	string Li;
	string Ri;
	string Ln;
	string Rn;
	string K;
	string f;

	K = findKey(key, round);

	Li.append(ciphertext, 0, 6);
	Ri.append(ciphertext, 6, 6);

	Rn = Li;

	f.append(functionF(Rn, K));

	Ln.append(f);
	Ln = XOR(Ri, f);

	return (Ln + Rn);
}

string findKey(string key, int round)
{
	string K;

	if (round == 1)
	{
		K.append(key, 0, 8);
	}
	else if (round == 2)
	{
		K.append(key, 1, 8);
	}
	else if (round == 3)
	{
		K.append(key, 2, 7);
		K.append(key, 0, 1);
	}
	else if (round == 4)
	{
		K.append(key, 3, 6);
		K.append(key, 0, 2);
	}
	return K;
}

string functionF(string R, string K)
{
	char tmp;
	string s1;
	string s2;

	R.append(R, 4, 2);
	tmp = R[3];
	R[5] = R[2];
	R[4] = tmp;
	R[3] = R[2];
	R[2] = tmp;

	R = XOR(R, K);
	s1.append(R, 0, 4);
	s2.append(R, 4, 4);

	return S1Box(s1) + S2Box(s2);
}

string XOR(string x, string y)
{
	for (int i = 0; i < x.length(); i++)
	{
		if (x[i] == y[i])
		{
			x[i] = '0';
		}
		else if (x[i] != y[i])
		{
			x[i] = '1';
		}
	}

	return x;
}

string S1Box(string s1)
{
	string row1[8] = { "101", "010", "001", "110", "011", "100", "111", "000" };
	string row2[8] = { "001", "100", "110", "010", "000", "111", "101", "011" };

	int column = 0;

	if (s1[0] == '0')
	{
		if (s1[1] == '1')
		{
			column += 4;
		}
		if (s1[2] == '1')
		{
			column += 2;
		}
		if (s1[3] == '1')
		{
			column += 1;
		}

		return row1[column];
	}
	else if (s1[0] == '1')
	{
		if (s1[1] == '1')
		{
			column += 4;
		}
		if (s1[2] == '1')
		{
			column += 2;
		}
		if (s1[3] == '1')
		{
			column += 1;
		}

		return row2[column];
	}
	else
	{
		return "ERROR";
	}
}

string S2Box(string s2)
{
	string row1[8] = { "100", "000", "110", "101", "111", "001", "011", "010" };
	string row2[8] = { "101", "011", "000", "111", "110", "010", "001", "100" };

	int column = 0;

	if (s2[0] == '0')
	{
		if (s2[1] == '1')
		{
			column += 4;
		}
		if (s2[2] == '1')
		{
			column += 2;
		}
		if (s2[3] == '1')
		{
			column += 1;
		}

		return row1[column];
	}
	else if (s2[0] == '1')
	{
		if (s2[1] == '1')
		{
			column += 4;
		}
		if (s2[2] == '1')
		{
			column += 2;
		}
		if (s2[3] == '1')
		{
			column += 1;
		}

		return row2[column];
	}
	else
	{
		return "ERROR";
	}
}

int main()
{
	string plaintext = "011100100110101010001001110101110011111000001010";
	string plaintext2 = "011100100110111010001001110101110011111000001010";
	string key = "010011001";
	string IV = "010111101000";

	string ciphertext;
	string ciphertext2;
	string decryption;
	string decryption2;
	int numrounds = 4;

	cout << "S_DES using CBC" << endl << endl;
	cout << "Plaintext: " << plaintext << endl <<"Plaintext2: " << plaintext2 << endl
		<< "Key: " << key << endl << "IV: " << IV << endl << endl;

	//Item 1 starts here
	cout << "Item #1" << endl << endl;

	cout << "Encryption with CBC: " << endl;
	ciphertext = CBCencrypt(key, plaintext, IV, 4);

	cout << "Ciphertext: " << ciphertext << endl << endl;
	cout << "Decryption with CBC: " << endl;
	decryption = CBCdecrypt(key, ciphertext, IV, 4);

	cout << "Plaintext: " << decryption << endl << endl;

	//Item 2 starts
	cout << "Item #2: using plaintext2" << endl << endl;

	cout << "Encryption with CBC: " << endl;
	ciphertext2 = CBCencrypt(key, plaintext2, IV, 4);

	cout << "Ciphertext2: " << ciphertext2 << endl << endl;
	cout << "Decryption with CBC: " << endl;
	decryption2 = CBCdecrypt(key, ciphertext2, IV, 4);
	cout << "Plaintext2: " << decryption2 << endl << endl;

	//print off of my findings when comparing ciphertext1 and 2
	cout << "Since cipher text 1 is " << ciphertext << endl << " and cipher text 2 is " << ciphertext2
		<< endl << " you can see that they are the same up to the 14th bit," << endl << " and then after they become completely different." << endl 
		<< "So if the 14th bit of plaintext was corrupted, the rest of the cipher text after the 14th bit would be messed up." << endl;

	system("pause");

	return 0;
}