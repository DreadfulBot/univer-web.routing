#include <iostream>
#include <string>
#include <sstream>
#include <exception>
#include <locale.h>	
#include <stdint.h>
#include <cmath>
//#include <windows.h>

struct FourOctets {
	bool isValid;
	int octets[ 4 ];
};

class UserException {
public:
	UserException() {
		
	}
};

//��������� �������� ������ �� �������
FourOctets GetOctets( const std::string & textLine ) {
	// ������������ �������� ������
	std::string testLine( textLine );

	// ������� ��������� ������� 
	FourOctets answer;
	answer.isValid = false;
	for(int i=0; i<4; i++) {
		answer.octets[i] = -1;
	}

	// ���� ��������� ������ - �������
	for (int i=0; i < testLine.length(); i++) {
		if (isalpha((unsigned char)testLine[i])) {
				return answer;
		}
	}

	// ��������� �� ������
	size_t foundOffset = 0;
	size_t numberOfDots = 0;
	while ( ( foundOffset = testLine.find( '.' ) ) != std::string::npos ) { 
		testLine.replace( foundOffset, 1, 1, ' ' );
		numberOfDots++;
	}

	// ��������� �� �������
	if( numberOfDots == 3 ) {
		std::stringstream ss( testLine );
		ss.exceptions( std::ios::failbit | std::ios::badbit );
		int *octets = answer.octets;
		try {
			ss >> octets[ 0 ] >> octets[ 1 ] >> octets[ 2 ] >> octets[ 3 ];
			for(int i=0; i<4; i++) {
				if(octets[i] > 255 || octets[i] < 0) {
					throw UserException();
				}
			}
			answer.isValid = true;
		} catch (...) {
			answer.isValid = false;
		}
	}
	return answer;
}

// ��������� ip-a���� �� ������� ������
FourOctets GetIpAddress(std::string ip) {
	FourOctets ipAddress = GetOctets(ip);
	return ipAddress;
}

// ��������� ����� �� ������� ������
FourOctets GetMask(std::string mask) {
	int posValues[] = {0, 128, 192, 224, 240, 248, 252, 254, 255};
	int posValuesCounter = 9;
	bool flag = false;
	int counter = 0;

	// ������� �����
	FourOctets ipMask = GetOctets(mask);
	if(ipMask.isValid = false) {
		return ipMask;
	}

	// ������ ����� ����� - ������� => ��� ����� �������
	if(ipMask.octets[0] == 0) {
		if(ipMask.octets[1] !=0 || ipMask.octets[2] !=0 || ipMask.octets[3] !=0) {
			ipMask.isValid = false;
			return ipMask;
		}
	}

	// ���������, ��� ������ ����� ����� ��������� ��������� ��������
	for(int i=0; i<4; i++) {
		for (int j=0; j<posValuesCounter; j++) {
			if (ipMask.octets[i] == posValues[j]) {
				counter++;
				break;
			}
		}
	}
	if (counter == 4) {
			ipMask.isValid = true;
	} else {
			ipMask.isValid = false;
			return ipMask;
	}
	counter = 0;

	try {
		for (int i=0; i<3; i++) {

			// ������ ����������� �� ������ �����������
			if(ipMask.octets[i+1] > ipMask.octets[i]) {
				throw UserException();
			}

			// ���� ���� ����������� �����, �� ���������� - 255
			if(ipMask.octets[i+1] != 0){
				if(ipMask.octets[i] != 255){
					throw UserException();
				}
			}

			// ���� ��� ����� ������
			ipMask.isValid = true;

		}
	} catch (...) {
		ipMask.isValid = false;
	}
	return ipMask;
}

// �������� �������� �����
FourOctets GetHostPart(FourOctets& address, FourOctets& mask) {
	FourOctets hostPart;
	for(int i=0; i<4; i++) {
		hostPart.octets[i] = address.octets[i] & (255 - mask.octets[i]);
	}
	return hostPart;
}

// �������� ������� �����
FourOctets GetWebPart(FourOctets& address, FourOctets& mask) {
	FourOctets webPart;
	for(int i=0; i<4; i++) {
		webPart.octets[i] = address.octets[i] & mask.octets[i];
	}
	return webPart;
}

// �������� �������� �������. ��� ������� - true, ���� �� ���� �������� - false
bool OctetsAreEqual(FourOctets in1, FourOctets in2) {
	int counter = 0;
	for(int i=0; i<4; i++) {
		if(in1.octets[i] == in2.octets[i]) {
			counter++;
		}
	}
	if(counter == 4) 
		return true;
	else return false;
}

// �������� ���� �� ���������
FourOctets GetDefaultGateway(FourOctets ipAddress, FourOctets ipMask) {
	FourOctets dg;
	int counter = -1;

	// �������� � ������� ������
	dg = GetWebPart(ipAddress, ipMask);

	// ��������� ��������� �����, �� ������ 255 (� �������� ����� ��������� 1)
	for(int i=3; i>=0; i--) {
		if(dg.octets[i] < 255) {
			counter = i;
			break;
		}
	}

	// ���� ����� ����� ����������, �� ����������� ��� �� 1
	// � ��� ����������� ������ �������� (������� �������)
	if(counter > 0) {
		dg.isValid = true;
		dg.octets[counter] += 1;
		if(counter < 3) {
			for(int i=counter+1; i<4; i++) {
				dg.octets[i] = 0;
			}
		}
	} else {
		dg.isValid = false;
	}

	return dg;
}

// �������� ����������������� �����
FourOctets GetBroadcastIp(FourOctets ipAddress, FourOctets ipMask) {
	FourOctets bcIp;
	for (int i=0; i<4; i++) {
		bcIp.octets[i] = ipAddress.octets[i] | (255 - ipMask.octets[i]);
	}
	return bcIp;
}

// ���������� ���������� ������ � �������
int CountNumberOfHosts(FourOctets address, FourOctets mask) {
	int noh = 0;
	FourOctets broadcast = GetBroadcastIp(address, mask);
	FourOctets web = GetWebPart(address, mask);
	for(int i=0; i<4; i++) {
		noh += broadcast.octets[i] - web.octets[i];
	}
	return noh;
}

// ��������� ������������� ���� �� ����� � ������
void ValidateWeb(FourOctets& address, FourOctets& mask) {
	try {
		
		// ���� ������� ����
		if(CountNumberOfHosts(address, mask) <= 2) {
			throw UserException();
		}

		// ip != ������������������
		FourOctets tempBcIp = GetBroadcastIp(address, mask);
		if(OctetsAreEqual(address, tempBcIp)) {
			throw UserException();
		}

		// ip ����� != ������� �����
		FourOctets webPart = GetWebPart(address, mask);
		if(OctetsAreEqual(address, webPart)) {
			throw UserException();
		}

		// ���� ��� ����� ������
		mask.isValid = true;
		address.isValid = true;

	} catch (...) {
		mask.isValid = false;
		address.isValid = false;
	}
	return;
}

// ��������� ����� �� �� �������
FourOctets GetMaskBySize(std::string size_str) {
	FourOctets mask;
	int size = 0;

	// ����������� ����� � �����
	std::stringstream ss(size_str);
	try {
		ss >> size;
	} catch(...) {
		mask.isValid = false;
		return mask;
	}

	// ��������� �� �����
	if(size > 32) {
		mask.isValid = false;
		return mask;
	}

	mask.isValid = false;
	for(int i=0; i<4; i++) {
		mask.octets[i] = 0;
	}
	
	// ��������� �����
	for(int i=0; i<size; i++) {
		if(i<=7) {
			mask.octets[0]+=(int)pow(2, 7-i);
		} else if(i>=8 && i<=15) {
			mask.octets[1]+=(int)pow(2, 15-i);
		} else if(i>=16 && i<=23) {
			mask.octets[2]+=(int)pow(2, 23-i);
		} else if(i>=24 && i<=31){
			mask.octets[3]+=(int)pow(2, 31-i);
		}
	}
	mask.isValid = true;
	return mask;
}

// ip-�����[������]�����
bool SplitStrIpMask(std::string src, FourOctets& ipAddress, FourOctets& ipMask) {

	// ������� ������� �� ������� ������
	size_t targetSpaceOffset = 0;
	size_t curSpaceOffset = 0;
	size_t numOfSpaces = 0;

	while ( (curSpaceOffset = src.find( ' ' )) != std::string::npos ) {
			if (curSpaceOffset != std::string::npos) {
				targetSpaceOffset = curSpaceOffset;
			}
			src.replace(curSpaceOffset, 1, 1, '_');
			numOfSpaces++;
	}

	// ��������� �� ���-�� ��������
	if (numOfSpaces != 1) {
			ipAddress.isValid = false;
			ipMask.isValid = false;
			return false;
	} else {
		// ��������� ip-�����
		ipAddress = GetIpAddress(src.substr(0, targetSpaceOffset));

		// ��������� �����
		if(ipAddress.isValid = true) {
			ipMask = GetMask(src.substr(targetSpaceOffset+=1, src.length()));
		} else {
			return false;
		}

		// ��������� ���� �� ����� � ������
		if(ipAddress.isValid && ipMask.isValid) {
			ValidateWeb(ipAddress, ipMask);
		}
		return ipAddress.isValid && ipMask.isValid;
	}
}

// ip-�����[/]�����[������]ip-�����
bool SplitStrIpMaskIp(std::string src, FourOctets& ipAddress1,FourOctets& ipAddress2, FourOctets& ipMask) {

	// ������� ������� �� ������� ������
	size_t targetSpaceOffset = 0;
	size_t targetSlashOffset = 0;
	size_t curSlashOffset = 0;
	size_t curSpaceOffset = 0;
	size_t numOfSpaces = 0;
	size_t numOfSlashes = 0;

	while ( (curSpaceOffset = src.find( ' ' )) != std::string::npos ) {
			if (curSpaceOffset != std::string::npos) {
				targetSpaceOffset = curSpaceOffset;
			}
			src.replace(curSpaceOffset, 1, 1, '_');
			numOfSpaces++;
	}

	// ��������� �� ���-�� ��������
	if (numOfSpaces != 1) {
			ipAddress1.isValid = false;
			ipMask.isValid = false;
			return false;
	} else {
		
		// ��������� ip-����� 1
		while( (curSlashOffset = src.substr(0, targetSpaceOffset).find( '/' )) != std::string::npos) {
			if(curSlashOffset != std::string::npos) {
				targetSlashOffset = curSlashOffset;
			}
			src.replace(curSlashOffset, 1, 1, '_');
			numOfSlashes++;
		}

		if(numOfSlashes != 1) {
			ipAddress1.isValid = false;
			ipMask.isValid = false;
			return false;
		}

		ipAddress1 = GetIpAddress(src.substr(0, targetSlashOffset));

		// ��������� �����
		if(ipAddress1.isValid = true) {
			ipMask = GetMaskBySize(src.substr(targetSlashOffset+=1, targetSpaceOffset));
		} else {
			return false;
		}

		// ��������� ���� �� ����� � ������ 1
		if(ipAddress1.isValid && ipMask.isValid) {
			ValidateWeb(ipAddress1, ipMask);
		}

		// ��������� ip-����� 2
		if(ipAddress1.isValid && ipMask.isValid) {
			ipAddress2 = GetOctets(src.substr(targetSpaceOffset+=1, src.length()));
		} else {
			return false;
		}

		// ��������� ���� �� ����� � ������ 2
		if(ipAddress2.isValid) {
			ValidateWeb(ipAddress2, ipMask);
		}

		return ipAddress1.isValid && ipAddress2.isValid && ipMask.isValid;
	}
}

//����������, ����� �� ������������� ����� ��������
bool IsNeedRouting(FourOctets ipAddress1, FourOctets ipAddress2, FourOctets ipMask) {
	FourOctets wp1 = GetWebPart(ipAddress1, ipMask);
	FourOctets wp2 = GetWebPart(ipAddress2, ipMask);
	if(OctetsAreEqual(wp1, wp2)) {
		return false;
	} else
		return true;
}

// ������� ������ ip-������ ����� �����
void PrintAddress(FourOctets address) {
	for (int i=0; i<4; i++) {
		std::cout << address.octets[i];
		if (i != 3) {
			std::cout << ".";
		}
		if (i == 3) {
			std::cout << std::endl;
		}
	}
}

int main(void) {
	setlocale(LC_ALL, "RU");
	std::string inputString;
	FourOctets ipAddress1;
	FourOctets ipAddress2;
	FourOctets ipMask;
	std::stringbuf strBuf("10.0.0.80/24 10.0.0.129");
	std::istream tStr(&strBuf);
	while( getline (/*tStr*/ std::cin, inputString) ) {
		// ��������� ������ �� ������� �� 2 �����. ���� ������ ������ - �����.
		SplitStrIpMaskIp(inputString, ipAddress1, ipAddress2, ipMask);
		try {
			if( !ipAddress1.isValid || !ipAddress2.isValid || !ipMask.isValid) {
				throw UserException();
			}
			if(IsNeedRouting(ipAddress1, ipAddress2, ipMask)) {
				std::cout << "routing is needed" << std::endl;
			} else {
				std::cout << "same subnet" << std::endl;
			}
		} catch (UserException) {
			std::cout << "X" << std::endl;
		}
	}
	return 0;
}