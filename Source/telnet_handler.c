#include "../Include/telnet_handler.h"
//extern int vivid;
//extern int hex;

extern struct recorder myRecorder;
extern MYSQL mysql;
extern MYSQL_RES *res;
extern MYSQL_ROW row;
extern char query[200];
extern char table_name[50];

char *telnet_command(u_char com_code)
{
	switch(com_code) {
		case 236: return "EOF";
		case 237: return "SUSP";
		case 238: return "ABORT";
		case 239: return "EOR";
		case 240: return "SE";
		case 241: return "NOP";
	    case 242: return "DM";
		case 243: return "BRK";
		case 244: return "IP";
		case 245: return "AO";
		case 246: return "AYT";
		case 247: return "EC";
		case 248: return "EL";
		case 249: return "GA";
		case 250: return "SB";
		case 251: return "WILL";
		case 252: return "WONT";
		case 253: return "DO";
		case 254: return "DONT";
		case 255: return "IAC";
		default: return NULL;
	}
}

char *telnet_option(u_char opt_code)
{
	switch(opt_code) {
		case   0: return "Binary";
		case   1: return "Echo";
		case   2: return "Recommection";
		case   3: return "Suppress Go Ahead";
		case   4: return "Approx Message Size Negotiation";
		case   5: return "Status";
		case   6: return "Timing Mark";
		case   7: return "Remote Controlled Trans and Echo";
		case   8: return "Output Line Width";
		case   9: return "Output Page Echo";
		case  10: return "Output Carriage Return Disposition";
		case  11: return "Output Horizontal Tab Stops";
		case  12: return "Output Horizontal Tab Disposition";
		case  13: return "Output Formfeed Disposition";
		case  14: return "Output Vertical Tabstops";
		case  15: return "Output Vertical Tab Disposition";
		case  16: return "Output Linefeed Disposition";
		case  17: return "Extended ASCII";
		case  18: return "Logout";
		case  19: return "Byte Marco";
		case  20: return "Data Entry Terminal";
		case  21: return "SUPDUP";
		case  22: return "SUPDUP Output";
		case  23: return "Send Location";
		case  24: return "Terminal Type";
		case  25: return "End of Record";
		case  26: return "TACACS User Identification";
		case  27: return "Output Marking";
		case  28: return "Terminal Location Number";
		case  29: return "Telnet 3270 Regime";
		case  30: return "X.3 PAD";
		case  31: return "Negotiate About Window Size";
		case  32: return "Terminal Speed";
		case  33: return "Remote Flow Control";
		case  34: return "Linemode";
		case  35: return "X Display Location";
		case  36: return "Environment Option";
		case  37: return "Authentication Option";
		case  38: return "Encryption Option";
		case  39: return "New Environment Option";
		case  40: return "TN3270E";
		case  41: return "XAUTH";
		case  42: return "CHARSET";
		case  43: return "Telnet Remote Serial Port(RSP)";
		case  44: return "Com Port Control Option";
		case  45: return "Telnet Suppress Local Echo";
		case  46: return "Telnet Start TLS";
		case  47: return "KERMIT";
		case  48: return "SEND-URL";
		case  49: return "FORWARD_X";
		case 138: return "TELOPT PRAGMA LOGON";
		case 139: return "TELOPT SSPI LOGON";
		case 140: return "TELOPT PRAGMA HEADTBEAT";
		default:  return "Unassigned";
	}
}
void telnet_handler(const u_char *packet, int len)
{
	//printf("	TELNET\n");
	memcpy(myRecorder.protocol_type, "TELNET\0", 7);
#if 0
	typedef struct {
		int len;
		char data[0];
	} buffer;
	if(0xff == *packet) {				// command
		int pix = 0;
		while(pix < len) {
			if(0xff == *(packet + pix) && 
			   0xfa == *(packet + pix + 1)) {		// suboption
				printf("\tCommand: Suboption\n");
				printf("\tSubcommand: %s\n", telnet_option(*(packet + pix + 2)));
				pix += 3;
				printf("\tdata: ");
				while(pix <len && 
					  !(0xff == *(packet + pix) && 0xf0 == *(packet + pix + 1))) {
					printf("%02x ", *(packet + pix));
					pix ++;
				}
				printf("\n");
				pix += 2;
			}
			else if(0xff == *(packet + pix)) {
				printf("\tCommand: %s\n", telnet_command(*(packet + pix + 1)));
				printf("\tSubcommand: %s\n", telnet_option(*(packet + pix + 2)));
				pix += 3;
			}
			else {
				pix ++;
			}
		}
	} 
	else {								// data, can't print '\r'
		for(;;) {
			int i;
			for(i = 0; i < len - 1 && 0 != strncmp(packet + i, "\r\n", 2); i++);
			if(i == len - 1) {						 
				i = len;
			}	
			buffer *line = (buffer*)malloc(sizeof(buffer) + i + 1);
			memcpy(line->data, packet, i);
			line->data[i] = '\0';
			if(i == len) {						
				printf("\tData: %s\n", line->data);
				packet += len;
				len = 0;
				break;
			}
			else {
				printf("\tData: %s\\r\\n\n", line->data);
				packet += (i + 2);
				len -= (i + 2);
			}

			if(0 == i || 0 == len){				// the line begin with "\r\n"
				break;
			}
		}
	}
	if(hex) {
		print_payload(packet, len);
	}
#endif


	int t = insert(&mysql, table_name, myRecorder);
	if(t) {
		printf("执行显示时出现异常：%s", mysql_error(&mysql));
	}
	else {
		printf("插入成功\n");
	}
	
}
