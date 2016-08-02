#include "../Include/mysql_handler.h"
extern char query[200];
int insert(MYSQL *mysql, char *table_name, struct recorder myRecorder)
{
	sprintf(query, "insert into %s (time, protocol_type, src_ip, dst_ip) values ('%f', '%s', '%s', '%s')", table_name, myRecorder.time, myRecorder.protocol_type, myRecorder.src_ip, myRecorder.dst_ip);
	
	int t = mysql_real_query(mysql, query, (unsigned int)strlen(query));
    if(t){
		return 1;
	}
	return 0;
}


