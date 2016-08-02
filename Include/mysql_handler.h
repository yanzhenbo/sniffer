#ifndef _MYSQL_HANDLER_H_
#define _MYSQL_HANDLER_H_ 1

#include <stdio.h>
#include <mysql/mysql.h>
#include <string.h>
struct recorder {
	int id;
	double time;
	char protocol_type[20];
	char src_ip[20];
	char dst_ip[20];
};
int sum(int x, int y);
int insert(MYSQL* mysql, char *table_name, struct recorder myRecorder);

#endif /* _MYSQL_HANDLER_H_ */
