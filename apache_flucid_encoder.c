/*
 * Author <andy.pitcher@mail.concordia.ca> 
 * apache_flucid_encoder is a simple program to turn Apache access logs into Forensic Lucid
 * 
 * Conversion can be done statically, by passing a LogFile formated in httpd.conf as below:
 * LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
 *
 * [In Progress] Conversion can be done dynamically, by using the piped log option with Apache in httpd.conf as below:
 * CustomLog "|/usr/sbin/apache_flucid_encoder -D" combined
 */


#include <stdio.h>
#include <stdlib.h> // For exit() function

//Definition of the ApacheLog structure as a variable to manipulate the attributes
struct ApacheLog {
  char ip[30];
  char identd[30];
  char userid[30];
  char date[60];
  char method[10];
  char http_path[128];
  char http_referer[256];
  char user_agent[256];
  char http_protocol[30];
  int date_zone;
  int http_code;
  int object_size;
};

//Definirion of collect_flucid_obs function
void collect_flucid_obs(char line[],int i);

//Definition of diplay_flucid_obs function
void display_flucid_obs(struct ApacheLog, int i);


int main(int argc, char *argv[])
{
  char line[1000];
  FILE *logs;
  int lines_count=0;
  int i=1;
  int scanresult;


//Options of the program
// -F [FILE] for static converstion (redirect to stdout)
// -D for dynamic converssion used with piped log

  while ((++argv)[0])
    {
            if (argv[0][0] == '-' )
            {
                    switch (argv[0][1])  {

                            default:
                                    printf("Unknown option -%c\n\nUsage: Convert_Apache2_Flucid [-D-F]... [FILE]...\n-D\tRead the stdin to use pipe", argv[0][1]);
                                    break;
                            case 'F':
                                    //argv[1] is waiting for an access_log to be passed as an argument
  				    if ((logs = fopen(argv[1], "r")) == NULL)
  					{
    						printf("Error! opening file\n");
        			    // Program exits if file pointer returns NULL.
    						exit(1);
  					}
                                    break;
                            case 'D':
				    logs = stdin;
				    //Option to read stdin for piped logging : CustomLog |/usr/sbin/converter_apache2_FLucid -D
                                    break;
                    }
            }

    }

//Count number of lines and assign that number to size of the struct
struct ApacheLog Log[8000];
  while(fgets(line, sizeof(line), logs) != NULL)
  {
//	printf("%s",line);
//	collect_flucid_obs(Log[i],line,i);
	scanresult = sscanf( line, "%s %s %s [%s -%d] \"%s %s %[HTTP/1.0-1]\" %d %d %s %[^\t\n]", Log[i].ip, Log[i].identd, Log[i].userid, Log[i].date, &Log[i].date_zone, Log[i].method, Log[i].http_path, Log[i].http_protocol, &Log[i].http_code, &Log[i].object_size, Log[i].http_referer, Log[i].user_agent);
        lines_count++;
	i ++;
  }

  
  printf("\nFLucid observations: %d\n\n",lines_count);
  /* for loop execution */
   for( i = 1; i < lines_count+1; i = i + 1 ){
      //printf("value of a: %d\n", a);
 display_flucid_obs(Log[i], i);
   }
  printf("\nFLucid observations processed: %d\n\n",lines_count);


return 0;
}


//Definition of fct collect_flucid_obs which collects the apache log line to flucid observation
void collect_flucid_obs( char line[],int i){
  
int scanresult;
//int i=1;
//char line [1000];
int lines_count;

//printf("%s",line);
//while ((fscanf(logs, "%[^\n]", line)) != EOF)
//  {
//   fgetc(logs);
//For each line we use the below regex to read through and assign each attributes to the given struct array  
//   scanresult = sscanf( line, "%s %s %s [%s -%d] \"%s %s %[HTTP/1.0-1]\" %d %d %s %[^\t\n]", Log[i].ip, Log[i].identd, Log[i].userid, Log[i].date, &Log[i].date_zone, Log[i].method, Log[i].http_path, Log[i].http_protocol, &Log[i].http_code, &Log[i].object_size, Log[i].http_referer, Log[i].user_agent);
//   if ( scanresult != 13 ) {

//Call the display_flucid_obs fct with the current struct defined by i

  //} else {
  //  printf( "Bad Log format provided\n" );
 // }
 // i++;
//}
//fclose(logs);
}

//Definition of fct display_flucid_obs which prints the apache log line to flucid observation
void display_flucid_obs(struct ApacheLog log, int i){

  printf("observation access_o_%d = ([src-ip:\"%s\" , access-date:\"%s\" , timezone:\"0%d\" , http-identd:\"%s\" , http-userid:\"%s\" , http-method:\"%s\" , http-path:\"%s\" , http-protocol:\"%s\" , http-code:\"%d\" , object-size:\"%d\" , http-referer:%s , user-agent:%s] 1 , 0 , 1 . 0 ,\"%s\" \n\n",
    i,log.ip,log.date,log.date_zone,log.identd,log.userid,log.method,log.http_path,log.http_protocol,log.http_code,log.object_size,log.http_referer,log.user_agent,log.date);
}
