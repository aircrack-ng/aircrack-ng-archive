#define __FAVOR_BSD 1

#include <string.h>
#include <dirent.h>
#include <fnmatch.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <getopt.h>

#include "version.h"

char usage[] =

"\n"
"  %s\n"
"\n"
"  usage: jupload <options>\n"
"\n"
"  Options:\n"
"      --dir           <path> : Path to dump files\n"
"      -d                     : same as --dir \n"
"      --filter <file filter> : Dump file filter\n"
"      -f                     : same as --filter\n"
"      --url            <url> : URL to upload the files to\n"
"      -u                     : same as --url\n"
"      --sleep      <seconds> : Number of seconds to sleep between checks\n"
"      -s                     : same as --sleep\n"
"\n"
"      --help                : Displays this usage screen\n"
"\n";

void uploadFile(char *dirName, char *strFileName, char* uploadUrl, char expectNoHeader)
{
	printf("Uploading file %s\n", strFileName);

	CURL *curl;
	CURLcode res;

	int ofn_len = strlen(dirName) + strlen(strFileName) + 2;
	char * ofn = (char *)calloc(1, ofn_len);
	memset(ofn, 0, ofn_len);
	snprintf( ofn,  ofn_len, "%s/%s", dirName, strFileName );

	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	struct curl_slist *headerlist = NULL;
	static const char buff[] = "Expect:";

	curl_global_init(CURL_GLOBAL_ALL);

	curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "sendfile", CURLFORM_FILE, strFileName, CURLFORM_END);
	curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "filename", CURLFORM_COPYCONTENTS, ofn, CURLFORM_END);
	curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "submit", CURLFORM_COPYCONTENTS, "send", CURLFORM_END);

	curl = curl_easy_init();

	headerlist = curl_slist_append(headerlist, buff);

	if(curl){
		curl_easy_setopt(curl, CURLOPT_URL, uploadUrl);

		if ( expectNoHeader )
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

		res = curl_easy_perform(curl);

		if(res == CURLE_OK)
		{
			//delete the file...
			printf("File %s uploaded, deleting file.\n", strFileName);
			remove(ofn);
		}
        else
        {
            printf("File %s not uploaded to %s, returned %d\n", strFileName, uploadUrl, res);
        }

		curl_easy_cleanup(curl);

		curl_formfree(formpost);

		curl_slist_free_all(headerlist);
	}

	free ( ofn );
}

void doProcessingLoop(char *dirName, char *fileFilter, char *uploadUrl)
{
	struct dirent **namelist;
	int n;
	n = scandir(dirName, &namelist, NULL, alphasort);
	if (n < 0)
	{
		printf("Unable to search for %s files in %s\n", fileFilter, dirName);
	}
	else {
		while ( n-- ) {
			if (fnmatch(fileFilter, namelist[n]->d_name, FNM_PATHNAME) == 0)
			{
				uploadFile(dirName, namelist[n]->d_name, uploadUrl, 0);
			}
            free(namelist[n]);
		}
		free(namelist);
	}
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
        {"dir",      1, 0, 'd'},
        {"filter",   1, 0, 'f'},
        {"url",      1, 0, 'u'},
        {"sleep",    1, 0, 's'},
        {"help",     0, 0, 'H'}
    };

    int num_opts = 0;
    int option = 0;
    int option_index = 0;
    int i = 0;
    int j = 0;
    int found = 0;

    int sleep_seconds = 5 * 60;
	char* dirName = NULL;
	char* fileFilter = NULL;
	char* uploadUrl = NULL;
	
	/* check the arguments */

    for(i=0; long_options[i].name != NULL; i++);
    num_opts = i;

    for(i=0; i<argc; i++) //go through all arguments
    {
        found = 0;
        if(strlen(argv[i]) >= 3)
        {
            if(argv[i][0] == '-' && argv[i][1] != '-')
            {
                //we got a single dash followed by at least 2 chars
                //lets check that against our long options to find errors
                for(j=0; j<num_opts;j++)
                {
                    if( strcmp(argv[i]+1, long_options[j].name) == 0 )
                    {
                        //found long option after single dash
                        found = 1;
                        if(i>1 && strcmp(argv[i-1], "-") == 0)
                        {
                            //separated dashes?
                            printf("Notice: You specified \"%s %s\". Did you mean \"%s%s\" instead?\n", argv[i-1], argv[i], argv[i-1], argv[i]);
                        }
                        else
                        {
                            //forgot second dash?
                            printf("Notice: You specified \"%s\". Did you mean \"-%s\" instead?\n", argv[i], argv[i]);
                        }
                        break;
                    }
                }
                if(found)
                {
                    sleep(3);
                    break;
                }
            }
        }
    }

    do
    {
    	option_index = 0;

        option = getopt_long( argc, argv,
                        "d:f:u:s:H",
                        long_options, &option_index );

        if( option < 0 ) break;

        switch ( option )
        {
        	case 0 : break;
        	case ':': printf("\"%s --help\" for help.\n", argv[0]); return( 1 );
        	case '?': printf("\"%s --help\" for help.\n", argv[0]); return( 1 );
        	case 'H': printf( usage, getVersion("jupload", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  ); return( 1 );
        	case 'd':
        		if ( dirName != NULL ) {
        			printf("Notice: directory already given\n");
        			break;
        		}
        		dirName = optarg;
        		break;
        	case 'f':
        		if ( fileFilter != NULL ) {
        			printf("Notice: filter already given\n");
        			break;
        		}
        		fileFilter = optarg;
        		break;
        	case 'u':
                if (uploadUrl != NULL) {
                    printf( "Notice: upload url already given\n" );
                    break;
                }
                uploadUrl = optarg;
                break;
            case 's':
                sleep_seconds = atoi(optarg);
                break;
        }

    } while(1);

    if (fileFilter == NULL || dirName == NULL || uploadUrl == NULL)
    	goto usage;

    printf("Starting jupload, sending %s files in %s folder to %s\n", fileFilter, dirName, uploadUrl);

	while(1)
	{
		doProcessingLoop(dirName, fileFilter, uploadUrl);
		sleep( sleep_seconds );
	}

usage:
	printf( usage, getVersion("jupload", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC)  );

	return 0;
}