#define __FAVOR_BSD 1

#include <string.h>
#include <dirent.h>
#include <fnmatch.h>
#include <unistd.h>
#include <stdio.h>
#include <curl/curl.h>

void uploadFile(char *strFileName, char* uploadUrl, char expectNoHeader)
{
	CURL *curl;
	CURLcode res;

	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	struct curl_slist *headerlist = NULL;
	static const char buff[] = "Expect:";

	curl_global_init(CURL_GLOBAL_ALL);

	curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "sendfile", CURLFORM_FILE, strFileName, CURLFORM_END);
	curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "filename", CURLFORM_COPYCONTENTS, strFileName, CURLFORM_END);
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
			remove(strFileName);
		}

		curl_easy_cleanup(curl);

		curl_formfree(formpost);

		curl_slist_free_all(headerlist);
	}
}

void doProcessingLoop(char *dirName, char *fileFilter, char *uploadUrl)
{
	struct dirent **namelist;
	int n;
	if ( chdir(dirName) < 0 )
	{
		perror("chdir");
		return;
	}
	n = scandir(".", &namelist, NULL, alphasort);
	if (n < 0)
		perror("scandir");
	else {
		while ( n-- ) {
			if (fnmatch(fileFilter, namelist[n]->d_name, FNM_PATHNAME) == 0)
			{
				uploadFile(namelist[n]->d_name, uploadUrl, 0);
			}
            free(namelist[n]);
		}
		free(namelist);
	}
}

int main(int argc, char *argv[])
{
	char* dirName;
	char* fileFilter;
	char* uploadUrl;
	if(argc < 4) // not enough arguments!!!
		return 0;

	dirName = argv[1];
	fileFilter = argv[2];
	uploadUrl = argv[3];

	while(1)
	{
		doProcessingLoop(dirName, fileFilter, uploadUrl);
		sleep( 60 * 5 );
	}

	return 0;
}