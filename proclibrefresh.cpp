/* 
 * proclibrefresh.cpp
 *
 * author: xicod
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <iostream>
#include <unordered_map>
#include <utility>
#include <functional>
#include <set>

#define BUFFSIZE 1024

typedef struct {
	long id;
	pid_t pid;
	char cmd[128];
	char type[10];
	ino_t inode;
	char filename[256];
} lsof_entry;

using namespace std;

unordered_map<pid_t, char*> pid_service_map;
set<char*> services_to_restart;

void handle_service_to_restart_set (pid_t pid){
	unordered_map<pid_t, char*>::const_iterator it = pid_service_map.find(pid);
	if (it != pid_service_map.end()){
		services_to_restart.insert(it->second);
	}
}

void handle_entry (lsof_entry *entry){
	
	//printf ("pid: %d, cmd: %s, type: %s, inode: %ld, filename: %s\n", entry->pid, entry->cmd, entry->type, entry->inode, entry->filename);

	int stat_ret;
	struct stat file_stat;

	if ( strstr(entry->filename, "type=") != NULL ){
		return;
	}

	if ( strstr(entry->filename, ".so") == NULL ){
		return;
	}
	
	// we add to count every file that is stat'd
	entry->id++;

	if ( (stat_ret = stat(entry->filename, &file_stat)) != 0 ){
		if ( errno == ENOENT ){
			printf ("Found that %s (PID=%d) uses a missing %s\n", entry->cmd, entry->pid, entry->filename);
			handle_service_to_restart_set(entry->pid);
		}else{
			printf ("Unknown error occured while stat'ing %s\n", entry->filename);
		}
		
		return;
	}

	// not a regular file
	if ( (file_stat.st_mode & S_IFMT) != S_IFREG ){
		return;
	}

	if ( entry->inode != file_stat.st_ino ){
		//printf ("lsof inode: %ld, actual inode: %ld\n", entry->inode, file_stat.st_ino);
		printf ("Found that %s (PID=%d) uses an outdated %s\n", entry->cmd, entry->pid, entry->filename);
		handle_service_to_restart_set(entry->pid);
	}
}

void parse_line (char *line, lsof_entry *entry){
	char type = line[0];
	char *value = line+1;

	switch (type){
		case 'p': 
			entry->pid = atoi(value);
			break;
		case 'c':
			strcpy(entry->cmd, value);
			break;
		case 'f':
			strcpy(entry->type, value);
			break;
		case 'i':
			entry->inode = atol(value);
			break;
		case 'n':
			strcpy(entry->filename, value);
			handle_entry(entry);
			break;
	}
}

char *make_path (const char *base, const char *additional){
	int newsize = strlen(base) + strlen(additional) + 2;
	char *new_path = (char*)(malloc(newsize));
	snprintf (new_path, newsize, "%s%s%s", base, "/", additional);

	return new_path;
}

char *extract_service_name_from_path (char* path){
	char *ret;
	char *start;
	size_t len;

	path = strrchr(path, (int)'/') -1;

	while ( *(path-1) != '/' ) path--;

	start = path;

	len = 0;
	while ( *path != '/' ){len++; path++;}

	ret = (char*)(malloc(len+1));

	strncpy(ret, start, len);
	ret[len] = '\0';

	return ret;
}

void handle_procs_file (unordered_map<pid_t, char*> *map, char *filepathandname){
	FILE *fp = NULL;
	char buff[128];
	pid_t pid;
	char *dot;	
	char *servicename;
	char service_name_used = 0;

	servicename = extract_service_name_from_path(filepathandname);

	dot = strrchr(servicename, '.');
	
	if ( !dot || strcmp(dot, ".service") != 0 ){
		goto cleanup;
	}

	if ( (fp = fopen(filepathandname, "r")) == NULL ){
		perror("");
		goto cleanup;
	}

	while ( fgets(buff, sizeof(buff), fp) != NULL ) {
		buff[strlen(buff)-1] = '\0';
		pid = atoi(buff);

		map->insert(pair<pid_t, char*>(pid, servicename));
		service_name_used = 1;
	}

	cleanup:
		if (fp) fclose(fp);
		if (!service_name_used) free(servicename);
}

void find_and_populate_pid_service_map (unordered_map<pid_t, char*> *map, const char *path, const char *filename){
	DIR *dir;
	struct dirent *ent;

	char *new_path;

	if ( (dir = opendir(path)) != NULL ){
		while ( (ent = readdir(dir)) != NULL ){
			if ( ent->d_name[0] == '.' ){
				continue;
			}

			new_path = make_path(path, ent->d_name);
			
			if ( ent->d_type == DT_DIR ){
				find_and_populate_pid_service_map(map, new_path, filename);
			} else if ( strcmp(ent->d_name, filename) == 0 ){
				handle_procs_file(map, new_path);
			}
			
			free(new_path);
		}

		closedir(dir);
	}else{
		perror("");
		return;
	}
}

void build_pid_service_assoc_map(){
	const char *base_path = "/sys/fs/cgroup/systemd/system.slice";
	const char *procs_file_name = "cgroup.procs";

	DIR *dir;

	if ( (dir = opendir(base_path)) == NULL ){
		printf ("\nThe path %s doesn't exist.\nIs this a systemd system?\n\n", base_path);
	}else{
		closedir(dir);
		find_and_populate_pid_service_map(&pid_service_map, base_path, procs_file_name);
	}
}

void free_pid_service_map(){
	set<char*> tempset;
	unordered_map<pid_t, char*>::iterator map_it;
	set<char*>::iterator set_it;
	
	map_it = pid_service_map.begin();
	while ( map_it != pid_service_map.end() ){
		tempset.insert(map_it->second);
		++map_it;
	}

	set_it = tempset.begin();
	while ( set_it != tempset.end() ){
		free(*set_it);
		++set_it;
	}
}

long do_lsof (){
	const char *cmd = "lsof -w -F cpin";
	
	lsof_entry entry;

	char buff[BUFFSIZE];
	
	FILE *fp;

	if ((fp = popen(cmd, "r")) == NULL) {
		printf("Error opening pipe!\n");
		return -1;
	}

	entry.id = 0;

	while (fgets (buff, BUFFSIZE, fp) != NULL){
		*(strstr(buff, "\n")) = '\0';
		parse_line (buff, &entry);
	}

	pclose(fp);

	return entry.id;
}

void handle_service_restart_hint(){
	const char *cmd_base = "systemctl restart ";
	char *cmd_str;
	set<char*>::iterator it;
	char ans;

	cmd_str = (char*)(malloc(strlen(cmd_base)+1));
	strcpy(cmd_str, cmd_base);

	it = services_to_restart.begin();
	
	if (it != services_to_restart.end()){
		printf ("You should probably run:\n\n");
		while (it!=services_to_restart.end()){
			cmd_str = (char*)(realloc(cmd_str, strlen(cmd_str) + strlen(*it) +2));
			strcat(cmd_str, *it);
			strcat(cmd_str, " ");
			++it;
		}
		printf ("%s\n\n", cmd_str);
		printf ("Would like to do it now? [y/n] ");
		scanf ("%c", &ans);

		if (ans == 'y' || ans == 'Y'){
			printf ("\nRunning systemctl restart command..\n\n");
			system(cmd_str);
			printf ("\nDone\n\n");
		}

	}

	free(cmd_str);
}

int main (){
	time_t exec_start, exec_end;
	int exec_time_sec;
	long lsof_entries_num;

	time(&exec_start);

	if ( getuid() != 0 ){
		printf ("\n\nPlease invoke as root. Otherwise output is very partial\n\n");
		return 0;
	}

	build_pid_service_assoc_map();

	lsof_entries_num = do_lsof();

	time(&exec_end);
	exec_time_sec = exec_end - exec_start;

	printf ("\nDone.\nExecution took %d seconds.\nHandled %ld lsof entries.\n\n", exec_time_sec, lsof_entries_num);

	handle_service_restart_hint();

	free_pid_service_map();

	return 0;
}
