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
#include <list>

#define BUFFSIZE 1024


enum init_system {SYSTEMD, OPENRC, UNIDENTIFIED};
enum lib_lookup_result {SUCCESS, MISSING, OUTDATED, ERROR, OTHER};


typedef struct {
	long id;
	pid_t pid;
	char cmd[128];
	char type[10];
	ino_t inode;
	char filename[256];
} lsof_entry;

typedef struct {
	char filename[256];
	struct stat file_stat;
	enum lib_lookup_result check_result;
} so_file_stat;

using namespace std;

unordered_map<pid_t, char*> pid_service_map;
list<so_file_stat*> lib_files_stat_list;
set<int> docker_owned_pids;

set<char*> services_to_restart;

enum init_system my_init_system;

unsigned int broken_entries_count = 0;
unsigned int stat_calls_count = 0;

void handle_service_to_restart_set (pid_t pid){
	unordered_map<pid_t, char*>::const_iterator it = pid_service_map.find(pid);
	if (it != pid_service_map.end()){
		services_to_restart.insert(it->second);
	}
}

void increment_broken_entries_count(){
	broken_entries_count++;
}

so_file_stat *find_so_file_in_checked_list (char *filename){
	for (list<so_file_stat*>::iterator it = lib_files_stat_list.begin(); it != lib_files_stat_list.end(); ++it){
		if (strcmp((*it)->filename, filename) == 0){
			return *it;
		}
	}

	return NULL;
}


enum lib_lookup_result check_entry(lsof_entry *entry){
	
//	int stat_ret;
//	struct stat file_stat;
	
	so_file_stat *so_file_stat_ptr;

	if ( strstr(entry->filename, "type=") != NULL ){
		return OTHER;
	}

	if ( strstr(entry->filename, ".so") == NULL ){
		return OTHER;
	}

	// we add to count every file that is stat'd
	entry->id++;

	so_file_stat_ptr = find_so_file_in_checked_list(entry->filename);

	if (so_file_stat_ptr == NULL){
		so_file_stat_ptr = (so_file_stat*)(malloc(sizeof(so_file_stat)));
		lib_files_stat_list.push_back(so_file_stat_ptr);

		strcpy(so_file_stat_ptr->filename, entry->filename);
		so_file_stat_ptr->check_result = SUCCESS;

		stat_calls_count++;

		if ( stat(entry->filename, &(so_file_stat_ptr->file_stat)) != 0 ){
			if ( errno == ENOENT ){
				return (so_file_stat_ptr->check_result = MISSING);
			}else{
				return (so_file_stat_ptr->check_result = ERROR);
			}
		}

		// not a regular file
		if ( ((so_file_stat_ptr->file_stat).st_mode & S_IFMT) != S_IFREG ){
			return (so_file_stat_ptr->check_result = OTHER);
		}
	}

	if ( so_file_stat_ptr->check_result == SUCCESS && entry->inode != (so_file_stat_ptr->file_stat).st_ino ){
		return OUTDATED;
	}else{
		return so_file_stat_ptr->check_result;
	}
}

void handle_entry (lsof_entry *entry){
	
	if (docker_owned_pids.find(entry->pid) != docker_owned_pids.end()) {
		return;
	}

	switch (check_entry(entry)){
		case MISSING:
			printf ("Found that %s (PID=%d) uses a missing %s\n", entry->cmd, entry->pid, entry->filename);
			handle_service_to_restart_set(entry->pid);
			increment_broken_entries_count();

			break;
		case OUTDATED:
			//printf ("lsof inode: %ld, actual inode: %ld\n", entry->inode, file_stat.st_ino);
			printf ("Found that %s (PID=%d) uses an outdated %s\n", entry->cmd, entry->pid, entry->filename);
			handle_service_to_restart_set(entry->pid);
			increment_broken_entries_count();

			break;
		case ERROR:
			printf ("Unknown error occured while stat'ing %s\n", entry->filename);

			break;
		default:
			break;
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
	char *servicename;
	char service_name_used = 0;

	servicename = extract_service_name_from_path(filepathandname);
	
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

void populate_docker_owned_pids_set (){
	FILE *fp = NULL;
	char buff[128];
	pid_t pid;
	const char *docker_slice_filename = "/sys/fs/cgroup/unified/system.slice/docker.service/cgroup.procs";

	if ( (fp = fopen(docker_slice_filename, "r")) == NULL ){
		//perror("");
		goto cleanup;
	}

	while ( fgets(buff, sizeof(buff), fp) != NULL ) {
		buff[strlen(buff)-1] = '\0';
		pid = atoi(buff);

		docker_owned_pids.insert(pid);
	}

	cleanup:
		if (fp) fclose(fp);
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

char *alloc_string (const char *str){
	char *ret = (char*)(malloc(strlen(str)+1));
	strcpy(ret, str);

	return ret;
}

char *get_base_proc_path(){
	const char *init_pid_path = "/proc/1/exe";

	const char *base_path_systemd = "/sys/fs/cgroup/systemd/system.slice";
	const char *base_path_openrc = "/sys/fs/cgroup/openrc";

	struct stat file_stat;
	char buff[1024];
	ssize_t len;
	int stat_ret;
	char *ret;

	strcpy(buff, init_pid_path);

	while (1){
		if ( (len = readlink(buff, buff, sizeof(buff)-1)) == -1 ) {
			return NULL;
		}
		
		buff[len] = '\0';

		if ( (stat_ret = lstat(buff, &file_stat)) != 0 ){
			return NULL;
		}
		
		if ( (file_stat.st_mode & S_IFMT) == S_IFREG ){
			break;
		}
	}

	if ( strstr(buff, "systemd") != NULL ){
		printf ("\nSeems you are using systemd (%s)\n\n", buff);
		ret = alloc_string(base_path_systemd);
		my_init_system = SYSTEMD;
	} else if ( strstr(buff, "init") != NULL ){
		printf ("\nSeems you are using OpenRC (%s)\n\n", buff);
		ret = alloc_string(base_path_openrc);
		my_init_system = OPENRC;
	} else {
		printf ("\nI can't identify init system '%s'\n\n", buff);
		my_init_system = UNIDENTIFIED;
		return NULL;
	}
	
	return ret;
}

void build_pid_service_assoc_map(){
	const char *procs_file_name = "cgroup.procs";

	DIR *dir;
	char *base_path;

	if ( (base_path = get_base_proc_path()) == NULL ){
		return;
	}

	if ( (dir = opendir(base_path)) == NULL ){
		printf ("\nThe path %s doesn't exist.\nWrongly identified init system?\n\n", base_path);
	}else{
		closedir(dir);
		find_and_populate_pid_service_map(&pid_service_map, base_path, procs_file_name);
	}

	free(base_path);
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

void free_lib_files_stat_list (){
	for (list<so_file_stat*>::iterator it = lib_files_stat_list.begin(); it != lib_files_stat_list.end(); ++it){
		free(*it);
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

char **get_services_restart_cmd_systemd (){
	const char *cmd_base_systemd = "systemctl restart ";
	char *cmd_str;
	char **cmds;
	set<char*>::iterator it;
	
	cmds = (char**)(malloc(sizeof(char*) *2));

	cmd_str = (char*)(malloc(strlen(cmd_base_systemd)+1));
	strcpy(cmd_str, cmd_base_systemd);

	it = services_to_restart.begin();
	
	if (it != services_to_restart.end()){
		while (it!=services_to_restart.end()){
			cmd_str = (char*)(realloc(cmd_str, strlen(cmd_str) + strlen(*it) +2));
			strcat(cmd_str, *it);
			strcat(cmd_str, " ");
			++it;
		}

		cmds[0] = cmd_str;
		cmds[1] = NULL;
	}else{
		free(cmd_str);
		cmds[0] = NULL;
	}
	
	return cmds;
}

char **get_services_restart_cmds_openrc (){
	const char *cmd_prefix = "rc-service ";
	const char *cmd_suffix = " restart";

	int cmd_size;
	char *cmd;
	char **cmds;
	int cmds_last_entry_index;
	set<char*>::iterator it;

	cmds_last_entry_index = 0;
	cmds = (char**)(malloc(sizeof(char*)));
	cmds[cmds_last_entry_index] = NULL;

	it = services_to_restart.begin();
	if (it != services_to_restart.end()){
		while (it!=services_to_restart.end()){
			cmd_size = strlen(cmd_prefix) + strlen(*it) + strlen(cmd_suffix)+1;
			cmd = (char*)(malloc(cmd_size));
			snprintf (cmd, cmd_size, "%s%s%s", cmd_prefix, *it, cmd_suffix);

			cmds = (char**)(realloc(cmds, sizeof(char*)*(cmds_last_entry_index+2)));
			cmds[cmds_last_entry_index++] = cmd;
			cmds[cmds_last_entry_index] = NULL;

			++it;
		}
	}

	return cmds;

}

char **get_services_restart_cmds (){
	
	char **cmds;	

	if (my_init_system == SYSTEMD) {
		cmds = get_services_restart_cmd_systemd();
	}else if (my_init_system == OPENRC){
		cmds = get_services_restart_cmds_openrc();
	} else {
		cmds = (char**)(malloc(1));
		cmds[0] = NULL;
	}

	return cmds;
}

void handle_service_restart_hint(){
	char ans;
	char **cmds;
	int i;

	cmds = get_services_restart_cmds();

	if (cmds[0] == NULL){
		goto cleanup;
	}

	printf ("You should probably run:\n\n");
	for (i=0 ; cmds[i] != NULL ; i++){
		printf ("%s\n", cmds[i]);
	}

	printf ("\nWould you like to do it now? [y/n] ");
	scanf ("%c", &ans);

	if (ans == 'y' || ans == 'Y'){
		printf ("\nRunning restart command[s]..\n\n");
		for (i=0 ; cmds[i] != NULL ; i++){
			system(cmds[i]);
		}
		printf ("\nDone\n\n");
	}else{
		printf ("\n");
	}

	
	cleanup:
		for (i=0 ; cmds[i] != NULL ; i++){
			free(cmds[i]);
		}
		free (cmds);
}

int main (){
	time_t exec_start, exec_end;
	int exec_time_sec;
	long lsof_entries_num;

	time(&exec_start);

	if ( getuid() != 0 ){
		printf ("\n\nPlease invoke as root. Otherwise output is very partial\n\n");
	}

	populate_docker_owned_pids_set();

	build_pid_service_assoc_map();

	printf("Scanning..\n\n");

	lsof_entries_num = do_lsof();

	time(&exec_end);
	exec_time_sec = exec_end - exec_start;

	printf("\n\n");
	if (broken_entries_count > 0){
		printf ("Found %u broken lib references.\n", broken_entries_count);
	}else{
		printf ("No broken lib references were found.\n");
	}

	printf ("\nDone.\nExecution took %d seconds.\nHandled %ld lsof entries (%u stat() calls).\n\n", exec_time_sec, lsof_entries_num, stat_calls_count);

	handle_service_restart_hint();

	free_pid_service_map();

	free_lib_files_stat_list();

	return 0;
}
