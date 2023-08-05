#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "devices/input.h"
#include <string.h>


static void syscall_handler (struct intr_frame *);

// Lock to synchronize file system functions
struct lock filesys;

/*
 * Initializes lock and interrupt handler for syscall
 *
 * pre: none
 * post: filesys lock is initialized
 */
void
syscall_init (void) 
{
  // Sashank driving, Praveen and Ike navigating
  // initializes file system lock 
  lock_init(&filesys);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
 * Checks if a user provided pointer is valid
 *
 * pre: void *pointer representing the pointer to be validated
 * post: boolean representing whether the pointer provided is valid
 */
static void check_pointer(void *pointer) {
  // checks if the pointer is non-null, in user space, and accessible from the 
  // process
  if(pointer == NULL || is_kernel_vaddr(pointer) || 
  	 pagedir_get_page(thread_current()->pagedir, pointer) == NULL) {
    exit(-1);
  }
  // end of Sashank driving
}

/*
 * Maps system calls to the appropriate system call implementation
 *
 * pre: struct intr_frame *f represents the current stack frame
 * post: none
 */
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // Praveen driving, Ike and Sashank navigating
  // Make sure all bytes are in bounds
  check_pointer(f->esp);
  check_pointer(((char *)f->esp) + 1);
  check_pointer(((char *)f->esp) + 2);
  check_pointer(((char *)f->esp) + 3);

  // calls the appropriate function based on the system call number  
  int syscall_number = *((int*) f->esp);

  switch(syscall_number) {
    case SYS_HALT:  
      halt();
  	  break;
  	case SYS_EXIT:
		int* status_p = ((int*) f->esp) + 1;

      	check_pointer(status_p);
      	exit(*status_p);
  		break;
	// end of Praveen driving
  	case SYS_EXEC:
	// Ike driving, Praveen and Sashank navigating
		char** file2_p = ((char**) f->esp) + 1;

		for (int i = 0; i < 4; i++) {
			check_pointer(((char*) file2_p) + i);
		}
		for (int i = 0; i < 4; i++) {
			check_pointer((*file2_p) + i);
		}
      	f->eax = exec(*file2_p);
  		break;
	// end of Ike driving
  	case SYS_WAIT:
	// Sashank driving, Praveen and Ike navigating
		pid_t* pid_p = ((pid_t*) f->esp) + 1;

      	check_pointer(pid_p);
      	f->eax = wait(*pid_p);
  		break;
  	case SYS_CREATE:
		char** file3_p = ((int*) f->esp) + 1;
		unsigned* initial_size_p = ((unsigned*) f->esp) + 2;

		check_pointer(file3_p);
		check_pointer(initial_size_p);
		f->eax = create (*file3_p, *initial_size_p);
  		break;
  	case SYS_REMOVE:
		char** file4_p = ((int*) f->esp) + 1;

		check_pointer(file4_p);
		f->eax = remove (*file4_p);
  		break;
  	case SYS_OPEN:
		char** file_p = ((char**) f->esp) + 1;

		check_pointer(file_p);
      	f->eax = open(*file_p);
  		break;
  	case SYS_FILESIZE:
		int* fd3_p = ((int*) f->esp) + 1;

      	check_pointer(fd3_p);
      	f->eax = filesize(*fd3_p);
  		break;
  	case SYS_READ:
		int* fd4_p = ((int*) f->esp) + 1;
		void** buffer2_p = ((void**) f->esp) + 2;
		unsigned* length2_p = ((unsigned*) f->esp) + 3;

		check_pointer(fd4_p);
		check_pointer(buffer2_p);
		check_pointer(*buffer2_p);
		check_pointer(length2_p);
		f->eax = read (*fd4_p, *buffer2_p, *length2_p);
  		break;
  	case SYS_WRITE:
		int* fd_p = ((int*) f->esp) + 1;
		void** buffer_p = ((void**) f->esp) + 2;
		unsigned* length_p = ((unsigned*) f->esp) + 3;

		check_pointer(fd_p);
		check_pointer(buffer_p);
		check_pointer(*buffer_p);
		check_pointer(length_p);
		f->eax = write (*fd_p, *buffer_p, *length_p);
  		break;
	// end of Sashank driving
  	case SYS_SEEK:
	// Praveen driving, Ike and Sashank navigating
		check_pointer((int *)f->esp + 1);
		check_pointer((int *)f->esp + 2);

		seek(*((int *)f->esp + 1), *((int *)f->esp + 2));
  		break;
  	case SYS_TELL:
		check_pointer((int *)f->esp + 1);
		f->esp = tell(*((int *)f->esp + 1));
  		break;
  	case SYS_CLOSE:
		int* fd2_p = ((int*) f->esp) + 1;

      	check_pointer(fd2_p);
      	close(*fd2_p);
  		break;
	// Sashank driving, Praveen and Eylam navigating
	case SYS_MKDIR:
		char** file_name = ((char**) f->esp) + 1;
		check_pointer(file_name);
      	f->eax = make_dir(*file_name);
  		break;
	case SYS_CHDIR:
		char** file_name_c = ((char**) f->esp) + 1;
		check_pointer(file_name_c);
      	f->eax = chdir(*file_name_c);
  		break;
	// end of Sashank driving
  	default:
	  // exits if system call not found
      exit(-1);
	  break;
	// end of Praveen driving
  }
}

/*
 * Checks if a filename is valid
 *
 * pre: char *filename representing the filename
 * post: boolean representing whether the fileame is valid
 */
bool validate_filename(char *filename) {
	// Sashank driving, Praveen and Ike navigating
	// checks if the filename pointer is valid, then checks size
	check_pointer(filename);
	int length = strlen(filename);
	// If non-root path, check if last file is valid
	char *last_filename = strrchr(filename, '/');
	if(last_filename) {
		int last_length = strlen(last_filename + 1);
		return last_length >= 1 && last_length <= 14;
	}
	return length >= 1 && length <= 14;
}

/*
 * Halts the system
 *
 * pre: none
 * post: none
 */
void halt () {
	shutdown_power_off();
}

/*
 * Exits the process
 *
 * pre: int status representing the exit code to exit with
 * post: none
 */
void exit (int status) {
	// Get rid of arguments in process name, for printing purposes
	char* filler = strtok_r (thread_current()->name, " ", &filler);
	printf("%s: exit(%d)\n", thread_current()->name, status);
	// sets status code and handles thread exit
	thread_current()->exit_status = status;
	thread_exit ();
	// end of Sashank driving
}

/*
 * Executes a process
 *
 * pre: int status representing the exit code to exit with
 * post: tid_t representing the thread id of the process executing the file, -1
 * if the process can't be loaded or run
 */
tid_t exec (const char *file) {
	// Ike driving, Praveen and Sashank navigating
	// executes the process while protected
	tid_t tid = process_execute(file);

    // See if child successfully executed
    struct thread *cur = thread_current();
    struct list_elem *e = NULL;
    struct thread *child_in_question = NULL;
    struct thread *cur_child = NULL;

    for (e = list_begin(&cur->children); e != list_end(&cur->children);
        e = list_next(e))
    {
      cur_child = list_entry(e, struct thread, child_elem);
      if (cur_child->tid == tid) {
        child_in_question = cur_child;
        break;
      }
    }

    if (!child_in_question) {
      return -1;
    }

	// waits until executing process has started
	child_in_question->need_exec = true;
	sema_down(&child_in_question->sema_exec);
	tid = child_in_question->tid;

    if (!child_in_question->exec_success) {
  	  list_remove(&child_in_question->child_elem);	
      tid = -1;
    }

	sema_up(&child_in_question->sema_exec_collected);
	// returns given tid, if there are no errors
	return tid;
	// end of Ike driving
}

/*
 * Waits for a child process pid and retrieves the child's exit status
 *
 * pre: pid_t pid represents the process to wait on
 * post: int representing the exit code of the process being waited on
 */
int wait (pid_t pid) {
	// Sashank driving, Praveen and Ike navigating
	return process_wait(pid);
}

/*
 * Creates a new file called file initially initial_size bytes in size
 *
 * pre: char *file represents the file name, unsigned initial_size represents 
 * the initial size of the file in bytes
 * post: boolean representing whether the creation of file was succesful
 */
bool create (const char *file, unsigned initial_size) {
	// checks for valid filename
	if(!validate_filename(file)) {
		return false;
	}
	// creates file while protected, storing whether the function was succesful
	lock_acquire(&filesys);
	bool status = filesys_create (file, initial_size, false);
	lock_release(&filesys);
	return status;
}

/*
 * Deletes the file called file
 *
 * pre: char *file represents the file name
 * post: boolean representing whether the removal of file was succesful
 */
bool remove (const char *file) {
	// checks for valid filename
	if(!validate_filename(file)) {
		return false;
	}
	// removes file while protected, storing whether the function was succesful
	lock_acquire(&filesys);
	bool status = filesys_remove (file);
	lock_release(&filesys);
	return status;
}

/*
 * Opens the file called file
 *
 * pre: char *file represents the file name
 * post: int representing whether the open of file was succesful
 */
int open (const char *file) {
	// checks for valid filename
	
	if(!validate_filename(file)) {
		return -1;
	}
	// finds a valid spot within the 126 possible open files to open
	int open_file_slot = -1;
	lock_acquire(&filesys);
	struct thread* cur = thread_current();
	for (int i = 0; i < 126; i++) {
		if (!cur->file_arr[i]) {
			open_file_slot = i;
			break;
		}
	}
	if (open_file_slot == -1) {
		// no open spots, unsucceful open
		lock_release(&filesys);
		return -1;
	} else {
		//add it to open files
		struct file* cur_file = filesys_open(file);
		if (!cur_file) {
			lock_release(&filesys);
			return -1;
		}
		cur->file_arr[open_file_slot] = cur_file;
	}

	lock_release(&filesys);
	// adds 2 to index to accomodate for stdin & stdout
	return open_file_slot+2;
	// end of Sashank driving
}

/*
 * Returns the size, in bytes, of the file open as fd
 *
 * pre: int fd representing the file's file descriptor
 * post: int representing the size of the file in bytes
 */
int filesize (int fd) {
	// Ike driving, Praveen and Sashank navigating
	int index = fd - 2;

	// checks if fd is within possible bounds
	if(index < 0 || index >= 126) {
		exit(-1);
	}

	// checks if fd points to a valid file
	struct thread* cur = thread_current();

	if (cur->file_arr[index]) {
		// if file exists, find the file size while protected
		lock_acquire(&filesys);
		int size = file_length(cur->file_arr[index]);
		lock_release(&filesys);
		return size;
	} else {
		exit(-1);
	}

	return -1;
}

/*
 * Reads size bytes from the file open as fd into buffer
 *
 * pre: int fd representing the file's file descriptor, void *buffer 
 * representing the contents of read, unsigned length representing the size of
 * bytes to read from the file
 * post: int representing the number of bytes actually read
 */
int read (int fd, void *buffer, unsigned length) {
	lock_acquire(&filesys);
	int read = -1;

	if (fd == STDIN_FILENO) {
		// gets input from stdin
		input_getc();
	} else if (fd > STDOUT_FILENO) {
		// determines whether a valid file descriptor was passsed
		int index = fd - 2;

		if(index < 0 || index >= 126) {
			exit(-1);
		}

		struct thread* cur = thread_current();

		if (cur->file_arr[index]) {
			// reads from the file into buffer and stores the number of bytes 
			// actually read
			read = file_read(cur->file_arr[index], buffer, length);
		} else {
			exit(-1);
		}
	}

	lock_release(&filesys);
	return read;
	// Ike driving, Praveen and Sashank navigating
}

/*
 * Writes size bytes from buffer to the open file fd
 *
 * pre: int fd representing the file's file descriptor, void *buffer 
 * representing the contents to write, unsigned length representing the size of
 * bytes to write from the buffer
 * post: int representing the number of bytes actually written
 */
int write (int fd, const void *buffer, unsigned length) {
	// Praveen driving, Ike and Sashank navigating
	lock_acquire(&filesys);
	
	if (fd == STDOUT_FILENO) {
		// prints to stdout
		const int MAX_PRINT = 512;
		int print_length = length;
		int index = 0;

		// prints MAX_PRINT bytes until there are fewer than MAX_PRINT bytes to
		// print
		while (print_length > MAX_PRINT) {
			putbuf (buffer + index, MAX_PRINT);
			print_length -= MAX_PRINT;
			index += MAX_PRINT;
		}

		// prints the remaining few bytes
		putbuf (buffer + index, print_length);
	} else if (fd > STDOUT_FILENO) {
		// determines whether file descriptor is valid
		int index = fd - 2;
		struct thread* cur = thread_current();
		if(index < 0 || index >= 126 || !cur->file_arr[index]) {
			lock_release(&filesys);
			exit(-1);
		}
		// writes and determines the number of bytes written
		length = file_write(cur->file_arr[index], buffer, length);
	}

	lock_release(&filesys);
	return length;
}

/*
 * Changes the next byte to be read or written in open file fd to position, 
 * expressed in bytes from the beginning of the file
 *
 * pre: int fd representing the file's file descriptor, unsigned position 
 * representing the offset from the beginning of the file
 * post: none
 */
void seek (int fd, unsigned position) {
	// determines whether file descriptor is valid
	int index = fd - 2;
	struct thread* cur = thread_current();
	if(index < 0 || index >= 126 || !cur->file_arr[index]) {
		exit(-1);
	}

	lock_acquire(&filesys);
	// calls the seek command, while protected
	file_seek(cur->file_arr[index], position);
	lock_release(&filesys);
	// end of Praveen driving
}

/*
 * Returns the position of the next byte to be read or written in open file fd,
 *  expressed in bytes from the beginning of the file
 *
 * pre: int fd representing the file's file descriptor
 * post: unsigned representing the next byte to be written or read from file
 */
unsigned tell (int fd) {
	// Sashank driving, Praveen and Ike navigating
	// determines whether file descriptor is valid
	int index = fd - 2;
	int status = -1;
	struct thread* cur = thread_current();
	if(index < 0 || index >= 126 || !cur->file_arr[index]) {
		return status;
	}
	lock_acquire(&filesys);
	// calls the tell command, while protected
	status = file_tell(cur->file_arr[index]);
	lock_release(&filesys);
	return status;
}

/*
 * Closes file descriptor fd
 *
 * pre: int fd representing the file's file descriptor
 * post: none
 */
void close (int fd) {
	// determines whether file descriptor is valid
	int index = fd - 2;
	if(index < 0 || index >= 126) {
		exit(-1);
	}
	struct thread* cur = thread_current();
	if (cur->file_arr[index]) {
		//file exists
		lock_acquire(&filesys);
		// close the file while protected and open up the spot
		file_close(cur->file_arr[index]);
		cur->file_arr[index] = NULL;
		lock_release(&filesys);
	} else {
		//no file there
		exit(-1);
	}
	// end of Sashank driving
 }
 
//  Sashank driving, Praveen and Eylam navigating
/*
 * Returns whether the directory was successfully created
 *
 * pre: char *filename representing the name of the directory to create
 * post: int representing whether the create was successful
 */
 int make_dir(const char *filename) {
	int return_code;
	int len = strlen(filename);
	if (len == 0) {
		return 0;
	}
	lock_acquire (&filesys);
	return_code = filesys_create(filename, 0, true);
	lock_release (&filesys);
	return return_code;
 }

/*
 * Returns whether a directory change was successful
 *
 * pre: char *filename representing the name of the directory to change to
 * post: int representing whether the change was successful
 */
int chdir(const char *filename) {
	return 1;
}
// end of int driving