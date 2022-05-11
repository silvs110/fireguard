#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <arpa/inet.h>

/*Macros*/

#define WR_ADD 1
#define WR_DELETE 2


/*Structures*/

static struct Message{
  int action;
  unsigned int blockIp;
  int user;
} m;


/*Prototype*/
void displayMenu();


/*Functions*/
int main(){
  
  FILE * fp;
  //open proc file
  fp = fopen("/proc/fireguard", "r+w");

  if (fp ==  NULL) {
      perror("open failed");
      return errno;
  }


  int ret, size;
  char * addr;
  int option = -1;
  size = sizeof(unsigned int) + 1;
  char data[size];
  
  while(option != 0){

    displayMenu();
    printf("\nOption: ");
    scanf(" %d", &option);//get user input 

    while(getchar() != '\n'); //used when the user inputs a char instead of an int

    if(option == 0){//if user wants to exit the program

      char ans;

      printf("Are you sure?(y/n): ");
      scanf(" %c", &ans);
      
      if(ans == 'y' || ans == 'Y'){//exit
        close(fp);
        return 0;

      }else{//continue with the program
        option = -1;
      }
      
    }else if(option == 1){

      char dest[15];
      unsigned int num;

      fseek(fp, 0, SEEK_SET);//sets it to start of the file
      printf("\nBlocket IPs:\n");
      while(1){//read all data from the file
        
        
     	fscanf(fp,"%s", data);
        if(feof(fp)) break;//break if it's end of file

        //process data from proc file
        num = atoi(data);
        if(inet_ntop(AF_INET, &num, dest, sizeof(dest)) != NULL){ //if inet_ntop succeed print data
           printf("%s\n", dest);
        }
        
      }
      
     
    }else if(option == 2){//add IP to blockedIPs

      struct Message msg;

      msg.action = WR_ADD;
      msg.user = (int)getuid();//get current user id


      printf("IPv4 address: ");   
      scanf(" %s", addr);
      if(inet_pton(AF_INET, addr, &msg.blockIp) > 0){
         
         printf("Your IP address in int: %u\n",msg.blockIp);

         fwrite(&msg, sizeof(struct Message), 1, fp); //writes to the prooc file
         fflush(fp);
      }
      
      

    } else if(option == 3){//Delete IP from blockedIPs

      struct Message msg;

      msg.action = WR_DELETE;
      msg.user = (int)getuid();
      

      printf("IPv4 address: ");
      scanf(" %s", addr);
      if(inet_pton(AF_INET, addr, &msg.blockIp) > 0){
         
         printf("Your IP address in int: %u\n",msg.blockIp);//writes to proc file

         fwrite(&msg, sizeof(struct Message), 1, fp);
         fflush(fp);
      }

    }
  }

  return 1;
}


//Display options
void displayMenu(){

  printf("\nWelcome to fireguard\n--------------------\n\n");
  printf("Choose from our menu\n\n");
  
  printf("1. View Blocked IPs\n");
  printf("2. Add IP\n");
  printf("3. Delete IP\n");
  printf("0. Exit program\n");

}
