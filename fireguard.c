#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#include <linux/fs_struct.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>



MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Packet-Filtering Firewall");

/*Macros*/

#define WR_ADD 1
#define WR_DELETE 2
#define SUPER_USER 1000
#define MAX_SIZE 10


/* Varibables*/
static struct proc_dir_entry * this_proc;
static struct nf_hook_ops in_hook;
int ipsSize;
unsigned int blockedIps[MAX_SIZE];
int userSize;
uid_t allowedUsers[MAX_SIZE];


/* driver prototype functions*/

static int firewall_open(struct inode *inode, struct file *file);
static ssize_t firewall_read(struct file *, char *, size_t, loff_t *);
static ssize_t firewall_write(struct file *, const char *, size_t, loff_t *);

unsigned int hookInFunction(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static int addRule(unsigned int rule);
static int deleteRule(unsigned int rule);
static int checkPermission(uid_t user);
static int getIndexMatch(unsigned int ip );


/* Structures*/


static struct file_operations fops = {

 .owner = THIS_MODULE,
 .open = firewall_open,
 .read = firewall_read,
 .write = firewall_write
};


static struct Message{
  int action;
  unsigned int blockIp;
  uid_t user;
}message;



/*Functions*/

//Called when module is inserted
static int __init firewall_init(void) {

  int hook;

  in_hook.hook = hookInFunction;
  in_hook.hooknum = NF_INET_PRE_ROUTING;//first hook
  in_hook.pf = PF_INET;
  in_hook.priority = NF_IP_PRI_FIRST;//higher priority first

  hook = nf_register_hook(&in_hook);
  this_proc = proc_create("fireguard", 0666, NULL , &fops);//0666->read and write


  if(this_proc != NULL || hook == 0){

    printk(KERN_INFO "Firewall module created\n");
    ipsSize = 0;
    allowedUsers[0] = 1000;//superuser
    userSize = 1;
    
  }else{
    printk(KERN_ERR "Failed to register\n");
  }


  return 0;
}




/*Purpose: Filter networks packets by IP source
 * Called when a network packet reaches the first hook (NF_INET_PRE_ROUTING)
*/
unsigned int hookInFunction(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
  int i;
  struct iphdr *ipHeader = (struct iphdr *)skb_network_header(skb);//gets packet ip header
  
  unsigned int srcIp = (unsigned int)ipHeader->saddr;
  


  for(i = 0; i < ipsSize; i++){
    if(srcIp == blockedIps[i]){
      printk(KERN_INFO "Packet is blocked. Source IP(int): %u\n", srcIp);
     
      return NF_DROP;
    }
  }
  printk(KERN_INFO "Packet passed. Source IP: %u\n", srcIp);
  return NF_ACCEPT;
}






//called when module exits
static void __exit firewall_exit(void) {
  nf_unregister_hook(&in_hook);
  remove_proc_entry("fireguard", NULL);

  printk(KERN_INFO "Firewall module closed\n");
}






static int firewall_open(struct inode *inode, struct file *file) {

  printk(KERN_INFO "fireguard is open!\n");
  return 0;

}



/* Called when module is read.
* filep = pointer to a file
* buffer = pointer to the buffer to which this function writes the data
* len = length of buffer
* offset = offset in buffer
*/
static ssize_t firewall_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {

  int length = 0;
  int i;
  
  if(*offset !=0){
    return 0;
  }

  for(i = 0; i < ipsSize; i++){
   
     length += sprintf(buffer+length, "%u\n", blockedIps[i]);//prints the ip to the buffer
  }

  *offset = length;
  
  return length;

}


/* Called whenever module is written.
* filep = pointer to file
* buffer = pointer to buffer that contains data to write to the device
* len = length of data
* offset = offset in buffer
*/

static ssize_t firewall_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
  struct Message m;

  if(copy_from_user(&m, buffer, sizeof(message))){//getting data from user
    printk(KERN_INFO "Sorry can't read user input from /proc\n");
    return -EFAULT;
  }

  if(checkPermission(m.user)) {//checking current user permission
    printk(KERN_INFO "user %u doesn't have permission to access this firewall\n", m.user);
    return -EFAULT;
  }
  
	
  if(m.action == WR_ADD){//add new IP

    addRule(m.blockIp);

  }else if(m.action == WR_DELETE){//deletes IP

    deleteRule(m.blockIp);
  }


  return len;
}



/*Adds new IP to the array of blocked IPs
 *Called in firewall_write()
*/
static int addRule(unsigned int rule){
  int i;

  if(ipsSize >= MAX_SIZE){//checks if array is full
    return 1;
  }

  i = getIndexMatch(rule);//looks for a IP in the address. Helps to avoid repetition

  if(i != -1){//if theres a match
     return 1;
  }

  //add IP

  blockedIps[ipsSize] = rule;
  ipsSize++;

  return 0;

}

/*Deletes IP to the array of blocked IPs
 *Called in firewall_write()
*/
static int deleteRule(unsigned int rule){

  int i, j;

  i = getIndexMatch(rule);//gets the index of the IP in the array

  if(i == -1){//no matches
    return 1;
  }
  blockedIps[i] = 0;
  
  //fill the gap
  for(j = i; j < ipsSize -1; j++){
    blockedIps[j] = blockedIps[j+1];
  }

  ipsSize--;

  return 0;
}


/* gets the index of ip in the array
 * Helper function called in addRule() and deleteRule()
*/
static int getIndexMatch(unsigned int ip){

  int i;
  //goes thorugh the array and returs its index
  for(i = 0; i < ipsSize; i++){
    if(blockedIps[i] == ip){
      return i;
    }
  }
  return -1;//if no matches has been found
}


/* Makes sure that the current user has permission to edit the file
 * Called in firewall_write()
 */
static int checkPermission(uid_t user){

  int i;
  //goes to the array looking for the user
  for(i = 0; i < userSize; i++){
    if(allowedUsers[i] == user){
      return 0;//if user is in the array
    }
  }
  return 1;//if user is not allo
}

module_init(firewall_init);
module_exit(firewall_exit);