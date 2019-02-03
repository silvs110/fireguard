Go to file directory through the terminal

Compile:

  Module(Firewall):

	"make"
  	"sudo insmod brickWall.ko"

  brickControl(UI):

	"gcc -o brickControl ./brickControl.c"
	

Run:

  UI:
	"cat /proc/brickWall"

notes:
	-do not compile in shared folder
	-To view kernel logs type in the terminal "tail -f /var/log/syslog"
	-to view website IPv4 type: "nslookup [website url]"
	-brickControl requires user input
	-blocked IPs is empty when the module is first loaded

